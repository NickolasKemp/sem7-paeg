import { validatePart, verifyBody, type Signed } from "./message.ts";
import { decrypt, generateKeyPair, multiplyCiphers, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  BRANCHES,
  middleLabel,
  type BallotPart,
  type Batch,
  type BatchRejection,
  type Branch,
  type BureauKeys,
  type Candidate,
  type CommissionLabel,
  type District,
  type ElectionResults,
  type ExcludedPart,
  type ResultRow,
  type Tally,
} from "./types.ts";

const FIRST_CANDIDATE_ID = 101n;

export function assignCandidateIds(names: readonly string[]): Candidate[] {
  return names.map((name, index) => ({ id: FIRST_CANDIDATE_ID + BigInt(index), name }));
}

function countVotes(rows: readonly ResultRow[], candidates: readonly Candidate[], district?: District): Tally {
  const tally = new Map(candidates.map((candidate) => [candidate.id, 0]));
  for (const row of rows) {
    if (row.status !== "accepted" || (district !== undefined && row.district !== district)) continue;
    tally.set(row.ballot, (tally.get(row.ballot) ?? 0) + 1);
  }
  return tally;
}

/** Підрахунок прийнятих рядків — загальний і по дільницях; ним користуються ЦВК і публічний аудит. */
export function summarize(rows: readonly ResultRow[], candidates: readonly Candidate[]): Pick<ElectionResults, "tally" | "byDistrict"> {
  return {
    tally: countVotes(rows, candidates),
    byDistrict: { 1: countVotes(rows, candidates, 1), 2: countVotes(rows, candidates, 2) },
  };
}

/**
 * Центральна виборча комісія: публікує ID кандидатів і відкритий ключ шифрування бюлетенів,
 * тримає закритий ключ, приймає пакети лише від СВК-1 і СВК-2, повторно перевіряє кожну частину,
 * зіставляє частини за ID виборця, об'єднує C₁ · C₂ mod n, розшифровує і рахує голоси.
 * Імен виборців ЦВК не знає: ID виборця — псевдонім, підписаний БР наосліп.
 */
export class CentralCommission {
  readonly candidates: readonly Candidate[];

  readonly #keys: KeyPair;
  readonly #bureauKeys: BureauKeys;
  readonly #middleKeys: Readonly<Record<Branch, PublicKey>>;

  constructor(options: {
    candidateNames: readonly string[];
    bureauKeys: BureauKeys;
    middleKeys: Readonly<Record<Branch, PublicKey>>;
    bits?: number;
  }) {
    this.candidates = assignCandidateIds(options.candidateNames);
    this.#keys = generateKeyPair(options.bits ?? 512);
    this.#bureauKeys = options.bureauKeys;
    this.#middleKeys = options.middleKeys;
  }

  get publicKey(): PublicKey {
    return this.#keys.publicKey;
  }

  count(batches: readonly Signed<Batch>[]): ElectionResults {
    const rejectedBatches: { from: CommissionLabel; reason: BatchRejection }[] = [];
    const excluded: ExcludedPart[] = [];
    const ballots = new Map<bigint, { district: District; parts: [BallotPart | undefined, BallotPart | undefined] }>();

    for (const batch of batches) {
      const { from, parts } = batch.body;
      const branch = BRANCHES.find((candidate) => middleLabel(candidate) === from);
      if (branch === undefined) {
        rejectedBatches.push({ from, reason: "UNKNOWN_SENDER" });
        continue;
      }
      if (!verifyBody(batch, this.#middleKeys[branch])) {
        rejectedBatches.push({ from, reason: "BAD_BATCH_SIGNATURE" });
        continue;
      }
      for (const part of parts) {
        const voterId = part.credential.token.voterId;
        const ballot = ballots.get(voterId) ?? { district: part.credential.district, parts: [undefined, undefined] };
        const reason = validatePart(part, this.#bureauKeys, { branch }) ?? (ballot.parts[branch - 1] ? "DUPLICATE" : undefined);
        if (reason) {
          excluded.push({ from, voterId, reason });
          continue;
        }
        ballot.parts[branch - 1] = part;
        ballots.set(voterId, ballot);
      }
    }

    const rows = [...ballots].map(([voterId, { district, parts }]) => this.#combine(voterId, district, parts));
    return { rows, excluded, rejectedBatches, ...summarize(rows, this.candidates) };
  }

  /** Спочатку об'єднання, потім розшифрування: (C₁ · C₂)ᵈ mod n = m₁ · m₂ mod n = m. */
  #combine(voterId: bigint, district: District, [first, second]: readonly [BallotPart | undefined, BallotPart | undefined]): ResultRow {
    const parts = [first?.encryptedPart, second?.encryptedPart] as const;
    if (!first || !second) return { voterId, district, parts, status: "rejected", reason: "MISSING_PART" };

    const combined = multiplyCiphers(first.encryptedPart, second.encryptedPart, this.publicKey);
    const ballot = decrypt(combined, this.#keys.privateKey);
    const isCandidate = this.candidates.some((candidate) => candidate.id === ballot);
    if (!isCandidate) return { voterId, district, parts, status: "rejected", reason: "NOT_A_CANDIDATE", combined, ballot };
    return { voterId, district, parts, status: "accepted", combined, ballot };
  }
}
