import { decrypt, generateKeyPair, multiplyCiphers, type KeyPair, type PublicKey } from "./rsa.ts";
import { hidingSplits } from "./split.ts";
import type { BallotPart, Candidate, CombinedBallot, ElectionResults, VoterRecord } from "./types.ts";

/**
 * Спільний множник усіх ID кандидатів: ID = 12 · k (24, 36, 48, …).
 * Завдяки ньому множники 2, 3, 4, 6, 12 трапляються в розкладах різних кандидатів.
 */
const ID_BASE = 12n;
const FIRST_MULTIPLIER = 2n;

/** ЦВК видає кандидатам ID, придатні для поділу: кожен має розклад, що не видає вибір. */
export function assignCandidateIds(names: readonly string[]): Candidate[] {
  const ids = names.map((_, index) => ID_BASE * (FIRST_MULTIPLIER + BigInt(index)));
  for (const id of ids) {
    if (hidingSplits(id, ids).length === 0) throw new Error(`ID ${id} не можна поділити, не видавши вибір`);
  }
  return names.map((name, index) => ({ id: ids[index]!, name }));
}

/**
 * Центральна виборча комісія: реєструє виборців за їх відкритими ключами ЕЦП,
 * видає ID кандидатам, тримає закритий ключ шифрування, об'єднує опубліковані
 * частини бюлетенів, розшифровує вже об'єднаний бюлетень і рахує голоси.
 */
export class CentralCommission {
  readonly keys: KeyPair;
  readonly candidates: readonly Candidate[];

  private readonly voters = new Map<string, VoterRecord>();

  constructor(options: { candidateNames: readonly string[]; bits?: number }) {
    this.keys = generateKeyPair(options.bits ?? 512);
    this.candidates = assignCandidateIds(options.candidateNames);
  }

  /** Відкритий ключ шифрування бюлетенів публікується для виборців. */
  get publicKey(): PublicKey {
    return this.keys.publicKey;
  }

  get candidateIds(): bigint[] {
    return this.candidates.map((candidate) => candidate.id);
  }

  /** Крок 1: виборець надсилає відкритий ключ ЕЦП — ЦВК вносить його до списку. */
  registerVoter(name: string, publicKey: PublicKey): void {
    if (this.voters.has(name)) throw new Error(`Виборець «${name}» уже зареєстрований`);
    this.voters.set(name, { name, publicKey });
  }

  /** Крок 1: список виборців з відкритими ключами, який ЦВК надсилає до ВК-1 та ВК-2. */
  voterList(): VoterRecord[] {
    return [...this.voters.values()];
  }

  /**
   * Крок 6: зіставлення частин за ID виборця, об'єднання C₁ · C₂ mod n
   * і лише потім розшифрування: (C₁ · C₂)^d mod n = m₁ · m₂.
   */
  combine(first: readonly BallotPart[], second: readonly BallotPart[]): CombinedBallot[] {
    const index = (list: readonly BallotPart[]) => new Map(list.map((entry) => [entry.voterId, entry.encryptedPart]));
    const [firstById, secondById] = [index(first), index(second)];
    const voterIds = [...new Set([...firstById.keys(), ...secondById.keys()])];

    return voterIds.map((voterId): CombinedBallot => {
      const parts = [firstById.get(voterId), secondById.get(voterId)] as const;
      const [c1, c2] = parts;
      if (c1 === undefined || c2 === undefined) return { voterId, parts, status: "rejected", reason: "MISSING_PART" };

      const combined = multiplyCiphers(c1, c2, this.publicKey);
      const ballot = decrypt(combined, this.keys.privateKey);
      return this.candidates.some((candidate) => candidate.id === ballot)
        ? { voterId, parts, status: "accepted", combined, ballot }
        : { voterId, parts, status: "rejected", reason: "NOT_A_CANDIDATE", combined, ballot };
    });
  }

  /** Підрахунок прийнятих бюлетенів; разом з результатами публікуються ID виборців та їх бюлетені. */
  tally(ballots: readonly CombinedBallot[]): ElectionResults {
    const tally = new Map(this.candidates.map((candidate) => [candidate.id, 0]));
    for (const ballot of ballots) {
      if (ballot.status === "accepted") tally.set(ballot.ballot, (tally.get(ballot.ballot) ?? 0) + 1);
    }

    const max = Math.max(0, ...tally.values());
    const leaders = max === 0 ? [] : this.candidates.filter((candidate) => tally.get(candidate.id) === max);
    return { ballots, tally, leaders, isTie: leaders.length > 1 };
  }
}
