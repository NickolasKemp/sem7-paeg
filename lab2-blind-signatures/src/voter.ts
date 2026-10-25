import { randomBytes } from "node:crypto";

import { blind, randomBlindingFactor, unblind } from "./blind-signature.ts";
import { encrypt, hashMessage, verify, type PublicKey } from "./rsa.ts";
import {
  parseBallot,
  SET_COUNT,
  serializeBallot,
  type BlindedSet,
  type Candidate,
  type Envelope,
  type PublishedBallot,
  type RevealedSet,
  type SignedBallot,
  type SigningRequest,
} from "./types.ts";

/** Набір бюлетенів з усіма секретами виборця. */
export type PreparedSet = {
  readonly id: string;
  readonly ballots: readonly string[];
  readonly hashes: readonly bigint[];
  readonly factors: readonly bigint[];
  readonly blinded: BlindedSet;
};

export type OwnVoteCheck = "counted" | "missing" | "altered";

/**
 * Виборець: готує 10 наборів бюлетенів, маскує їх хеші, розкриває обрані ВК набори,
 * знімає маскування з отриманих сліпих підписів і анонімно надсилає один бюлетень.
 */
export class Voter {
  readonly name: string;
  readonly document: string;

  private sets: readonly PreparedSet[] = [];
  private unopened: number | undefined;
  private signedBallots = new Map<string, SignedBallot>();
  private castBallot: SignedBallot | undefined;

  constructor(name: string, document: string) {
    this.name = name;
    this.document = document;
  }

  get preparedSets(): readonly PreparedSet[] {
    return this.sets;
  }

  get signed(): ReadonlyMap<string, SignedBallot> {
    return this.signedBallots;
  }

  /**
   * Кроки 2–4: 10 наборів по бюлетеню на кандидата, окремий випадковий ID на набір,
   * хеш кожного бюлетеня маскується власним множником r.
   * `choicesFor` дозволяє сформувати набір з іншими бюлетенями (сценарій шахрайства).
   */
  prepare(
    candidates: readonly Candidate[],
    commissionKey: PublicKey,
    choicesFor: (setIndex: number) => readonly string[] = () => candidates.map((candidate) => candidate.id),
  ): SigningRequest {
    const ids = new Set<string>();
    while (ids.size < SET_COUNT) ids.add(randomBytes(8).toString("hex"));

    this.sets = [...ids].map((id, index) => {
      const ballots = choicesFor(index).map((candidateId) => serializeBallot({ id, candidateId }));
      const hashes = ballots.map((ballot) => hashMessage(ballot, commissionKey.n));
      const factors = ballots.map(() => randomBlindingFactor(commissionKey.n));
      const blinded = hashes.map((hash, j) => blind(hash, factors[j]!, commissionKey));
      return { id, ballots, hashes, factors, blinded };
    });

    return {
      voterName: this.name,
      document: this.document,
      blindedSets: this.sets.map((set) => set.blinded),
    };
  }

  /** Крок 7: розкрити лише набори, обрані ВК; десятий залишається таємним. */
  reveal(indices: readonly number[]): RevealedSet[] {
    this.unopened = this.sets.findIndex((_, index) => !indices.includes(index));
    return indices.map((index) => {
      const set = this.sets[index];
      if (!set) throw new Error(`Набору №${index + 1} не існує`);
      return { index, ballots: set.ballots, factors: set.factors };
    });
  }

  /** Крок 10: S = S'·r⁻¹ mod n і перевірка, що це справді підпис ВК під нашим бюлетенем. */
  acceptSignatures(blindSignatures: readonly bigint[], commissionKey: PublicKey): void {
    const set = this.unopened === undefined ? undefined : this.sets[this.unopened];
    if (!set) throw new Error("Немає нерозкритого набору");

    this.signedBallots = new Map(
      set.ballots.map((ballot, j) => {
        const signature = unblind(blindSignatures[j] ?? 0n, set.factors[j]!, commissionKey);
        if (!verify(ballot, signature, commissionKey)) throw new Error("ВК повернула недійсний підпис");
        return [parseBallot(ballot).candidateId, { ballot, signature }];
      }),
    );
  }

  /** Кроки 11–12: обрати бюлетень, додати підпис ВК, зашифрувати відкритим ключем ВК. */
  vote(candidateId: string, commissionKey: PublicKey): Envelope {
    const signed = this.signedBallots.get(candidateId);
    if (!signed) throw new Error(`Немає підписаного бюлетеня за «${candidateId}»`);
    this.castBallot = signed;
    return { cipher: sealFor(signed, commissionKey) };
  }

  /** Крок 14: знайти свій ID серед опублікованих бюлетенів і звірити вибір. */
  checkPublished(published: readonly PublishedBallot[]): OwnVoteCheck {
    if (!this.castBallot) throw new Error("Виборець ще не голосував");
    const own = parseBallot(this.castBallot.ballot).id;
    const entry = published.find((item) => item.id === own);
    if (!entry) return "missing";
    return entry.ballot === this.castBallot.ballot && entry.signature === this.castBallot.signature
      ? "counted"
      : "altered";
  }
}

/**
 * Шифрування бюлетеня з підписом відкритим ключем ВК.
 * Відкритий ключ доступний будь-кому — цим користуються негативні сценарії.
 */
export function sealFor(signed: SignedBallot, commissionKey: PublicKey): bigint[] {
  const payload = JSON.stringify({ ballot: signed.ballot, signature: signed.signature.toString(16) });
  return encrypt(payload, commissionKey);
}
