import { randomInt } from "node:crypto";

import { gcd } from "./bigint-math.ts";
import { blind, signBlinded } from "./blind-signature.ts";
import { decrypt, generateKeyPair, hashMessage, verify, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  parseBallot,
  SET_COUNT,
  SIGNING_REJECTIONS,
  VOTE_REJECTIONS,
  type Ballot,
  type BlindedSet,
  type Candidate,
  type ChallengeResult,
  type ElectionResults,
  type Envelope,
  type PublishedBallot,
  type Rejected,
  type RevealedSet,
  type SigningRejection,
  type SigningRequest,
  type SigningResult,
  type VoteRejection,
  type VoteResult,
  type VoterRecord,
} from "./types.ts";

export type CheckName =
  | "inList"
  | "identity"
  | "notIssued"
  | "requestShape"
  | "challenge"
  | "revealedIndices"
  | "setValid"
  | "blindSign"
  | "decrypt"
  | "signature"
  | "ballotValid"
  | "uniqueId";

export type CheckEvent = { readonly check: CheckName; readonly passed: boolean; readonly detail: string };
export type CommissionObserver = (event: CheckEvent) => void;

type PendingRequest = { readonly blindedSets: readonly BlindedSet[]; readonly unopened: number };

/**
 * Виборча комісія (ВК): список виборців і кандидатів, сліпе підписування наборів
 * за схемою «розкрий 9 з 10», анонімне приймання бюлетенів і публікація результатів.
 */
export class ElectionCommission {
  readonly keys: KeyPair;
  readonly candidates: readonly Candidate[];

  private readonly voters = new Map<string, VoterRecord>();
  private readonly pending = new Map<string, PendingRequest>();
  private readonly accepted = new Map<string, PublishedBallot>();
  private readonly revealedIds = new Set<string>();
  private readonly observer: CommissionObserver | undefined;
  private readonly pickUnopened: () => number;
  private rejectedCount = 0;

  constructor(options: {
    candidates: readonly Candidate[];
    bits?: number;
    observer?: CommissionObserver;
    pickUnopened?: () => number;
  }) {
    this.keys = generateKeyPair(options.bits ?? 512);
    this.candidates = options.candidates;
    this.observer = options.observer;
    this.pickUnopened = options.pickUnopened ?? (() => randomInt(SET_COUNT));
  }

  /** Відкритий ключ ВК публікується: ним маскують хеші, перевіряють підпис і шифрують бюлетені. */
  get publicKey(): PublicKey {
    return this.keys.publicKey;
  }

  /** Крок 1: формування списку виборців. */
  registerVoter(name: string, document: string): void {
    if (this.voters.has(name)) throw new Error(`Виборець «${name}» уже зареєстрований`);
    this.voters.set(name, { name, document, status: "registered" });
  }

  get voterList(): readonly VoterRecord[] {
    return [...this.voters.values()];
  }

  /** ID, які ВК дізналася з розкритих наборів; ID нерозкритих наборів сюди не потрапляють. */
  get knownIds(): ReadonlySet<string> {
    return this.revealedIds;
  }

  /** Кроки 5–6: перевірка особи та права на підписаний набір, вибір 9 наборів для розкриття. */
  requestSigning(request: SigningRequest): ChallengeResult {
    const voter = this.voters.get(request.voterName);
    if (!voter) {
      this.note("inList", false, `«${request.voterName}» відсутній у списку виборців`);
      return rejected("NOT_IN_LIST", SIGNING_REJECTIONS);
    }
    this.note("inList", true, `«${voter.name}» є у списку виборців`);

    if (voter.document !== request.document) {
      this.note("identity", false, `документ ${request.document} не належить «${voter.name}»`);
      return rejected("IDENTITY_MISMATCH", SIGNING_REJECTIONS);
    }
    this.note("identity", true, `особу підтверджено документом ${voter.document}`);

    if (voter.status !== "registered") {
      const reason = voter.status === "issued" ? "ALREADY_ISSUED" : "REFUSED_EARLIER";
      this.note("notIssued", false, SIGNING_REJECTIONS[reason]);
      return rejected(reason, SIGNING_REJECTIONS);
    }
    this.note("notIssued", true, "у реєстрі ВК немає позначки про видачу");

    const wellFormed =
      request.blindedSets.length === SET_COUNT &&
      request.blindedSets.every((set) => set.length === this.candidates.length);
    this.note(
      "requestShape",
      wellFormed,
      `${request.blindedSets.length} наборів × ${request.blindedSets.map((set) => set.length).join("/")} замаск. хешів`,
    );
    if (!wellFormed) return rejected("MALFORMED_REQUEST", SIGNING_REJECTIONS);

    const unopened = this.pickUnopened();
    const reveal = [...Array(SET_COUNT).keys()].filter((index) => index !== unopened);
    this.pending.set(voter.name, { blindedSets: request.blindedSets, unopened });
    this.note("challenge", true, `розкрити набори №${reveal.map((index) => index + 1).join(", ")}`);
    return { status: "challenge", reveal };
  }

  /** Кроки 8–9: перевірка 9 розкритих наборів і сліпий підпис десятого. */
  completeSigning(voterName: string, revealed: readonly RevealedSet[]): SigningResult {
    const voter = this.voters.get(voterName);
    const request = this.pending.get(voterName);
    if (!voter || !request) return rejected("NO_PENDING_REQUEST", SIGNING_REJECTIONS);
    this.pending.delete(voterName);

    const expected = [...Array(SET_COUNT).keys()].filter((index) => index !== request.unopened);
    const indices = revealed.map((set) => set.index).sort((a, b) => a - b);
    const indicesMatch = indices.join() === expected.join();
    this.note("revealedIndices", indicesMatch, `розкрито набори №${indices.map((index) => index + 1).join(", ")}`);
    if (!indicesMatch) return this.refuse(voter, "WRONG_REVEAL");

    for (const set of revealed) {
      const problem = this.inspectSet(set, request.blindedSets[set.index] ?? []);
      this.note("setValid", problem === undefined, `набір №${set.index + 1}: ${problem ?? "коректний"}`);
      if (problem !== undefined) return this.refuse(voter, "BAD_SET", `набір №${set.index + 1}: ${problem}`);
    }

    const blindSignatures = (request.blindedSets[request.unopened] ?? []).map((hash) =>
      signBlinded(hash, this.keys.privateKey),
    );
    voter.status = "issued";
    this.note("blindSign", true, `набір №${request.unopened + 1} підписано наосліп: S' = (H')ᵈ mod n`);
    return { status: "signed", blindSignatures };
  }

  /** Кроки 12–13: анонімний бюлетень — розшифрування, перевірка ЕЦП ВК та унікальності ID. */
  receive(envelope: Envelope): VoteResult {
    const opened = this.open(envelope);
    if (!opened.ok) {
      this.note("decrypt", false, opened.error);
      return this.reject("UNDECRYPTABLE", opened.error);
    }
    const { text, ballot, signature } = opened;
    this.note("decrypt", true, `бюлетень: ${text}`);

    const signatureValid = verify(text, signature, this.publicKey);
    this.note("signature", signatureValid, signatureValid ? "H = H_c, підпис ВК справжній" : "H ≠ H_c, підпис недійсний");
    if (!signatureValid) return this.reject("BAD_SIGNATURE");

    const candidate = this.candidates.find((item) => item.id === ballot.candidateId);
    this.note("ballotValid", candidate !== undefined, candidate ? `голос за «${candidate.name}»` : `кандидата «${ballot.candidateId}» немає`);
    if (!candidate) return this.reject("INVALID_BALLOT");

    if (this.accepted.has(ballot.id)) {
      this.note("uniqueId", false, `ID ${ballot.id} уже використано`);
      return this.reject("DUPLICATE_ID", `ID ${ballot.id}`);
    }
    this.note("uniqueId", true, `ID ${ballot.id} використовується вперше`);

    this.accepted.set(ballot.id, { ...ballot, ballot: text, signature });
    return { status: "accepted", ballot };
  }

  /** Крок 14: підрахунок і публікація результатів разом з усіма ID та підписаними бюлетенями. */
  publishResults(): ElectionResults {
    const published = [...this.accepted.values()];
    const tally = new Map(
      this.candidates.map((candidate) => [
        candidate.id,
        published.filter((entry) => entry.candidateId === candidate.id).length,
      ]),
    );
    const max = Math.max(0, ...tally.values());
    const leaders = max === 0 ? [] : this.candidates.filter((candidate) => tally.get(candidate.id) === max);

    return {
      tally,
      published,
      accepted: published.length,
      rejected: this.rejectedCount,
      leaders,
      isTie: leaders.length > 1,
    };
  }

  /** Повертає опис порушення або undefined, якщо набір коректний. */
  private inspectSet(set: RevealedSet, blinded: BlindedSet): string | undefined {
    if (set.ballots.length !== this.candidates.length || set.factors.length !== set.ballots.length) {
      return `очікувалось ${this.candidates.length} бюлетені з множниками`;
    }

    let ballots: Ballot[];
    try {
      ballots = set.ballots.map(parseBallot);
    } catch {
      return "бюлетень містить зайві або некоректні дані";
    }

    const ids = new Set(ballots.map((ballot) => ballot.id));
    if (ids.size !== 1) return "бюлетені набору мають різні ID";
    const [id] = ids;
    if (id === undefined || this.revealedIds.has(id)) return `ID ${id} повторюється в іншому наборі`;
    this.revealedIds.add(id);

    const choices = ballots.map((ballot) => ballot.candidateId).sort();
    const expected = this.candidates.map((candidate) => candidate.id).sort();
    if (choices.join() !== expected.join()) {
      return `бюлетені ${ballots.map((ballot) => ballot.candidateId).join(", ")} замість ${expected.join(", ")}`;
    }

    for (const [j, text] of set.ballots.entries()) {
      const r = set.factors[j] ?? 0n;
      if (gcd(r, this.publicKey.n) !== 1n) return `множник r бюлетеня ${j + 1} не взаємно простий з n`;
      if (blind(hashMessage(text, this.publicKey.n), r, this.publicKey) !== blinded[j]) {
        return `H·rᵉ mod n бюлетеня ${j + 1} ≠ отриманому раніше H'`;
      }
    }
    return undefined;
  }

  private open(envelope: Envelope): { ok: true; text: string; ballot: Ballot; signature: bigint } | { ok: false; error: string } {
    try {
      const payload: unknown = JSON.parse(decrypt(envelope.cipher, this.keys.privateKey));
      if (
        typeof payload !== "object" ||
        payload === null ||
        typeof (payload as { ballot?: unknown }).ballot !== "string" ||
        typeof (payload as { signature?: unknown }).signature !== "string"
      ) {
        throw new Error("Невідомий формат повідомлення");
      }
      const { ballot: text, signature } = payload as { ballot: string; signature: string };
      return { ok: true, text, ballot: parseBallot(text), signature: BigInt(`0x${signature}`) };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  private refuse(voter: VoterRecord, reason: SigningRejection, extra?: string): Rejected<SigningRejection> {
    voter.status = "refused";
    return rejected(reason, SIGNING_REJECTIONS, extra);
  }

  private reject(reason: VoteRejection, extra?: string): Rejected<VoteRejection> {
    this.rejectedCount += 1;
    return rejected(reason, VOTE_REJECTIONS, extra);
  }

  private note(check: CheckName, passed: boolean, detail: string): void {
    this.observer?.({ check, passed, detail });
  }
}

function rejected<Reason extends string>(
  reason: Reason,
  messages: Record<Reason, string>,
  extra?: string,
): Rejected<Reason> {
  const base = messages[reason];
  return { status: "rejected", reason, message: extra ? `${base} (${extra})` : base };
}
