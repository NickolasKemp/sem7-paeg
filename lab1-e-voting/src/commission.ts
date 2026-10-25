import { decrypt, generateKeyPair, verify, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  parseBallot,
  REJECTION_REASONS,
  type Ballot,
  type Candidate,
  type ElectionResults,
  type Envelope,
  type ProcessingResult,
  type RegisteredVoter,
  type RejectionReason,
} from "./types.ts";

export type CheckName =
  | "decrypt"
  | "inList"
  | "signature"
  | "identity"
  | "notVotedYet"
  | "ballotValid";

export type CheckEvent = { readonly check: CheckName; readonly passed: boolean; readonly detail: string };
export type CommissionObserver = (event: CheckEvent) => void;

/**
 * Виборча комісія (ВК): веде список допущених виборців та їх відкритих ключів,
 * список кандидатів, приймає зашифровані бюлетені, перевіряє їх і рахує голоси.
 */
export class ElectionCommission {
  readonly keys: KeyPair;
  readonly candidates: readonly Candidate[];

  private readonly voters = new Map<string, RegisteredVoter>();
  private readonly tally = new Map<string, number>();
  private readonly observer: CommissionObserver | undefined;
  private acceptedCount = 0;
  private rejectedCount = 0;

  constructor(options: {
    candidates: readonly Candidate[];
    bits?: number;
    observer?: CommissionObserver;
  }) {
    this.keys = generateKeyPair(options.bits ?? 512);
    this.candidates = options.candidates;
    this.observer = options.observer;
    for (const candidate of options.candidates) this.tally.set(candidate.id, 0);
  }

  /** Відкритий ключ ВК публікується у вільному доступі. */
  get publicKey(): PublicKey {
    return this.keys.publicKey;
  }

  /** Крок 1: перевірка особи виборця та внесення його до списку разом з відкритим ключем. */
  registerVoter(name: string, publicKey: PublicKey): void {
    if (this.voters.has(name)) throw new Error(`Виборець «${name}» уже зареєстрований`);
    this.voters.set(name, { name, publicKey, hasVoted: false });
  }

  get voterList(): readonly RegisteredVoter[] {
    return [...this.voters.values()];
  }

  /** Крок 3: розшифрування бюлетеня та всі передбачені протоколом перевірки. */
  receive(envelope: Envelope): ProcessingResult {
    const opened = this.open(envelope);
    if (!opened.ok) return this.reject(envelope.senderName, "UNDECRYPTABLE", opened.error);

    const { ballot, signature, signedText } = opened;
    this.note("decrypt", true, `бюлетень розшифровано: кандидат «${ballot.candidateId}»`);

    const voter = this.voters.get(envelope.senderName);
    if (!voter) {
      this.note("inList", false, `«${envelope.senderName}» відсутній у списку виборців`);
      return this.reject(envelope.senderName, "NOT_IN_LIST");
    }
    this.note("inList", true, `«${voter.name}» є у списку допущених виборців`);

    const signatureValid = verify(signedText, signature, voter.publicKey);
    this.note(
      "signature",
      signatureValid,
      signatureValid ? "H = H_c, ЕЦП справжній" : "H ≠ H_c, ЕЦП недійсний",
    );
    if (!signatureValid) return this.reject(envelope.senderName, "BAD_SIGNATURE");

    const identityMatches = ballot.voterName === envelope.senderName;
    this.note(
      "identity",
      identityMatches,
      identityMatches
        ? "ПІБ у бюлетені збігається з відправником"
        : `у бюлетені «${ballot.voterName}», а надіслав «${envelope.senderName}»`,
    );
    if (!identityMatches) return this.reject(envelope.senderName, "IDENTITY_MISMATCH");

    if (voter.hasVoted) {
      this.note("notVotedYet", false, `«${voter.name}» уже має позначку про голосування`);
      return this.reject(envelope.senderName, "ALREADY_VOTED");
    }
    this.note("notVotedYet", true, `позначки про голосування «${voter.name}» немає`);

    const candidate = this.candidates.find((item) => item.id === ballot.candidateId);
    if (!candidate) {
      this.note("ballotValid", false, `кандидата «${ballot.candidateId}» немає у списку`);
      return this.reject(envelope.senderName, "INVALID_BALLOT");
    }
    this.note("ballotValid", true, `голос за кандидата «${candidate.name}»`);

    voter.hasVoted = true; // фіксація факту голосування
    this.tally.set(candidate.id, (this.tally.get(candidate.id) ?? 0) + 1);
    this.acceptedCount += 1;

    return { status: "accepted", voterName: voter.name, candidateId: candidate.id };
  }

  /** Крок 4: підрахунок голосів і публікація результатів. */
  publishResults(): ElectionResults {
    const max = Math.max(0, ...this.tally.values());
    const leaders = this.candidates.filter((candidate) => this.tally.get(candidate.id) === max);

    return {
      tally: new Map(this.tally),
      accepted: this.acceptedCount,
      rejected: this.rejectedCount,
      turnout: {
        voted: this.voterList.filter((voter) => voter.hasVoted).length,
        registered: this.voters.size,
      },
      leaders: max === 0 ? [] : leaders,
      isTie: max > 0 && leaders.length > 1,
    };
  }

  private open(
    envelope: Envelope,
  ):
    | { ok: true; ballot: Ballot; signature: bigint; signedText: string }
    | { ok: false; error: string } {
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
      const { ballot: signedText, signature } = payload as { ballot: string; signature: string };
      return { ok: true, ballot: parseBallot(signedText), signature: BigInt(`0x${signature}`), signedText };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  private note(check: CheckName, passed: boolean, detail: string): void {
    this.observer?.({ check, passed, detail });
  }

  private reject(voterName: string, reason: RejectionReason, extra?: string): ProcessingResult {
    this.rejectedCount += 1;
    const base = REJECTION_REASONS[reason];
    return { status: "rejected", voterName, reason, message: extra ? `${base} (${extra})` : base };
  }
}
