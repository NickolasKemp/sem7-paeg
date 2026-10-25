import { decrypt, generateKeyPair, verify, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  isRecord,
  parseRnList,
  parseVoteMessage,
  REJECTION_REASONS,
  type Candidate,
  type ElectionResults,
  type Envelope,
  type Observer,
  type ProcessingResult,
  type PublishedBallot,
  type RejectionReason,
  type RnListMessage,
  type VoteMessage,
} from "./types.ts";

export type CommissionCheck =
  | "rnListSignature"
  | "decrypt"
  | "rnInList"
  | "rnNotUsed"
  | "signature"
  | "idUnique"
  | "ballotValid";

/** Запис реєстру ВК: що ВК знає про кожен RN (персональних даних тут немає). */
export type RnEntry = { readonly rn: string; readonly publicKey: PublicKey; readonly used: boolean };

export type RnListImport = { readonly ok: true; readonly count: number } | { readonly ok: false; readonly error: string };

/**
 * Виборча комісія (ВК): отримує від БР список дійсних RN з відкритими ключами ЕЦП,
 * приймає зашифровані повідомлення (ID; RN; бюлетень), перевіряє їх, рахує голоси
 * та публікує список ID з підписаними бюлетенями. Осіб виборців ВК не знає.
 */
export class ElectionCommission {
  readonly candidates: readonly Candidate[];

  readonly #keys: KeyPair;
  readonly #rns = new Map<string, { publicKey: PublicKey; used: boolean }>();
  readonly #ballots = new Map<string, PublishedBallot>();
  readonly #observer: Observer<CommissionCheck> | undefined;
  #rejected = 0;

  constructor(options: { candidates: readonly Candidate[]; bits?: number; observer?: Observer<CommissionCheck> }) {
    this.#keys = generateKeyPair(options.bits ?? 512);
    this.candidates = options.candidates;
    this.#observer = options.observer;
  }

  /** Відкритий ключ ВК публікується: ним виборці шифрують свої повідомлення. */
  get publicKey(): PublicKey {
    return this.#keys.publicKey;
  }

  /** Крок 3: прийняття списку RN від БР — лише якщо його підписала саме БР. */
  importRnList(message: RnListMessage, bureauKey: PublicKey): RnListImport {
    const authentic = verify(message.payload, message.signature, bureauKey);
    this.#note(
      "rnListSignature",
      authentic,
      authentic ? "ЕЦП БР під списком RN справжній" : "ЕЦП під списком RN не належить БР",
    );
    if (!authentic) return { ok: false, error: "підпис не належить БР" };

    const records = parseRnList(message.payload);
    for (const { rn, publicKey } of records) this.#rns.set(rn, { publicKey, used: false });
    return { ok: true, count: records.length };
  }

  /** Реєстр RN у тому вигляді, у якому його бачить ВК (для демонстрації). */
  get rnRegister(): readonly RnEntry[] {
    return [...this.#rns].map(([rn, { publicKey, used }]) => ({ rn, publicKey, used }));
  }

  /** Крок 5: розшифрування повідомлення та всі передбачені протоколом перевірки. */
  receive(envelope: Envelope): ProcessingResult {
    const opened = this.#open(envelope);
    if (!opened.ok) {
      this.#note("decrypt", false, opened.error);
      return this.#reject("UNDECRYPTABLE");
    }
    const { message, text, signature } = opened;
    this.#note("decrypt", true, `ID = ${message.id}, RN = ${message.rn}, бюлетень: «${message.candidateId}»`);

    const entry = this.#rns.get(message.rn);
    if (!entry) {
      this.#note("rnInList", false, `RN ${message.rn} немає у списку від БР`);
      return this.#reject("UNKNOWN_RN");
    }
    this.#note("rnInList", true, `RN ${message.rn} є у списку від БР`);

    if (entry.used) {
      this.#note("rnNotUsed", false, `RN ${message.rn} уже позначений як використаний`);
      return this.#reject("RN_USED");
    }
    this.#note("rnNotUsed", true, `RN ${message.rn} ще не використовувався`);

    const signatureValid = verify(text, signature, entry.publicKey);
    this.#note(
      "signature",
      signatureValid,
      signatureValid ? "H = H_c, ЕЦП відповідає ключу цього RN" : "H ≠ H_c, ЕЦП не відповідає ключу цього RN",
    );
    if (!signatureValid) return this.#reject("BAD_SIGNATURE");

    if (this.#ballots.has(message.id)) {
      this.#note("idUnique", false, `ID ${message.id} уже є серед прийнятих бюлетенів`);
      return this.#reject("DUPLICATE_ID");
    }
    this.#note("idUnique", true, `ID ${message.id} унікальний`);

    const candidate = this.candidates.find((item) => item.id === message.candidateId);
    if (!candidate) {
      this.#note("ballotValid", false, `кандидата «${message.candidateId}» немає у списку`);
      return this.#reject("INVALID_BALLOT");
    }
    this.#note("ballotValid", true, `голос за кандидата «${candidate.name}»`);

    entry.used = true;
    this.#ballots.set(message.id, { id: message.id, candidateId: candidate.id, message: text, signature });
    return { status: "accepted", id: message.id, candidateId: candidate.id };
  }

  /** Крок 6: підрахунок голосів і публікація результатів разом зі списком (ID; підписаний бюлетень). */
  publishResults(): ElectionResults {
    const ballots = [...this.#ballots.values()].sort((a, b) => a.id.localeCompare(b.id));
    const tally = new Map(this.candidates.map((candidate) => [candidate.id, 0]));
    for (const ballot of ballots) tally.set(ballot.candidateId, (tally.get(ballot.candidateId) ?? 0) + 1);

    const max = Math.max(0, ...tally.values());
    const leaders = max === 0 ? [] : this.candidates.filter((candidate) => tally.get(candidate.id) === max);

    return {
      tally,
      ballots,
      rejected: this.#rejected,
      registered: this.#rns.size,
      leaders,
      isTie: leaders.length > 1,
    };
  }

  #open(
    envelope: Envelope,
  ): { ok: true; message: VoteMessage; text: string; signature: bigint } | { ok: false; error: string } {
    try {
      const payload: unknown = JSON.parse(decrypt(envelope.cipher, this.#keys.privateKey));
      if (!isRecord(payload)) throw new Error("Невідомий формат повідомлення");
      const { text, signature } = payload;
      if (typeof text !== "string" || typeof signature !== "string") throw new Error("Невідомий формат повідомлення");
      return { ok: true, message: parseVoteMessage(text), text, signature: BigInt(`0x${signature}`) };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  #note(check: CommissionCheck, passed: boolean, detail: string): void {
    this.#observer?.({ check, passed, detail });
  }

  #reject(reason: RejectionReason): ProcessingResult {
    this.#rejected += 1;
    return { status: "rejected", reason, message: REJECTION_REASONS[reason] };
  }
}
