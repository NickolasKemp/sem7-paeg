import { signBody, validatePart, type PartCheck, type Signed } from "./message.ts";
import { generateKeyPair, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  lowerLabel,
  type BallotPart,
  type Batch,
  type Branch,
  type BureauKeys,
  type District,
  type LowerLabel,
  type Observer,
  type PartResult,
} from "./types.ts";

/**
 * Дільнична виборча комісія нижнього рівня (ДВК-гілка.дільниця): приймає від виборців своєї дільниці
 * одну частину бюлетеня своєї гілки, перевіряє мандат і ЕЦП, не допускає повторного голосування,
 * публікує прийняте і передає підписаний пакет до своєї СВК. Вміст частин їй недоступний.
 */
export class LowerCommission {
  readonly label: LowerLabel;
  readonly branch: Branch;
  readonly district: District;

  readonly #keys: KeyPair;
  readonly #bureauKeys: BureauKeys;
  readonly #observer: Observer | undefined;
  readonly #accepted = new Map<bigint, BallotPart>();

  constructor(options: { branch: Branch; district: District; bureauKeys: BureauKeys; bits?: number; observer?: Observer }) {
    this.branch = options.branch;
    this.district = options.district;
    this.label = lowerLabel(options.branch, options.district);
    this.#keys = generateKeyPair(options.bits ?? 512);
    this.#bureauKeys = options.bureauKeys;
    this.#observer = options.observer;
  }

  /** Ключ, яким СВК і виборці перевіряють підпис ДВК під її публікацією. */
  get publicKey(): PublicKey {
    return this.#keys.publicKey;
  }

  receive(part: BallotPart): PartResult {
    const note = (check: PartCheck | "once", passed: boolean, detail: string) =>
      this.#observer?.({ actor: this.label, check, passed, detail });

    const rejection = validatePart(part, this.#bureauKeys, { branch: this.branch, district: this.district }, note);
    if (rejection) return { status: "rejected", reason: rejection };

    const { voterId } = part.credential.token;
    const used = this.#accepted.has(voterId);
    note("once", !used, used ? `ID ${voterId} уже голосував на цій ДВК` : "мандат використано вперше — відмітку поставлено");
    if (used) return { status: "rejected", reason: "ALREADY_VOTED" };

    this.#accepted.set(voterId, part);
    return { status: "accepted", voterId };
  }

  /** Публікація прийнятих частин під ЕЦП ДВК — той самий пакет передається до СВК. */
  publish(): Signed<Batch> {
    return signBody({ from: this.label, parts: this.entries() }, this.#keys.privateKey);
  }

  /** Що потрапляє до публікації; нечесна ДВК у моделі атак підміняє саме цей набір. */
  protected entries(): readonly BallotPart[] {
    return [...this.#accepted.values()];
  }
}
