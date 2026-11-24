import { signBody, validatePart, verifyBody, type Signed } from "./message.ts";
import { generateKeyPair, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  DISTRICTS,
  lowerLabel,
  middleLabel,
  type BallotPart,
  type Batch,
  type BatchRejection,
  type Branch,
  type BureauKeys,
  type CommissionLabel,
  type District,
  type ExcludedPart,
  type MiddleLabel,
  type Observer,
  type PartResult,
} from "./types.ts";

export type CollectReport =
  | { readonly status: "accepted"; readonly from: CommissionLabel; readonly accepted: number; readonly excluded: readonly ExcludedPart[] }
  | { readonly status: "rejected"; readonly from: CommissionLabel; readonly reason: BatchRejection };

/**
 * Виборча комісія середнього рівня (СВК-гілка): приймає підписані пакети від двох ДВК своєї гілки,
 * повторно перевіряє кожну частину, відкидає дублікати, розглядає скарги виборців і передає
 * зведений підписаний пакет до ЦВК. Бачить лише зашифровані частини однієї гілки.
 */
export class MiddleCommission {
  readonly label: MiddleLabel;
  readonly branch: Branch;

  readonly #keys: KeyPair;
  readonly #bureauKeys: BureauKeys;
  readonly #lower: ReadonlyMap<CommissionLabel, { readonly district: District; readonly key: PublicKey }>;
  readonly #observer: Observer | undefined;
  readonly #parts = new Map<bigint, BallotPart>();

  constructor(options: {
    branch: Branch;
    lowerKeys: Readonly<Record<District, PublicKey>>;
    bureauKeys: BureauKeys;
    bits?: number;
    observer?: Observer;
  }) {
    this.branch = options.branch;
    this.label = middleLabel(options.branch);
    this.#keys = generateKeyPair(options.bits ?? 512);
    this.#bureauKeys = options.bureauKeys;
    this.#lower = new Map(
      DISTRICTS.map((district) => [lowerLabel(options.branch, district), { district, key: options.lowerKeys[district] }]),
    );
    this.#observer = options.observer;
  }

  get publicKey(): PublicKey {
    return this.#keys.publicKey;
  }

  /** Прийом пакета від ДВК: перевірка відправника, ЕЦП пакета і кожної частини окремо. */
  collect(batch: Signed<Batch>): CollectReport {
    const { from, parts } = batch.body;
    const sender = this.#lower.get(from);
    this.#note("sender", sender !== undefined, sender ? `${from} підпорядкована ${this.label}` : `${from} не належить до гілки ${this.branch}`);
    if (!sender) return { status: "rejected", from, reason: "UNKNOWN_SENDER" };

    const signed = verifyBody(batch, sender.key);
    this.#note("batchSignature", signed, signed ? `ЕЦП ${from} під пакетом справжній (частин: ${parts.length})` : `ЕЦП ${from} недійсний`);
    if (!signed) return { status: "rejected", from, reason: "BAD_BATCH_SIGNATURE" };

    const excluded: ExcludedPart[] = [];
    let accepted = 0;
    for (const part of parts) {
      const result = this.#accept(part, sender.district);
      if (result.status === "accepted") accepted += 1;
      else excluded.push({ from, voterId: part.credential.token.voterId, reason: result.reason });
    }
    for (const entry of excluded) this.#note("part", false, `${from}: ID ${entry.voterId} відкинуто [${entry.reason}]`);
    this.#note("part", excluded.length === 0, `від ${from} прийнято: ${accepted}, відкинуто: ${excluded.length}`);
    return { status: "accepted", from, accepted, excluded };
  }

  /**
   * Скарга виборця: він надсилає свою підписану частину, якої немає в пакеті ДВК.
   * Частину приймають, якщо вона дійсна і для цього ID ще нічого не зараховано.
   */
  appeal(part: BallotPart): PartResult {
    const result = this.#accept(part, part.credential.district);
    this.#note("appeal", result.status === "accepted", result.status === "accepted"
      ? `скаргу ID ${part.credential.token.voterId} задоволено — частину відновлено`
      : `скаргу відхилено [${result.reason}]`);
    return result;
  }

  publish(): Signed<Batch> {
    return signBody({ from: this.label, parts: this.entries() }, this.#keys.privateKey);
  }

  protected entries(): readonly BallotPart[] {
    return [...this.#parts.values()];
  }

  #accept(part: BallotPart, district: District): PartResult {
    const rejection = validatePart(part, this.#bureauKeys, { branch: this.branch, district });
    if (rejection) return { status: "rejected", reason: rejection };

    const { voterId } = part.credential.token;
    if (this.#parts.has(voterId)) return { status: "rejected", reason: "DUPLICATE" };

    this.#parts.set(voterId, part);
    return { status: "accepted", voterId };
  }

  #note(check: string, passed: boolean, detail: string): void {
    this.#observer?.({ actor: this.label, check, passed, detail });
  }
}
