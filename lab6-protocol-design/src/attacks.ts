import { signBlinded } from "./blind-signature.ts";
import { RegistrationBureau, type Registration } from "./bureau.ts";
import { LowerCommission } from "./lower-commission.ts";
import { MiddleCommission } from "./middle-commission.ts";
import { encrypt, type PublicKey } from "./rsa.ts";
import type { BallotPart, RegistrationRequest, RegistrationResult } from "./types.ts";

/** Зміна, яку нечесна комісія вносить у свою публікацію перед підписанням. */
export type Tamper = (parts: readonly BallotPart[]) => readonly BallotPart[];

type LowerOptions = ConstructorParameters<typeof LowerCommission>[0];
type MiddleOptions = ConstructorParameters<typeof MiddleCommission>[0];

export class CorruptLowerCommission extends LowerCommission {
  readonly #tamper: Tamper;

  constructor(options: LowerOptions, tamper: Tamper) {
    super(options);
    this.#tamper = tamper;
  }

  protected override entries(): readonly BallotPart[] {
    return this.#tamper(super.entries());
  }
}

export class CorruptMiddleCommission extends MiddleCommission {
  readonly #tamper: Tamper;

  constructor(options: MiddleOptions, tamper: Tamper) {
    super(options);
    this.#tamper = tamper;
  }

  protected override entries(): readonly BallotPart[] {
    return this.#tamper(super.entries());
  }
}

/** Нечесна БР: підписує мандати без перевірок і готова передати свої записи ЦВК. */
export class CorruptBureau extends RegistrationBureau {
  issueGhost(request: RegistrationRequest): RegistrationResult {
    return { status: "registered", blindSignature: signBlinded(request.blindedToken, this.keys[request.district].privateKey) };
  }

  leakRegistry(): readonly Registration[] {
    return [...this.registry.values()];
  }
}

/** Перебір малих значень відкритим ключем ЦВК — спрацьовує лише проти детермінованих малих частин. */
export function decodeByDictionary(cipher: bigint, key: PublicKey, maxValue: bigint): bigint | undefined {
  for (let value = 1n; value <= maxValue; value += 1n) {
    if (encrypt(value, key) === cipher) return value;
  }
  return undefined;
}
