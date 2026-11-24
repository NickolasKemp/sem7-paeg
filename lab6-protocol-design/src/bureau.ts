import { signBlinded } from "./blind-signature.ts";
import { generateKeyPair, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  type BureauKeys,
  type Citizen,
  type District,
  type Observer,
  type RegistrationRefusal,
  type RegistrationRequest,
  type RegistrationResult,
} from "./types.ts";

const ADULT_AGE = 18;

/** Що БР зберігає про виборця: особу і лише замаскований хеш мандата. */
export type Registration = { readonly name: string; readonly district: District; readonly blindedToken: bigint };

/**
 * Бюро реєстрації (частина ЦВК): звіряє особу з реєстром громадян, перевіряє право голосу
 * і дільницю, ставить сліпий ЕЦП на мандат ключем дільниці — не більше одного разу на особу.
 * Мандата у відкритому вигляді БР не бачить, бюлетенів не отримує.
 */
export class RegistrationBureau {
  protected readonly keys: Readonly<Record<District, KeyPair>>;
  protected readonly registry = new Map<string, Registration>();

  readonly #roll: ReadonlyMap<string, Citizen>;
  readonly #electionDate: string;
  readonly #observer: Observer | undefined;

  constructor(options: { citizens: readonly Citizen[]; electionDate: string; bits?: number; observer?: Observer }) {
    const bits = options.bits ?? 512;
    this.keys = { 1: generateKeyPair(bits), 2: generateKeyPair(bits) };
    this.#roll = new Map(options.citizens.map((citizen) => [citizen.passport, citizen]));
    this.#electionDate = options.electionDate;
    this.#observer = options.observer;
  }

  /** Відкриті ключі сліпого ЕЦП публікуються: ними будь-хто перевіряє мандати. */
  get publicKeys(): BureauKeys {
    return { 1: this.keys[1].publicKey, 2: this.keys[2].publicKey };
  }

  publicKey(district: District): PublicKey {
    return this.keys[district].publicKey;
  }

  register(request: RegistrationRequest): RegistrationResult {
    const refuse = (reason: RegistrationRefusal): RegistrationResult => ({ status: "refused", reason });

    const citizen = this.#roll.get(request.passport);
    this.#note("inRoll", citizen !== undefined, citizen ? `паспорт ${request.passport} є в реєстрі` : `паспорта ${request.passport} немає в реєстрі`);
    if (!citizen) return refuse("NOT_IN_ROLL");

    const sameName = citizen.name === request.name;
    this.#note("identity", sameName, sameName ? "ПІБ збігається з реєстром" : `за паспортом зареєстровано «${citizen.name}»`);
    if (!sameName) return refuse("IDENTITY_MISMATCH");

    const age = ageOn(citizen.birthDate, this.#electionDate);
    const hasRight = age >= ADULT_AGE;
    this.#note("votingRight", hasRight, `на день виборів ${this.#electionDate} виповниться ${age} р.`);
    if (!hasRight) return refuse("NO_VOTING_RIGHT");

    const ownDistrict = citizen.district === request.district;
    this.#note("district", ownDistrict, `за реєстром — дільниця №${citizen.district}, запит — №${request.district}`);
    if (!ownDistrict) return refuse("WRONG_DISTRICT");

    const registered = this.registry.has(request.passport);
    this.#note("once", !registered, registered ? `«${citizen.name}» уже отримав мандат` : "мандат видається вперше");
    if (registered) return refuse("ALREADY_REGISTERED");

    this.registry.set(request.passport, { name: citizen.name, district: citizen.district, blindedToken: request.blindedToken });
    return { status: "registered", blindSignature: signBlinded(request.blindedToken, this.keys[citizen.district].privateKey) };
  }

  /** Публічний список зареєстрованих по дільницях (без мандатів): верхня межа кількості бюлетенів. */
  publishRegistered(): Readonly<Record<District, readonly string[]>> {
    const names = (district: District) =>
      [...this.registry.values()].filter((entry) => entry.district === district).map((entry) => entry.name).sort();
    return { 1: names(1), 2: names(2) };
  }

  #note(check: string, passed: boolean, detail: string): void {
    this.#observer?.({ actor: "БР", check, passed, detail });
  }
}

function ageOn(birthDate: string, on: string): number {
  const years = Number(on.slice(0, 4)) - Number(birthDate.slice(0, 4));
  return on.slice(5) < birthDate.slice(5) ? years - 1 : years;
}
