import { randomBigInt } from "./bigint-math.ts";
import { generateKeyPair, sign, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  REGISTRATION_REFUSALS,
  serializeRnList,
  type Citizen,
  type Observer,
  type Registration,
  type RegistrationRefusal,
  type RegistrationRequest,
  type RegistrationResult,
  type RnListMessage,
} from "./types.ts";

export type BureauCheck = "inRoll" | "identity" | "votingRight" | "notRegistered";

/** Діапазон RN значно більший за кількість виборців, щоб дійсний RN неможливо було вгадати. */
const RN_MIN = 100_000n;
const RN_MAX = 999_999n;
const ADULT_AGE = 18;

/**
 * Бюро реєстрації (БР): звіряє особу виборця з реєстром громадян, перевіряє право голосу
 * та відсутність попередньої реєстрації, видає випадковий унікальний RN і зберігає зв’язок
 * «виборець — RN — відкритий ключ ЕЦП». Голосів виборців БР не бачить.
 */
export class RegistrationBureau {
  readonly #keys: KeyPair;
  readonly #roll: ReadonlyMap<string, Citizen>;
  readonly #electionDate: string;
  readonly #registry = new Map<string, Registration>();
  readonly #issuedRns = new Set<string>();
  readonly #observer: Observer<BureauCheck> | undefined;

  constructor(options: {
    citizens: readonly Citizen[];
    electionDate: string;
    bits?: number;
    observer?: Observer<BureauCheck>;
  }) {
    this.#keys = generateKeyPair(options.bits ?? 512);
    this.#roll = new Map(options.citizens.map((citizen) => [citizen.passport, citizen]));
    this.#electionDate = options.electionDate;
    this.#observer = options.observer;
  }

  /** Відкритий ключ БР — ним ВК перевіряє ЕЦП під переданим списком RN. */
  get publicKey(): PublicKey {
    return this.#keys.publicKey;
  }

  /** Кроки 1–2: перевірка виборця та видача йому RN. */
  register(request: RegistrationRequest): RegistrationResult {
    const citizen = this.#roll.get(request.passport);
    if (!citizen) {
      this.#note("inRoll", false, `паспорта ${request.passport} немає в реєстрі громадян`);
      return refuse("NOT_IN_ROLL");
    }
    this.#note("inRoll", true, `паспорт ${request.passport} є в реєстрі громадян`);

    const identityMatches = citizen.name === request.name;
    this.#note(
      "identity",
      identityMatches,
      identityMatches
        ? `паспорт належить «${citizen.name}»`
        : `за цим паспортом у реєстрі — «${citizen.name}»`,
    );
    if (!identityMatches) return refuse("IDENTITY_MISMATCH");

    const age = ageOn(citizen.birthDate, this.#electionDate);
    const hasRight = age >= ADULT_AGE;
    this.#note("votingRight", hasRight, `на день виборів ${this.#electionDate} виповниться ${age} р.`);
    if (!hasRight) return refuse("NO_VOTING_RIGHT");

    if (this.#registry.has(request.passport)) {
      this.#note("notRegistered", false, `«${citizen.name}» уже має RN`);
      return refuse("ALREADY_REGISTERED");
    }
    this.#note("notRegistered", true, `«${citizen.name}» раніше не реєструвався`);

    const rn = this.#issueRn();
    this.#registry.set(request.passport, { ...request, rn });
    return { status: "registered", rn };
  }

  /** Реєстр БР у тому вигляді, у якому його бачить сама БР (для демонстрації). */
  get registry(): readonly Registration[] {
    return [...this.#registry.values()];
  }

  /** Крок 3: список дійсних RN і відкритих ключів без персональних даних, підписаний БР. */
  exportRnList(): RnListMessage {
    const payload = serializeRnList(
      shuffle([...this.#registry.values()]).map(({ rn, publicKey }) => ({ rn, publicKey })),
    );
    return { payload, signature: sign(payload, this.#keys.privateKey) };
  }

  /** Публікація списку зареєстрованих виборців без RN — для контролю кількості бюлетенів. */
  publishVoterList(): readonly string[] {
    return [...this.#registry.values()].map(({ name }) => name).sort((a, b) => a.localeCompare(b, "uk"));
  }

  #issueRn(): string {
    while (true) {
      const rn = randomBigInt(RN_MIN, RN_MAX).toString();
      if (!this.#issuedRns.has(rn)) {
        this.#issuedRns.add(rn);
        return rn;
      }
    }
  }

  #note(check: BureauCheck, passed: boolean, detail: string): void {
    this.#observer?.({ check, passed, detail });
  }
}

function refuse(reason: RegistrationRefusal): RegistrationResult {
  return { status: "refused", reason, message: REGISTRATION_REFUSALS[reason] };
}

/** Повних років на дату `on` (обидві дати у форматі YYYY-MM-DD). */
function ageOn(birthDate: string, on: string): number {
  const years = Number(on.slice(0, 4)) - Number(birthDate.slice(0, 4));
  return on.slice(5) < birthDate.slice(5) ? years - 1 : years;
}

/** Порядок записів у списку для ВК не повинен повторювати порядок реєстрації (Фішер — Єйтс). */
function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Number(randomBigInt(0n, BigInt(i)));
    [items[i], items[j]] = [items[j]!, items[i]!];
  }
  return items;
}
