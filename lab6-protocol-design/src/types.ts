import type { PublicKey } from "./rsa.ts";

/**
 * Гілки збирання бюлетеня: частина 1 проходить ДВК-1.x → СВК-1, частина 2 — ДВК-2.x → СВК-2.
 * Виборчі дільниці: на кожній працює по одній ДВК від кожної гілки.
 */
export const BRANCHES = [1, 2] as const;
export type Branch = (typeof BRANCHES)[number];

export const DISTRICTS = [1, 2] as const;
export type District = (typeof DISTRICTS)[number];

export type MiddleLabel = `СВК-${Branch}`;
export type LowerLabel = `ДВК-${Branch}.${District}`;
export type CommissionLabel = MiddleLabel | LowerLabel;

export const middleLabel = (branch: Branch): MiddleLabel => `СВК-${branch}`;
export const lowerLabel = (branch: Branch, district: District): LowerLabel => `ДВК-${branch}.${district}`;

/** Відкриті ключі БР: окремий ключ сліпого ЕЦП для кожної дільниці. */
export type BureauKeys = Readonly<Record<District, PublicKey>>;

export type Candidate = { readonly id: bigint; readonly name: string };

/** Запис державного реєстру громадян; дільниця визначається місцем проживання. */
export type Citizen = {
  readonly name: string;
  readonly passport: string;
  readonly birthDate: string;
  readonly district: District;
};

/**
 * Анонімний мандат виборця: випадковий ID і відкритий ключ ЕЦП, який виборець згенерував
 * лише для цього голосування. Під ним стоїть сліпий підпис БР — БР його ніколи не бачила.
 */
export type Token = { readonly voterId: bigint; readonly publicKey: PublicKey };
export type Credential = { readonly token: Token; readonly district: District; readonly signature: bigint };

/** Звернення до БР: особа виборця і замаскований хеш мандата H' = H·rᵉ mod n. */
export type RegistrationRequest = {
  readonly name: string;
  readonly passport: string;
  readonly district: District;
  readonly blindedToken: bigint;
};

export const REGISTRATION_REFUSALS = {
  NOT_IN_ROLL: "Особи з таким паспортом немає в реєстрі громадян",
  IDENTITY_MISMATCH: "ПІБ не збігається з паспортними даними в реєстрі",
  NO_VOTING_RIGHT: "Особа не має права голосу: на день виборів їй не виповниться 18 років",
  WRONG_DISTRICT: "Громадянин належить до іншої виборчої дільниці",
  ALREADY_REGISTERED: "Виборець уже отримав сліпий підпис — другий мандат не видається",
} as const;
export type RegistrationRefusal = keyof typeof REGISTRATION_REFUSALS;

export type RegistrationResult =
  | { readonly status: "registered"; readonly blindSignature: bigint }
  | { readonly status: "refused"; readonly reason: RegistrationRefusal };

/** Частина бюлетеня: мандат + RSA(mᵢ) ключем ЦВК + ЕЦП виборця ключем з мандата. */
export type BallotPart = {
  readonly credential: Credential;
  readonly branch: Branch;
  readonly encryptedPart: bigint;
  readonly signature: bigint;
};

/** Те, що підписує виборець: номер гілки входить у підпис, тож частину не перенаправити в іншу гілку. */
export function partPayload(part: Pick<BallotPart, "credential" | "branch" | "encryptedPart">) {
  return { voterId: part.credential.token.voterId, branch: part.branch, encryptedPart: part.encryptedPart };
}

/** Пакет, який комісія підписує власним ключем і публікує / передає на рівень вище. */
export type Batch = { readonly from: CommissionLabel; readonly parts: readonly BallotPart[] };

export const PART_REJECTIONS = {
  WRONG_COMMISSION: "Частину адресовано іншій ДВК (інша гілка або дільниця)",
  NOT_ELIGIBLE: "Сліпий ЕЦП БР на мандаті недійсний — права голосу не підтверджено",
  BAD_SIGNATURE: "ЕЦП частини не перевіряється ключем з мандата (зміна або чужий підпис)",
  ALREADY_VOTED: "За цим мандатом частину бюлетеня вже прийнято",
  DUPLICATE: "Частина з цим ID виборця вже є у зведеному списку",
} as const;
export type PartRejection = keyof typeof PART_REJECTIONS;

export const BATCH_REJECTIONS = {
  UNKNOWN_SENDER: "Пакет надійшов не від підпорядкованої комісії",
  BAD_BATCH_SIGNATURE: "ЕЦП комісії під пакетом недійсний",
} as const;
export type BatchRejection = keyof typeof BATCH_REJECTIONS;

export const RESULT_REJECTIONS = {
  MISSING_PART: "Для ID виборця надійшла лише одна частина бюлетеня",
  NOT_A_CANDIDATE: "Після об'єднання і розшифрування отримано число, що не є ID кандидата",
} as const;
export type ResultRejection = keyof typeof RESULT_REJECTIONS;

export type PartResult =
  | { readonly status: "accepted"; readonly voterId: bigint }
  | { readonly status: "rejected"; readonly reason: PartRejection };

/** Запис, що відкидається комісією з пакета: доказ проти комісії, яка його підписала. */
export type ExcludedPart = { readonly from: CommissionLabel; readonly voterId: bigint; readonly reason: PartRejection };

export type CheckEvent = {
  readonly actor: string;
  readonly check: string;
  readonly passed: boolean;
  readonly detail: string;
};
export type Observer = (event: CheckEvent) => void;

/** Рядок публікації ЦВК: ID виборця → обидві частини → їх добуток → розшифрований бюлетень. */
export type ResultRow = {
  readonly voterId: bigint;
  readonly district: District;
  readonly parts: readonly [bigint | undefined, bigint | undefined];
} & (
  | { readonly status: "accepted"; readonly combined: bigint; readonly ballot: bigint }
  | { readonly status: "rejected"; readonly reason: "NOT_A_CANDIDATE"; readonly combined: bigint; readonly ballot: bigint }
  | { readonly status: "rejected"; readonly reason: "MISSING_PART" }
);

export type Tally = ReadonlyMap<bigint, number>;

export type ElectionResults = {
  readonly rows: readonly ResultRow[];
  readonly excluded: readonly ExcludedPart[];
  readonly rejectedBatches: readonly { readonly from: CommissionLabel; readonly reason: BatchRejection }[];
  readonly tally: Tally;
  readonly byDistrict: Readonly<Record<District, Tally>>;
};
