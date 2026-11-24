import type { PublicKey } from "./rsa.ts";

/** Кількість раундів шифрування (і відповідних раундів розшифрування). */
export const ROUNDS = 2;

/** Довжина випадкового рядка RP у символах (4 × 16 = 64 біти). */
export const RP_LENGTH = 4;

export type Candidate = { readonly id: number; readonly name: string };

/** Запис спільного впорядкованого списку: позиція в списку задає черговість у протоколі. */
export type RosterEntry = { readonly name: string; readonly publicKey: PublicKey };
export type Roster = readonly RosterEntry[];

/** Набір, який перший виборець збирає від усіх учасників перед першим раундом розшифрування. */
export type CollectedSet = { readonly kind: "collected"; readonly ballots: readonly string[] };

/** Набір, який виборець підписує після свого етапу і передає далі. */
export type SignedSet = {
  readonly kind: "signed";
  readonly from: string;
  readonly ballots: readonly string[];
  readonly signature: bigint;
};

export type IncomingSet = CollectedSet | SignedSet;

/** Кількість голосів за кожного кандидата (за id) і кількість недійсних бюлетенів. */
export type Tally = { readonly votes: ReadonlyMap<number, number>; readonly invalid: number };

/** Остаточний набір відкритих бюлетенів, який публікує останній виборець, і оголошений ним підсумок. */
export type Publication = { readonly set: SignedSet; readonly announced: Tally };

/**
 * Канонічний текст набору — саме він хешується і підписується.
 * Шифротекст може містити будь-які символи, тому кожен бюлетень записано з довжиною.
 */
export function serializeSet(from: string, ballots: readonly string[]): string {
  return `${from}|${ballots.map((ballot) => `${ballot.length}:${ballot}`).join("")}`;
}

export const REJECTIONS = {
  NOT_RECEIVED: "Набір від попереднього учасника не надійшов",
  UNEXPECTED_SENDER: "Набір надіслав не той учасник, що стоїть попереду в списку",
  BAD_SIGNATURE: "ЕЦП набору не пройшов перевірку відкритим ключем попереднього учасника",
  COUNT_MISMATCH: "Кількість бюлетенів не дорівнює кількості учасників",
  BAD_CIPHERTEXT: "Шар бюлетеня не знімається закритим ключем виборця",
  RP_NOT_FOUND: "Серед бюлетенів немає жодного з власним RP виборця",
  RP_DUPLICATE: "Власний RP виборця знайдено у кількох бюлетенях",
  TALLY_MISMATCH: "Повторний підрахунок не збігається з оголошеним результатом",
} as const;

export type Rejection = keyof typeof REJECTIONS;
export type Failure = { readonly reason: Rejection; readonly detail: string };
