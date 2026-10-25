import type { PublicKey } from "./rsa.ts";

/** ID кандидата — число, яке виборець розкладає на множники. */
export type Candidate = { readonly id: bigint; readonly name: string };

/** Запис списку виборців, який ЦВК формує і передає ВК-1 та ВК-2. */
export type VoterRecord = { readonly name: string; readonly publicKey: PublicKey };

export const PART_COMMISSIONS = ["ВК-1", "ВК-2"] as const;
export type PartCommissionLabel = (typeof PART_COMMISSIONS)[number];

/** Частина бюлетеня, як її бачать ВК і ЦВК: ID виборця + RSA(EVP). */
export type BallotPart = { readonly voterId: bigint; readonly encryptedPart: bigint };

/** EDS(RSA(EVP), ID): частина бюлетеня з ЕЦП виборця. */
export type SignedPart = BallotPart & { readonly signature: bigint };

/** Повідомлення до однієї з ВК: ПІБ виборця не приховується. */
export type PartMessage = { readonly senderName: string; readonly part: SignedPart };

/** Канонічний текст частини бюлетеня — саме він хешується та підписується. */
export function serializePart(part: BallotPart): string {
  return JSON.stringify({ voterId: part.voterId.toString(), encryptedPart: part.encryptedPart.toString(16) });
}

export const VK_REJECTIONS = {
  NOT_IN_LIST: "Відправника немає у списку виборців, отриманому від ЦВК",
  BAD_SIGNATURE: "ЕЦП не пройшов перевірку відкритим ключем виборця",
  ALREADY_VOTED: "Від цього виборця вже прийнято частину бюлетеня",
} as const;

export const CVK_REJECTIONS = {
  MISSING_PART: "Для ID опубліковано лише одну частину бюлетеня",
  NOT_A_CANDIDATE: "Після об'єднання і розшифрування отримано число, що не є ID кандидата",
} as const;

export type VkRejection = keyof typeof VK_REJECTIONS;
export type CvkRejection = keyof typeof CVK_REJECTIONS;

export type VkResult =
  | { readonly status: "accepted"; readonly voterName: string; readonly voterId: bigint }
  | { readonly status: "rejected"; readonly voterName: string; readonly reason: VkRejection };

/** Рядок, який ЦВК формує для кожного ID після зіставлення частин. */
export type CombinedBallot = {
  readonly voterId: bigint;
  readonly parts: readonly [bigint | undefined, bigint | undefined];
} & (
  | { readonly status: "accepted"; readonly combined: bigint; readonly ballot: bigint }
  | { readonly status: "rejected"; readonly reason: "NOT_A_CANDIDATE"; readonly combined: bigint; readonly ballot: bigint }
  | { readonly status: "rejected"; readonly reason: "MISSING_PART" }
);

export type ElectionResults = {
  readonly ballots: readonly CombinedBallot[];
  readonly tally: ReadonlyMap<bigint, number>;
  readonly leaders: readonly Candidate[];
  readonly isTie: boolean;
};
