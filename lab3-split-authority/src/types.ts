import type { PublicKey } from "./rsa.ts";

export type Candidate = { readonly id: string; readonly name: string };

/** Запис державного реєстру громадян, з яким БР звіряє особу виборця. */
export type Citizen = { readonly name: string; readonly passport: string; readonly birthDate: string };

/** Звернення виборця до БР: особа + відкритий ключ ЕЦП, який виборець згенерував сам. */
export type RegistrationRequest = {
  readonly name: string;
  readonly passport: string;
  readonly publicKey: PublicKey;
};

/** Запис реєстру БР: зв’язок «виборець — RN — відкритий ключ ЕЦП». */
export type Registration = RegistrationRequest & { readonly rn: string };

/** Те, що БР передає до ВК: лише RN і відкриті ключі, без персональних даних. */
export type RnRecord = { readonly rn: string; readonly publicKey: PublicKey };

/** Список RN, підписаний ЕЦП БР, щоб ВК могла перевірити його походження. */
export type RnListMessage = { readonly payload: string; readonly signature: bigint };

/** Повідомлення виборця до ВК: (ID; RN; бюлетень). Імені виборця в ньому немає. */
export type VoteMessage = { readonly id: string; readonly rn: string; readonly candidateId: string };

/** Повідомлення разом з ЕЦП виборця (підписується канонічний текст повідомлення). */
export type SignedMessage = { readonly text: string; readonly signature: bigint };

/** Зашифроване відкритим ключем ВК повідомлення — до ВК не надходить нічого, крім шифротексту. */
export type Envelope = { readonly cipher: readonly bigint[] };

/** Запис, який ВК публікує після голосування: ID і відповідний підписаний бюлетень. */
export type PublishedBallot = {
  readonly id: string;
  readonly candidateId: string;
  readonly message: string;
  readonly signature: bigint;
};

export type CheckEvent<Check extends string> = {
  readonly check: Check;
  readonly passed: boolean;
  readonly detail: string;
};

export type Observer<Check extends string> = (event: CheckEvent<Check>) => void;

export const REGISTRATION_REFUSALS = {
  NOT_IN_ROLL: "Особи з таким паспортом немає в реєстрі громадян",
  IDENTITY_MISMATCH: "ПІБ не збігається з паспортними даними в реєстрі",
  NO_VOTING_RIGHT: "Особа не має права голосу: на день виборів їй не виповниться 18 років",
  ALREADY_REGISTERED: "Виборець уже зареєстрований і отримав RN — другий RN не видається",
} as const;

export type RegistrationRefusal = keyof typeof REGISTRATION_REFUSALS;

export type RegistrationResult =
  | { readonly status: "registered"; readonly rn: string }
  | { readonly status: "refused"; readonly reason: RegistrationRefusal; readonly message: string };

export const REJECTION_REASONS = {
  UNDECRYPTABLE: "Повідомлення не вдалося розшифрувати або розібрати",
  UNKNOWN_RN: "RN відсутній у списку, отриманому від БР",
  RN_USED: "RN уже використаний для прийнятого бюлетеня",
  BAD_SIGNATURE: "ЕЦП не пройшов перевірку відкритим ключем, закріпленим за цим RN",
  DUPLICATE_ID: "ID уже використаний в іншому прийнятому бюлетені",
  INVALID_BALLOT: "Бюлетень зіпсований: кандидата немає у списку",
} as const;

export type RejectionReason = keyof typeof REJECTION_REASONS;

export type ProcessingResult =
  | { readonly status: "accepted"; readonly id: string; readonly candidateId: string }
  | { readonly status: "rejected"; readonly reason: RejectionReason; readonly message: string };

export type ElectionResults = {
  readonly tally: ReadonlyMap<string, number>;
  readonly ballots: readonly PublishedBallot[];
  readonly rejected: number;
  readonly registered: number;
  readonly leaders: readonly Candidate[];
  readonly isTie: boolean;
};

export type VerificationResult =
  | { readonly status: "confirmed"; readonly id: string }
  | { readonly status: "missing"; readonly id: string }
  | { readonly status: "mismatch"; readonly id: string; readonly expected: string; readonly published: string };

/** Канонічний текст повідомлення виборця — саме він хешується та підписується. */
export function serializeVoteMessage(message: VoteMessage): string {
  return JSON.stringify({ id: message.id, rn: message.rn, candidateId: message.candidateId });
}

export function parseVoteMessage(raw: string): VoteMessage {
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) throw new Error("Невідома структура повідомлення виборця");
  const { id, rn, candidateId } = parsed;
  if (typeof id !== "string" || typeof rn !== "string" || typeof candidateId !== "string") {
    throw new Error("Невідома структура повідомлення виборця");
  }
  return { id, rn, candidateId };
}

/** Канонічний текст списку RN, який підписує БР і розбирає ВК (числа ключів — у hex). */
export function serializeRnList(records: readonly RnRecord[]): string {
  return JSON.stringify(
    records.map(({ rn, publicKey }) => ({ rn, e: publicKey.e.toString(16), n: publicKey.n.toString(16) })),
  );
}

export function parseRnList(raw: string): RnRecord[] {
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("Список RN має бути масивом");
  return parsed.map((item: unknown) => {
    if (!isRecord(item)) throw new Error("Невідома структура запису списку RN");
    const { rn, e, n } = item;
    if (typeof rn !== "string" || typeof e !== "string" || typeof n !== "string") {
      throw new Error("Невідома структура запису списку RN");
    }
    return { rn, publicKey: { e: BigInt(`0x${e}`), n: BigInt(`0x${n}`) } };
  });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
