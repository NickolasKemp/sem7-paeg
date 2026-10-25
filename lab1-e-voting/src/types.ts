import type { PublicKey } from "./rsa.ts";

export type Candidate = { readonly id: string; readonly name: string };

/** Вміст бюлетеня, який заповнює виборець. */
export type Ballot = {
  readonly voterName: string;
  readonly candidateId: string;
  readonly issuedAt: string;
};

/** Бюлетень разом із ЕЦП виборця (підписується канонічний текст бюлетеня). */
export type SignedBallot = { readonly ballot: string; readonly signature: bigint };

/**
 * Те, що реально надходить до ВК: ПІБ відправника у відкритому вигляді
 * (ВК має знати, чий бюлетень вона розшифровує) і блоки шифротексту.
 */
export type Envelope = { readonly senderName: string; readonly cipher: readonly bigint[] };

export type RegisteredVoter = {
  readonly name: string;
  readonly publicKey: PublicKey;
  hasVoted: boolean;
};

export const REJECTION_REASONS = {
  UNDECRYPTABLE: "Повідомлення не вдалося розшифрувати або розібрати",
  NOT_IN_LIST: "Відправника немає у списку допущених виборців",
  BAD_SIGNATURE: "ЕЦП не пройшов перевірку відкритим ключем виборця",
  IDENTITY_MISMATCH: "ПІБ у бюлетені не збігається з ПІБ відправника",
  ALREADY_VOTED: "Виборець уже проголосував",
  INVALID_BALLOT: "Бюлетень зіпсований: кандидата немає у списку",
} as const;

export type RejectionReason = keyof typeof REJECTION_REASONS;

export type ProcessingResult =
  | { readonly status: "accepted"; readonly voterName: string; readonly candidateId: string }
  | {
      readonly status: "rejected";
      readonly voterName: string;
      readonly reason: RejectionReason;
      readonly message: string;
    };

export type ElectionResults = {
  readonly tally: ReadonlyMap<string, number>;
  readonly accepted: number;
  readonly rejected: number;
  readonly turnout: { readonly voted: number; readonly registered: number };
  readonly leaders: readonly Candidate[];
  readonly isTie: boolean;
};

/** Канонічний текст бюлетеня — саме він хешується та підписується. */
export function serializeBallot(ballot: Ballot): string {
  return JSON.stringify({
    voterName: ballot.voterName,
    candidateId: ballot.candidateId,
    issuedAt: ballot.issuedAt,
  });
}

export function parseBallot(raw: string): Ballot {
  const parsed: unknown = JSON.parse(raw);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as Ballot).voterName !== "string" ||
    typeof (parsed as Ballot).candidateId !== "string" ||
    typeof (parsed as Ballot).issuedAt !== "string"
  ) {
    throw new Error("Невідома структура бюлетеня");
  }
  return parsed as Ballot;
}
