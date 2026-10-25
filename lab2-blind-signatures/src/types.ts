/** Кількість наборів бюлетенів, які виборець надсилає на сліпий підпис. */
export const SET_COUNT = 10;

export type Candidate = { readonly id: string; readonly name: string };

/** Бюлетень: лише випадковий ID набору та вибір — жодних персональних даних. */
export type Ballot = { readonly id: string; readonly candidateId: string };

/** Набір замаскованих хешів: по одному на кожен бюлетень набору. */
export type BlindedSet = readonly bigint[];

/** Крок 5: запит виборця на сліпий підпис (особа + 10 наборів замаскованих хешів). */
export type SigningRequest = {
  readonly voterName: string;
  readonly document: string;
  readonly blindedSets: readonly BlindedSet[];
};

/** Крок 7: розкритий набір — початкові бюлетені та множники маскування. */
export type RevealedSet = {
  readonly index: number;
  readonly ballots: readonly string[];
  readonly factors: readonly bigint[];
};

/** Бюлетень разом із дійсним (уже розмаскованим) підписом ВК. */
export type SignedBallot = { readonly ballot: string; readonly signature: bigint };

/** Крок 12: анонімне повідомлення до ВК — лише шифротекст. */
export type Envelope = { readonly cipher: readonly bigint[] };

export type VoterRecord = {
  readonly name: string;
  readonly document: string;
  status: "registered" | "issued" | "refused";
};

export const SIGNING_REJECTIONS = {
  NOT_IN_LIST: "Особи немає у списку виборців",
  IDENTITY_MISMATCH: "Документ не відповідає особі зі списку виборців",
  ALREADY_ISSUED: "Виборець уже отримав підписаний набір бюлетенів",
  REFUSED_EARLIER: "Виборцю раніше відмовлено через некоректний набір",
  MALFORMED_REQUEST: "Запит не містить 10 наборів з бюлетенем для кожного кандидата",
  NO_PENDING_REQUEST: "Немає запиту на підпис, що очікує розкриття",
  WRONG_REVEAL: "Розкрито не ті набори, які обрала ВК",
  BAD_SET: "Некоректний розкритий набір",
} as const;

export const VOTE_REJECTIONS = {
  UNDECRYPTABLE: "Повідомлення не вдалося розшифрувати або розібрати",
  BAD_SIGNATURE: "ЕЦП ВК не пройшов перевірку",
  INVALID_BALLOT: "Бюлетень зіпсований: кандидата немає у списку",
  DUPLICATE_ID: "Бюлетень з таким ID уже прийнято",
} as const;

export type SigningRejection = keyof typeof SIGNING_REJECTIONS;
export type VoteRejection = keyof typeof VOTE_REJECTIONS;

export type Rejected<Reason> = { readonly status: "rejected"; readonly reason: Reason; readonly message: string };

export type ChallengeResult = { readonly status: "challenge"; readonly reveal: readonly number[] } | Rejected<SigningRejection>;
export type SigningResult = { readonly status: "signed"; readonly blindSignatures: readonly bigint[] } | Rejected<SigningRejection>;
export type VoteResult = { readonly status: "accepted"; readonly ballot: Ballot } | Rejected<VoteRejection>;

/** Запис на дошці оголошень: ID, вибір і підписаний бюлетень. */
export type PublishedBallot = Ballot & SignedBallot;

export type ElectionResults = {
  readonly tally: ReadonlyMap<string, number>;
  readonly published: readonly PublishedBallot[];
  readonly accepted: number;
  readonly rejected: number;
  readonly leaders: readonly Candidate[];
  readonly isTie: boolean;
};

/** Канонічний текст бюлетеня — саме він хешується та підписується. */
export function serializeBallot(ballot: Ballot): string {
  return JSON.stringify({ id: ballot.id, candidateId: ballot.candidateId });
}

/** Строгий розбір: рівно два рядкові поля, без зайвих даних. */
export function parseBallot(raw: string): Ballot {
  const parsed: unknown = JSON.parse(raw);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Object.keys(parsed).length !== 2 ||
    typeof (parsed as Ballot).id !== "string" ||
    typeof (parsed as Ballot).candidateId !== "string"
  ) {
    throw new Error("Невідома структура бюлетеня");
  }
  return parsed as Ballot;
}
