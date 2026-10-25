import { randomBigInt } from "./bigint-math.ts";
import { encrypt, generateKeyPair, sign, type KeyPair, type PublicKey } from "./rsa.ts";
import { hidingSplits, type Split } from "./split.ts";
import { serializePart, type BallotPart, type CombinedBallot, type PartMessage } from "./types.ts";

/** Те, що виборець залишає собі, щоб потім перевірити публікації ВК і ЦВК. */
export type Receipt = {
  readonly voterId: bigint;
  readonly candidateId: bigint;
  readonly split: Split;
  readonly encryptedParts: readonly [bigint, bigint];
};

export type Ballot = { readonly messages: readonly [PartMessage, PartMessage]; readonly receipt: Receipt };

const VOTER_ID_MIN = 1n << 63n;
const VOTER_ID_MAX = (1n << 64n) - 1n;

/**
 * Виборець: самостійно генерує ключі ЕЦП і випадковий ID, ділить ID кандидата
 * на два множники, шифрує кожен відкритим ключем ЦВК і підписує обидва повідомлення.
 */
export class Voter {
  readonly name: string;
  readonly keys: KeyPair;

  constructor(name: string, bits = 512) {
    this.name = name;
    this.keys = generateKeyPair(bits);
  }

  get publicKey(): PublicKey {
    return this.keys.publicKey;
  }

  /** Кроки 2–3: поділ ID кандидата, шифрування множників, EDS(RSA(EVP), ID) для кожної ВК. */
  vote(
    candidateId: bigint,
    candidateIds: readonly bigint[],
    cvkKey: PublicKey,
    split: Split = pickSplit(candidateId, candidateIds),
  ): Ballot {
    if (split[0] * split[1] !== candidateId) throw new Error(`${split.join(" · ")} ≠ ${candidateId}`);

    const voterId = randomBigInt(VOTER_ID_MIN, VOTER_ID_MAX);
    const encryptedParts = [encrypt(split[0], cvkKey), encrypt(split[1], cvkKey)] as const;
    const messages = [
      this.signPart({ voterId, encryptedPart: encryptedParts[0] }),
      this.signPart({ voterId, encryptedPart: encryptedParts[1] }),
    ] as const;

    return { messages, receipt: { voterId, candidateId, split, encryptedParts } };
  }

  signPart(part: BallotPart): PartMessage {
    return { senderName: this.name, part: { ...part, signature: sign(serializePart(part), this.keys.privateKey) } };
  }
}

/** Перевірка виборцем, що кожна ВК опублікувала саме ту зашифровану частину, яку він їй надіслав. */
export function checkPublications(
  receipt: Receipt,
  published: readonly [readonly BallotPart[], readonly BallotPart[]],
): readonly [boolean, boolean] {
  const matches = (list: readonly BallotPart[], expected: bigint) =>
    list.some((entry) => entry.voterId === receipt.voterId && entry.encryptedPart === expected);
  return [matches(published[0], receipt.encryptedParts[0]), matches(published[1], receipt.encryptedParts[1])];
}

/** Перевірка виборцем, що ЦВК опублікувала для його ID саме того кандидата, за якого він голосував. */
export function checkResult(receipt: Receipt, ballots: readonly CombinedBallot[]): boolean {
  const own = ballots.find((ballot) => ballot.voterId === receipt.voterId);
  return own?.status === "accepted" && own.ballot === receipt.candidateId;
}

function pickSplit(candidateId: bigint, candidateIds: readonly bigint[]): Split {
  const splits = hidingSplits(candidateId, candidateIds);
  if (splits.length === 0) throw new Error(`ID ${candidateId} не має розкладу, що приховує вибір`);
  return splits[Number(randomBigInt(0n, BigInt(splits.length - 1)))]!;
}
