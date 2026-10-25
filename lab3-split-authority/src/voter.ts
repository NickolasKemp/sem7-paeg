import { randomBigInt } from "./bigint-math.ts";
import { encrypt, generateKeyPair, sign, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  serializeVoteMessage,
  type Envelope,
  type PublishedBallot,
  type RegistrationRequest,
  type SignedMessage,
  type VerificationResult,
} from "./types.ts";

/** ID із 16 десяткових цифр: імовірність збігу у двох виборців мізерна. */
const ID_MIN = 10n ** 15n;
const ID_MAX = 10n ** 16n - 1n;

export const generateId = (): string => randomBigInt(ID_MIN, ID_MAX).toString();

/**
 * Виборець: сам генерує пару ключів RSA для ЕЦП, реєструється в БР і отримує RN,
 * сам генерує випадковий ID, підписує повідомлення (ID; RN; бюлетень), шифрує його
 * відкритим ключем ВК, а після публікації результатів перевіряє свій голос.
 */
export class Voter {
  readonly name: string;
  readonly passport: string;
  readonly keys: KeyPair;

  #rn: string | undefined;
  #cast: { readonly id: string; readonly candidateId: string; readonly text: string } | undefined;

  constructor(name: string, passport: string, bits = 512) {
    this.name = name;
    this.passport = passport;
    this.keys = generateKeyPair(bits);
  }

  get publicKey(): PublicKey {
    return this.keys.publicKey;
  }

  /** Крок 1: звернення до БР з особою та власним відкритим ключем ЕЦП. */
  registrationRequest(): RegistrationRequest {
    return { name: this.name, passport: this.passport, publicKey: this.publicKey };
  }

  acceptRn(rn: string): void {
    this.#rn = rn;
  }

  get rn(): string {
    if (this.#rn === undefined) throw new Error(`«${this.name}» ще не отримав RN`);
    return this.#rn;
  }

  /** ID, з яким виборець голосував, — за ним він шукає свій бюлетень у публікації ВК. */
  get castId(): string {
    if (!this.#cast) throw new Error(`«${this.name}» ще не голосував`);
    return this.#cast.id;
  }

  /** Крок 4: сформувати повідомлення (ID; RN; бюлетень) і підписати його закритим ключем. */
  prepare(candidateId: string, id = generateId()): SignedMessage {
    const text = serializeVoteMessage({ id, rn: this.rn, candidateId });
    return { text, signature: sign(text, this.keys.privateKey) };
  }

  /** Повний крок виборця: сформувати → підписати → зашифрувати ключем ВК; виборець запам’ятовує свій ID і вибір. */
  vote(candidateId: string, commissionKey: PublicKey): { signed: SignedMessage; envelope: Envelope } {
    const id = generateId();
    const signed = this.prepare(candidateId, id);
    this.#cast = { id, candidateId, text: signed.text };
    return { signed, envelope: sealFor(signed, commissionKey) };
  }

  /** Після публікації: знайти власний ID і переконатися, що бюлетень врахований без змін. */
  verifyPublication(ballots: readonly PublishedBallot[]): VerificationResult {
    if (!this.#cast) throw new Error(`«${this.name}» ще не голосував`);
    const { id, candidateId, text } = this.#cast;

    const published = ballots.find((ballot) => ballot.id === id);
    if (!published) return { status: "missing", id };
    if (published.candidateId !== candidateId || published.message !== text) {
      return { status: "mismatch", id, expected: candidateId, published: published.candidateId };
    }
    return { status: "confirmed", id };
  }
}

/**
 * Шифрування підписаного повідомлення разом з ЕЦП відкритим ключем ВК.
 * Винесено окремо, бо відкритий ключ ВК доступний будь-кому —
 * цим користуються негативні сценарії з підміною повідомлення.
 */
export function sealFor(signed: SignedMessage, commissionKey: PublicKey): Envelope {
  const payload = JSON.stringify({ text: signed.text, signature: signed.signature.toString(16) });
  return { cipher: encrypt(payload, commissionKey) };
}
