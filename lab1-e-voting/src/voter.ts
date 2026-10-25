import { encrypt, generateKeyPair, sign, type KeyPair, type PublicKey } from "./rsa.ts";
import { serializeBallot, type Ballot, type Envelope, type SignedBallot } from "./types.ts";

/**
 * Виборець: самостійно генерує власну пару ключів RSA для ЕЦП,
 * заповнює бюлетень, підписує його та шифрує відкритим ключем ВК.
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

  /** Крок 2.1–2.3: сформувати бюлетень, захешувати та підписати закритим ключем. */
  fillAndSign(candidateId: string, issuedAt = new Date().toISOString()): SignedBallot {
    const ballot: Ballot = { voterName: this.name, candidateId, issuedAt };
    const text = serializeBallot(ballot);
    return { ballot: text, signature: sign(text, this.keys.privateKey) };
  }

  /** Крок 2.4: запечатати підписаний бюлетень відкритим ключем ВК. */
  seal(signed: SignedBallot, commissionKey: PublicKey): Envelope {
    return { senderName: this.name, cipher: sealFor(signed, commissionKey) };
  }

  /** Повний крок виборця: заповнити → підписати → зашифрувати → надіслати. */
  vote(candidateId: string, commissionKey: PublicKey): Envelope {
    return this.seal(this.fillAndSign(candidateId), commissionKey);
  }
}

/**
 * Шифрування підписаного бюлетеня відкритим ключем ВК.
 * Винесено окремо, бо відкритий ключ ВК доступний будь-кому —
 * цим користуються негативні сценарії з підміною бюлетеня.
 */
export function sealFor(signed: SignedBallot, commissionKey: PublicKey): bigint[] {
  const payload = JSON.stringify({ ballot: signed.ballot, signature: signed.signature.toString(16) });
  return encrypt(payload, commissionKey);
}
