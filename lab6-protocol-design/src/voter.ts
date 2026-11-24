import { blind, randomBlindingFactor, unblind } from "./blind-signature.ts";
import { modInverse, randomBigInt } from "./bigint-math.ts";
import { serialize, type Signed } from "./message.ts";
import { encrypt, generateKeyPair, hashMessage, sign, verify, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  partPayload,
  type BallotPart,
  type Batch,
  type Branch,
  type Citizen,
  type Credential,
  type ElectionResults,
  type RegistrationRequest,
  type RegistrationResult,
  type Token,
} from "./types.ts";

const VOTER_ID_MIN = 1n << 63n;
const VOTER_ID_MAX = (1n << 64n) - 1n;

/**
 * Поділ бюлетеня на дві частини в мультиплікативній групі за модулем n ключа ЦВК:
 * m₁ — випадкове, m₂ = m · m₁⁻¹ mod n, тож m₁ · m₂ ≡ m. Кожна частина окремо рівномірно випадкова
 * і не несе жодної інформації про вибір, а RSA(m₁) · RSA(m₂) = RSA(m) mod n.
 */
export function splitBallot(candidateId: bigint, n: bigint): readonly [bigint, bigint] {
  const first = randomBlindingFactor(n);
  return [first, (candidateId * modInverse(first, n)) % n];
}

/** Що виборець зберігає після голосування: вибір і обидві підписані частини (вони ж — доказ для скарги). */
export type Receipt = {
  readonly voterId: bigint;
  readonly candidateId: bigint;
  readonly split: readonly [bigint, bigint];
  readonly parts: readonly [BallotPart, BallotPart];
};

/**
 * Виборець: генерує псевдонімну пару ключів ЕЦП і випадковий ID (мандат), отримує на мандат
 * сліпий ЕЦП БР, ділить бюлетень на дві частини, шифрує їх ключем ЦВК і підписує ключем мандата.
 */
export class Voter {
  readonly citizen: Citizen;

  readonly #pseudonym: KeyPair;
  readonly #token: Token;
  #blinding: bigint | undefined;
  #credential: Credential | undefined;

  constructor(citizen: Citizen, bits = 512) {
    this.citizen = citizen;
    this.#pseudonym = generateKeyPair(bits);
    this.#token = { voterId: randomBigInt(VOTER_ID_MIN, VOTER_ID_MAX), publicKey: this.#pseudonym.publicKey };
  }

  get name(): string {
    return this.citizen.name;
  }

  get credential(): Credential | undefined {
    return this.#credential;
  }

  /** Маскування хешу мандата: H' = H · rᵉ mod n (ключ БР для своєї дільниці). */
  requestRegistration(bureauKey: PublicKey): RegistrationRequest {
    this.#blinding = randomBlindingFactor(bureauKey.n);
    const hash = hashMessage(serialize(this.#token), bureauKey.n);
    return {
      name: this.citizen.name,
      passport: this.citizen.passport,
      district: this.citizen.district,
      blindedToken: blind(hash, this.#blinding, bureauKey),
    };
  }

  /** Зняття маски S = S' · r⁻¹ mod n і перевірка, що отримано справжній ЕЦП БР на мандаті. */
  completeRegistration(result: RegistrationResult, bureauKey: PublicKey): boolean {
    if (result.status !== "registered" || this.#blinding === undefined) return false;
    const signature = unblind(result.blindSignature, this.#blinding, bureauKey);
    const valid = verify(serialize(this.#token), signature, bureauKey);
    if (valid) this.#credential = { token: this.#token, district: this.citizen.district, signature };
    return valid;
  }

  vote(candidateId: bigint, cvkKey: PublicKey): Receipt {
    const credential = this.#credential;
    if (!credential) throw new Error(`«${this.name}» не має мандата`);

    const split = splitBallot(candidateId, cvkKey.n);
    const part = (branch: Branch, value: bigint) => this.signPart({ credential, branch, encryptedPart: encrypt(value, cvkKey) });
    return { voterId: credential.token.voterId, candidateId, split, parts: [part(1, split[0]), part(2, split[1])] };
  }

  signPart(unsigned: Omit<BallotPart, "signature">): BallotPart {
    return { ...unsigned, signature: sign(serialize(partPayload(unsigned)), this.#pseudonym.privateKey) };
  }
}

/** Виборець шукає у підписаній публікації комісії свою частину бюлетеня. */
export function isIncluded(receipt: Receipt, publication: Signed<Batch>): boolean {
  return publication.body.parts.some((part) =>
    receipt.parts.some((own) => own.branch === part.branch && own.encryptedPart === part.encryptedPart && own.signature === part.signature),
  );
}

/** Виборець перевіряє, що ЦВК опублікувала для його ID саме того кандидата, за якого він голосував. */
export function isCountedCorrectly(receipt: Receipt, results: ElectionResults): boolean {
  const row = results.rows.find((entry) => entry.voterId === receipt.voterId);
  return row?.status === "accepted" && row.ballot === receipt.candidateId;
}
