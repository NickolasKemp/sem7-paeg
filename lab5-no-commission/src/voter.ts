import { randomInt } from "node:crypto";

import { countVotes, randomRp, sameTally, wrapLayers, type LayerTrace } from "./ballot.ts";
import { decryptLayer, generateKeyPair, sign, verify, type KeyPair, type PublicKey } from "./rsa.ts";
import {
  REJECTIONS,
  ROUNDS,
  serializeSet,
  type Candidate,
  type Failure,
  type IncomingSet,
  type Publication,
  type Rejection,
  type Roster,
  type RosterEntry,
  type SignedSet,
  type Tally,
} from "./types.ts";

export type StepResult =
  | {
      readonly ok: true;
      readonly output: SignedSet;
      /** Учасник, чий ЕЦП перевірено; undefined — набір зібрано від усіх виборців. */
      readonly verifiedSender: string | undefined;
      readonly rp: string;
    }
  | ({ readonly ok: false } & Failure);

export type VerificationResult = { readonly ok: true; readonly tally: Tally } | ({ readonly ok: false } & Failure);

export type BallotTrace = { readonly round: number; readonly layers: readonly LayerTrace[] };

const reject = (reason: Rejection, detail: string = REJECTIONS[reason]) => ({ ok: false, reason, detail }) as const;

/**
 * Виборець — єдиний тип учасника протоколу: він сам генерує ключі, шифрує
 * свій бюлетень, знімає свої шари з усіх бюлетенів, перевіряє RP, перемішує,
 * підписує набір і перевіряє дії попереднього учасника.
 */
export class Voter {
  readonly name: string;
  readonly keys: KeyPair;
  #roster: Roster = [];
  /** RP, згенеровані для кожного раунду шифрування; індекс — номер раунду. */
  readonly #rp: string[] = [];

  constructor(name: string) {
    this.name = name;
    this.keys = generateKeyPair();
  }

  get publicKey(): PublicKey {
    return this.keys.publicKey;
  }

  get roster(): Roster {
    return this.#roster;
  }

  /** Крок 1: виборець зберігає власну копію спільного списку з відкритими ключами. */
  acceptRoster(roster: Roster): void {
    const own = roster.find((entry) => entry.name === this.name);
    if (own?.publicKey.n !== this.publicKey.n || own.publicKey.e !== this.publicKey.e) {
      throw new Error(`${this.name}: у списку немає мене з моїм відкритим ключем`);
    }
    this.#roster = [...roster];
  }

  /** Крок 2: ROUNDS раундів багатошарового шифрування; перед власним шаром — новий RP. */
  castBallot(evp: string, onLayer?: (trace: LayerTrace & { readonly round: number }) => void): string {
    let message = evp;
    for (let round = 0; round < ROUNDS; round += 1) {
      const rp = randomRp();
      this.#rp[round] = rp;
      const ownLayer = (entry: RosterEntry) => (entry.name === this.name ? rp : undefined);
      message = wrapLayers(message, this.#roster, ownLayer, (trace) => onLayer?.({ ...trace, round }));
    }
    return message;
  }

  /** RP, який виборець шукає в раунді розшифрування: раунди знімаються у зворотному порядку. */
  rpFor(decryptionRound: number): string {
    const rp = this.#rp[ROUNDS - 1 - decryptionRound];
    if (rp === undefined) throw new Error(`${this.name}: бюлетень ще не зашифровано`);
    return rp;
  }

  /** Від кого виборець очікує набір: попередній у списку, а для першого — останній з попереднього раунду. */
  expectedSender(decryptionRound: number): RosterEntry | undefined {
    const position = this.#roster.findIndex((entry) => entry.name === this.name);
    if (position > 0) return this.#roster[position - 1];
    if (decryptionRound > 0) return this.#roster.at(-1);
    return undefined;
  }

  /**
   * Кроки 3–4: перевірка відправника та його ЕЦП, кількості бюлетенів, зняття власного шару
   * з усіх бюлетенів, пошук і видалення власного RP, перемішування і підпис набору.
   */
  processSet(incoming: IncomingSet, decryptionRound: number): StepResult {
    const expected = this.expectedSender(decryptionRound);
    if (expected === undefined) {
      if (incoming.kind !== "collected") return reject("UNEXPECTED_SENDER", `очікувалися бюлетені від усіх виборців, а надійшов набір від ${incoming.from}`);
    } else {
      if (incoming.kind !== "signed" || incoming.from !== expected.name) {
        return reject("UNEXPECTED_SENDER", `очікувався набір від ${expected.name}`);
      }
      const signatureValid = verify(serializeSet(incoming.from, incoming.ballots), incoming.signature, expected.publicKey);
      if (!signatureValid) return reject("BAD_SIGNATURE", `ЕЦП набору не відповідає відкритому ключу ${expected.name}`);
    }

    const expectedCount = this.#roster.length;
    if (incoming.ballots.length !== expectedCount) {
      return reject("COUNT_MISMATCH", `отримано бюлетенів: ${incoming.ballots.length}, учасників: ${expectedCount}`);
    }

    const decrypted: string[] = [];
    for (const ballot of incoming.ballots) {
      const opened = decryptLayer(ballot, this.keys.privateKey);
      if (opened === undefined) return reject("BAD_CIPHERTEXT");
      decrypted.push(opened);
    }

    const rp = this.rpFor(decryptionRound);
    const own = decrypted.filter((ballot) => ballot.endsWith(rp));
    if (own.length === 0) return reject("RP_NOT_FOUND", `власний RP з раунду шифрування ${ROUNDS - decryptionRound} відсутній`);
    if (own.length > 1) return reject("RP_DUPLICATE", `власний RP знайдено у ${own.length} бюлетенях — хтось скопіював бюлетень`);

    const stripped = decrypted.map((ballot) => (ballot.endsWith(rp) ? ballot.slice(0, -rp.length) : ballot));
    return { ok: true, output: this.signSet(shuffle(stripped)), verifiedSender: expected?.name, rp };
  }

  signSet(ballots: readonly string[]): SignedSet {
    return { kind: "signed", from: this.name, ballots, signature: sign(serializeSet(this.name, ballots), this.keys.privateKey) };
  }

  /** Крок 5: перевірка опублікованого набору і самостійний повторний підрахунок голосів. */
  verifyPublication(publication: Publication, candidates: readonly Candidate[]): VerificationResult {
    const publisher = this.#roster.at(-1);
    const { set } = publication;
    if (publisher === undefined || set.from !== publisher.name) {
      return reject("UNEXPECTED_SENDER", `результати має публікувати ${publisher?.name}`);
    }
    if (!verify(serializeSet(set.from, set.ballots), set.signature, publisher.publicKey)) {
      return reject("BAD_SIGNATURE", `ЕЦП опублікованого набору не відповідає ключу ${publisher.name}`);
    }
    if (set.ballots.length !== this.#roster.length) {
      return reject("COUNT_MISMATCH", `опубліковано бюлетенів: ${set.ballots.length}, учасників: ${this.#roster.length}`);
    }

    const tally = countVotes(set.ballots, candidates);
    if (!sameTally(tally, publication.announced)) return reject("TALLY_MISMATCH");
    return { ok: true, tally };
  }
}

/** Перемішування Фішера — Єйтса з криптографічно стійким генератором. */
export function shuffle<T>(items: readonly T[]): T[] {
  const result = [...items];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = randomInt(index + 1);
    [result[index], result[other]] = [result[other]!, result[index]!];
  }
  return result;
}
