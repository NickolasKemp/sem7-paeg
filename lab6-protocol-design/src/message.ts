import { sign, verify, type PrivateKey, type PublicKey } from "./rsa.ts";
import { partPayload, type BallotPart, type BureauKeys, type Branch, type District, type PartRejection } from "./types.ts";

/** Будь-які дані разом з ЕЦП сторони, яка їх надіслала або опублікувала. */
export type Signed<T> = { readonly body: T; readonly signature: bigint };

/** Канонічний текст повідомлення — саме він хешується та підписується. */
export function serialize(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => (typeof item === "bigint" ? item.toString(16) : item));
}

export function signBody<T>(body: T, key: PrivateKey): Signed<T> {
  return { body, signature: sign(serialize(body), key) };
}

export function verifyBody<T>(signed: Signed<T>, key: PublicKey): boolean {
  return verify(serialize(signed.body), signed.signature, key);
}

export type PartCheck = "commission" | "eligibility" | "signature";
type Note = (check: PartCheck, passed: boolean, detail: string) => void;

/**
 * Перевірки частини бюлетеня, які повторює кожен рівень (ДВК, СВК, ЦВК), не довіряючи нижчому:
 * адреса (гілка і дільниця), сліпий ЕЦП БР на мандаті, ЕЦП виборця ключем з мандата.
 */
export function validatePart(
  part: BallotPart,
  bureauKeys: BureauKeys,
  expected: { readonly branch: Branch; readonly district?: District },
  note: Note = () => {},
): PartRejection | undefined {
  const { credential } = part;

  const addressed = part.branch === expected.branch && (expected.district ?? credential.district) === credential.district;
  note(
    "commission",
    addressed,
    addressed
      ? `частина ${part.branch}, дільниця №${credential.district}`
      : `частина ${part.branch} дільниці №${credential.district} надійшла не за адресою`,
  );
  if (!addressed) return "WRONG_COMMISSION";

  const eligible = verify(serialize(credential.token), credential.signature, bureauKeys[credential.district]);
  note("eligibility", eligible, eligible ? "Sᵉ mod n = H(мандат) — сліпий ЕЦП БР справжній" : "Sᵉ mod n ≠ H(мандат)");
  if (!eligible) return "NOT_ELIGIBLE";

  const authentic = verify(serialize(partPayload(part)), part.signature, credential.token.publicKey);
  note("signature", authentic, authentic ? "H = H_c — частину підписав власник мандата" : "H ≠ H_c — ЕЦП частини недійсний");
  if (!authentic) return "BAD_SIGNATURE";

  return undefined;
}
