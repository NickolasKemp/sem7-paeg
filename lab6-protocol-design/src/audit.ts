import { summarize } from "./central-commission.ts";
import { validatePart, type Signed } from "./message.ts";
import { modPow } from "./bigint-math.ts";
import { multiplyCiphers, type PublicKey } from "./rsa.ts";
import {
  DISTRICTS,
  type Batch,
  type BureauKeys,
  type Candidate,
  type District,
  type ElectionResults,
} from "./types.ts";

export const AUDIT_FINDINGS = {
  MIDDLE_MISMATCH: "Частина з публікації ДВК відсутня або змінена в СВК",
  CVK_DROPPED: "Пара частин з публікацій СВК відсутня в результатах",
  PART_MISMATCH: "Частини в рядку ЦВК ≠ опублікованим СВК",
  DECRYPTION_MISMATCH: "mᵉ mod n ≠ C₁ · C₂ mod n — хибне розшифрування",
  TALLY_MISMATCH: "Підсумок ≠ перерахунку прийнятих рядків",
  OVER_REGISTERED: "Бюлетенів на дільниці більше, ніж зареєстрованих",
} as const;
export type AuditFinding = { readonly kind: keyof typeof AUDIT_FINDINGS; readonly detail: string };

/** Усе, що опубліковано: будь-який спостерігач може провести аудит лише за відкритими даними. */
export type Publications = {
  readonly lower: readonly Signed<Batch>[];
  readonly middle: readonly Signed<Batch>[];
  readonly results: ElectionResults;
  readonly registered: Readonly<Record<District, readonly string[]>>;
  readonly candidates: readonly Candidate[];
  readonly bureauKeys: BureauKeys;
  readonly cvkKey: PublicKey;
};

/**
 * Публічний аудит: ланцюжок ДВК → СВК → ЦВК звіряється за опублікованими даними,
 * а розшифрування ЦВК перевіряється відкритим ключем — RSA детермінований, тож mᵉ mod n має дати C.
 */
export function audit(publications: Publications): AuditFinding[] {
  const { lower, middle, results, registered, candidates, bureauKeys, cvkKey } = publications;
  const findings: AuditFinding[] = [];

  const middleParts = middle.flatMap((batch) => batch.body.parts);
  const sameSignedPart = (a: { encryptedPart: bigint; signature: bigint }, b: { encryptedPart: bigint; signature: bigint }) =>
    a.encryptedPart === b.encryptedPart && a.signature === b.signature;

  for (const batch of lower) {
    for (const part of batch.body.parts) {
      if (validatePart(part, bureauKeys, { branch: part.branch }) !== undefined) continue;
      if (!middleParts.some((entry) => sameSignedPart(entry, part))) {
        findings.push({ kind: "MIDDLE_MISMATCH", detail: `${batch.body.from} → СВК-${part.branch}: ID ${part.credential.token.voterId}` });
      }
    }
  }

  const validMiddle = middleParts.filter((part) => validatePart(part, bureauKeys, { branch: part.branch }) === undefined);
  const pairedIds = new Set(
    validMiddle
      .filter((part) => part.branch === 1)
      .map((part) => part.credential.token.voterId)
      .filter((voterId) => validMiddle.some((part) => part.branch === 2 && part.credential.token.voterId === voterId)),
  );

  for (const voterId of pairedIds) {
    const row = results.rows.find((entry) => entry.voterId === voterId);
    if (!row) {
      findings.push({ kind: "CVK_DROPPED", detail: `ID ${voterId}` });
      continue;
    }
    const published = [1, 2].map((branch) => validMiddle.find((part) => part.branch === branch && part.credential.token.voterId === voterId)?.encryptedPart);
    if (row.parts[0] !== published[0] || row.parts[1] !== published[1]) findings.push({ kind: "PART_MISMATCH", detail: `ID ${voterId}` });
  }

  for (const row of results.rows) {
    if (!("ballot" in row) || row.parts[0] === undefined || row.parts[1] === undefined) continue;
    const combined = multiplyCiphers(row.parts[0], row.parts[1], cvkKey);
    if (modPow(row.ballot, cvkKey.e, cvkKey.n) !== combined) {
      findings.push({ kind: "DECRYPTION_MISMATCH", detail: `ID ${row.voterId}: опубліковано ${row.ballot}` });
    }
  }

  const recount = summarize(results.rows, candidates);
  const scopes = [
    ["загальний підсумок", recount.tally, results.tally],
    ...DISTRICTS.map((district) => [`дільниця №${district}`, recount.byDistrict[district], results.byDistrict[district]] as const),
  ] as const;
  for (const [scope, expected, published] of scopes) {
    const differs = candidates.some((candidate) => expected.get(candidate.id) !== published.get(candidate.id));
    if (differs) findings.push({ kind: "TALLY_MISMATCH", detail: scope });
  }

  for (const district of DISTRICTS) {
    const accepted = results.rows.filter((row) => row.status === "accepted" && row.district === district).length;
    if (accepted > registered[district].length) {
      findings.push({ kind: "OVER_REGISTERED", detail: `дільниця №${district}: ${accepted} бюлетенів на ${registered[district].length} зареєстрованих` });
    }
  }

  return findings;
}
