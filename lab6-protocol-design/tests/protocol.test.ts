import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { CorruptBureau, CorruptLowerCommission, CorruptMiddleCommission, type Tamper } from "../src/attacks.ts";
import { audit } from "../src/audit.ts";
import { RegistrationBureau } from "../src/bureau.ts";
import { CentralCommission, summarize } from "../src/central-commission.ts";
import { LowerCommission } from "../src/lower-commission.ts";
import { serialize, type Signed } from "../src/message.ts";
import { MiddleCommission } from "../src/middle-commission.ts";
import { encrypt, generateKeyPair, hashMessage } from "../src/rsa.ts";
import { lowerLabel, type BallotPart, type Batch, type Branch, type Citizen, type District, type LowerLabel } from "../src/types.ts";
import { isCountedCorrectly, isIncluded, splitBallot, Voter } from "../src/voter.ts";

const BITS = 256;

const CITIZENS: readonly Citizen[] = [
  { name: "В1", passport: "П1", birthDate: "1990-01-01", district: 1 },
  { name: "В2", passport: "П2", birthDate: "1990-01-01", district: 1 },
  { name: "В3", passport: "П3", birthDate: "1990-01-01", district: 2 },
  { name: "Неповнолітній", passport: "П4", birthDate: "2010-01-01", district: 2 },
];

type Corruption = { bureau?: true; lower?: Partial<Record<LowerLabel, Tamper>>; middle?: Partial<Record<Branch, Tamper>> };

function election(corruption: Corruption = {}) {
  const options = { citizens: CITIZENS, electionDate: "2026-11-15", bits: BITS };
  const bureau = corruption.bureau ? new CorruptBureau(options) : new RegistrationBureau(options);
  const bureauKeys = bureau.publicKeys;
  const makeLower = (branch: Branch, district: District) => {
    const tamper = corruption.lower?.[lowerLabel(branch, district)];
    const lowerOptions = { branch, district, bureauKeys, bits: BITS };
    return tamper ? new CorruptLowerCommission(lowerOptions, tamper) : new LowerCommission(lowerOptions);
  };
  const lower = { "ДВК-1.1": makeLower(1, 1), "ДВК-1.2": makeLower(1, 2), "ДВК-2.1": makeLower(2, 1), "ДВК-2.2": makeLower(2, 2) };
  const makeMiddle = (branch: Branch) => {
    const tamper = corruption.middle?.[branch];
    const lowerKeys = { 1: lower[lowerLabel(branch, 1)].publicKey, 2: lower[lowerLabel(branch, 2)].publicKey };
    const middleOptions = { branch, lowerKeys, bureauKeys, bits: BITS };
    return tamper ? new CorruptMiddleCommission(middleOptions, tamper) : new MiddleCommission(middleOptions);
  };
  const middle = { 1: makeMiddle(1), 2: makeMiddle(2) };
  const cvk = new CentralCommission({
    candidateNames: ["К1", "К2"],
    bureauKeys,
    middleKeys: { 1: middle[1].publicKey, 2: middle[2].publicKey },
    bits: BITS,
  });

  const voters = CITIZENS.slice(0, 3).map((citizen) => new Voter(citizen, BITS));
  for (const voter of voters) {
    const key = bureau.publicKey(voter.citizen.district);
    voter.completeRegistration(bureau.register(voter.requestRegistration(key)), key);
  }

  const send = (part: BallotPart) => lower[lowerLabel(part.branch, part.credential.district)].receive(part);
  const vote = (voter: Voter, candidateId: bigint) => {
    const receipt = voter.vote(candidateId, cvk.publicKey);
    return { receipt, results: receipt.parts.map(send) };
  };

  const finish = () => {
    const lowerPublications = Object.values(lower).map((commission) => commission.publish());
    for (const publication of lowerPublications) {
      const branch: Branch = publication.body.from.startsWith("ДВК-1") ? 1 : 2;
      middle[branch].collect(publication);
    }
    const middlePublications = [middle[1].publish(), middle[2].publish()];
    const results = cvk.count(middlePublications);
    const findings = audit({
      lower: lowerPublications,
      middle: middlePublications,
      results,
      registered: bureau.publishRegistered(),
      candidates: cvk.candidates,
      bureauKeys,
      cvkKey: cvk.publicKey,
    });
    return { lowerPublications, middlePublications, results, findings };
  };

  return { bureau, lower, middle, cvk, voters, send, vote, finish };
}

const kinds = (findings: readonly { kind: string }[]) => findings.map((finding) => finding.kind);

describe("Поділ бюлетеня", () => {
  test("m₁ · m₂ ≡ m mod n, а RSA(m₁) · RSA(m₂) розшифровується в m", () => {
    const keys = generateKeyPair(BITS);
    const [m1, m2] = splitBallot(102n, keys.publicKey.n);
    assert.equal((m1 * m2) % keys.publicKey.n, 102n);
    assert.notEqual(m1, 102n);
  });
});

describe("БР", () => {
  test("видає мандат зі сліпим ЕЦП, який перевіряється ключем дільниці", () => {
    const { voters, bureau } = election();
    const credential = voters[0]!.credential;
    assert.ok(credential);
    assert.equal(credential.district, 1);
    assert.deepEqual(bureau.publishRegistered()[1], ["В1", "В2"]);
  });

  test("відмовляє неповнолітньому, чужій дільниці та повторній реєстрації", () => {
    const { bureau } = election();
    const request = (citizen: Citizen) => new Voter(citizen, BITS).requestRegistration(bureau.publicKey(citizen.district));
    assert.deepEqual(bureau.register(request(CITIZENS[3]!)), { status: "refused", reason: "NO_VOTING_RIGHT" });
    assert.deepEqual(bureau.register(request({ ...CITIZENS[2]!, district: 1 })), { status: "refused", reason: "WRONG_DISTRICT" });
    assert.deepEqual(bureau.register(request(CITIZENS[0]!)), { status: "refused", reason: "ALREADY_REGISTERED" });
    assert.deepEqual(bureau.register(request({ ...CITIZENS[0]!, name: "Інший" })), { status: "refused", reason: "IDENTITY_MISMATCH" });
  });

  test("не бачить мандата: замаскований хеш не збігається з хешем мандата", () => {
    const { bureau, voters } = election({ bureau: true });
    const registry = (bureau as CorruptBureau).leakRegistry();
    const hashes = voters.map((voter) => hashMessage(serialize(voter.credential!.token), bureau.publicKey(voter.citizen.district).n));
    assert.equal(registry.length, 3);
    assert.ok(registry.every((entry) => !hashes.includes(entry.blindedToken)));
  });
});

describe("ДВК", () => {
  test("приймає дві частини і відхиляє повторне голосування", () => {
    const { voters, vote } = election();
    assert.deepEqual(vote(voters[0]!, 101n).results.map((result) => result.status), ["accepted", "accepted"]);
    assert.deepEqual(vote(voters[0]!, 102n).results.map((result) => result.status === "rejected" && result.reason), ["ALREADY_VOTED", "ALREADY_VOTED"]);
  });

  test("відхиляє мандат без ЕЦП БР, підміну частини і чужий ключ", () => {
    const { voters, cvk, send } = election();
    const [part] = voters[1]!.vote(101n, cvk.publicKey).parts;

    const forgedCredential = { ...part, credential: { ...part.credential, signature: part.credential.signature + 1n } };
    assert.deepEqual(send(forgedCredential), { status: "rejected", reason: "NOT_ELIGIBLE" });
    assert.deepEqual(send({ ...part, encryptedPart: encrypt(102n, cvk.publicKey) }), { status: "rejected", reason: "BAD_SIGNATURE" });
    const thief = new Voter(CITIZENS[1]!, BITS);
    assert.deepEqual(send(thief.signPart({ credential: part.credential, branch: 1, encryptedPart: part.encryptedPart })), { status: "rejected", reason: "BAD_SIGNATURE" });
  });

  test("відхиляє частину іншої гілки або дільниці", () => {
    const { voters, cvk, lower } = election();
    const [first] = voters[0]!.vote(101n, cvk.publicKey).parts;
    assert.deepEqual(lower["ДВК-2.1"].receive(first), { status: "rejected", reason: "WRONG_COMMISSION" });
    assert.deepEqual(lower["ДВК-1.2"].receive(first), { status: "rejected", reason: "WRONG_COMMISSION" });
    const moved = { ...first, credential: { ...first.credential, district: 2 as const } };
    assert.deepEqual(lower["ДВК-1.2"].receive(moved), { status: "rejected", reason: "NOT_ELIGIBLE" });
  });
});

describe("Підрахунок і аудит", () => {
  test("штатне голосування: ЦВК відновлює бюлетені, виборці і аудит не мають зауважень", () => {
    const { voters, vote, finish } = election();
    const receipts = [vote(voters[0]!, 101n), vote(voters[1]!, 102n), vote(voters[2]!, 101n)].map(({ receipt }) => receipt);
    const { results, findings, middlePublications } = finish();
    assert.equal(results.tally.get(101n), 2);
    assert.equal(results.byDistrict[2].get(101n), 1);
    assert.ok(receipts.every((receipt) => isCountedCorrectly(receipt, results)));
    assert.ok(receipts.every((receipt) => middlePublications.every((publication) => isIncluded(receipt, publication))));
    assert.deepEqual(findings, []);
  });

  test("ДВК підміняє частину: СВК відкидає її, скарга виборця відновлює голос", () => {
    let victim = 0n;
    const tamper: Tamper = (parts) => parts.map((part) => (part.credential.token.voterId === victim ? { ...part, encryptedPart: part.encryptedPart + 1n } : part));
    const s = election({ lower: { "ДВК-1.1": tamper } });
    const { receipt } = s.vote(s.voters[0]!, 102n);
    victim = receipt.voterId;
    const publication = s.lower["ДВК-1.1"].publish();
    assert.equal(isIncluded(receipt, publication), false);
    const report = s.middle[1].collect(publication);
    assert.ok(report.status === "accepted" && report.excluded[0]?.reason === "BAD_SIGNATURE");
    assert.equal(s.middle[1].appeal(receipt.parts[0]).status, "accepted");
  });

  test("СВК не може підмінити частину: ЦВК відкидає її, аудит вказує на СВК", () => {
    let victim = 0n;
    const s = election({
      middle: { 2: (parts) => parts.map((part) => (part.credential.token.voterId === victim ? { ...part, encryptedPart: encrypt(101n, s.cvk.publicKey) } : part)) },
    });
    victim = s.vote(s.voters[2]!, 102n).receipt.voterId;
    const { results, findings } = s.finish();
    assert.equal(results.rows[0]?.status === "rejected" && results.rows[0].reason, "MISSING_PART");
    assert.deepEqual(kinds(findings), ["MIDDLE_MISMATCH"]);
  });

  test("ЦВК не може змінити голос непомітно: mᵉ mod n ≠ C₁ · C₂", () => {
    const s = election();
    s.vote(s.voters[0]!, 101n);
    const { lowerPublications, middlePublications, results } = s.finish();
    const rows = results.rows.map((row) => (row.status === "accepted" ? { ...row, ballot: 102n } : row));
    const rigged = { ...results, rows, ...summarize(rows, s.cvk.candidates) };
    const findings = audit({
      lower: lowerPublications,
      middle: middlePublications,
      results: rigged,
      registered: s.bureau.publishRegistered(),
      candidates: s.cvk.candidates,
      bureauKeys: s.bureau.publicKeys,
      cvkKey: s.cvk.publicKey,
    });
    assert.deepEqual(kinds(findings), ["DECRYPTION_MISMATCH"]);
  });

  test("ЦВК відкидає пакет з чужим ЕЦП", () => {
    const s = election();
    s.vote(s.voters[0]!, 101n);
    const { middlePublications } = s.finish();
    const forged: Signed<Batch> = { ...middlePublications[0]!, signature: middlePublications[0]!.signature + 1n };
    const results = s.cvk.count([forged, middlePublications[1]!]);
    assert.deepEqual(results.rejectedBatches, [{ from: "СВК-1", reason: "BAD_BATCH_SIGNATURE" }]);
  });

  test("«мертва душа» від БР виявляється, коли бюлетенів більше, ніж зареєстрованих", () => {
    const s = election({ bureau: true });
    s.vote(s.voters[0]!, 101n);
    s.vote(s.voters[1]!, 101n);
    const ghost = new Voter({ name: "Привид", passport: "—", birthDate: "1900-01-01", district: 1 }, BITS);
    const key = s.bureau.publicKey(1);
    ghost.completeRegistration((s.bureau as CorruptBureau).issueGhost(ghost.requestRegistration(key)), key);
    s.vote(ghost, 102n);
    assert.deepEqual(kinds(s.finish().findings), ["OVER_REGISTERED"]);
  });
});
