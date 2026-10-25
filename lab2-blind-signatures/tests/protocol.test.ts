import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { ElectionCommission } from "../src/commission.ts";
import { parseBallot, SET_COUNT, type Candidate } from "../src/types.ts";
import { sealFor, Voter } from "../src/voter.ts";

const BITS = 256;
const UNOPENED = 6;

const CANDIDATES: readonly Candidate[] = [
  { id: "К1", name: "Іваненко Іван Іванович" },
  { id: "К2", name: "Петренко Петро Петрович" },
];

function session(count: number) {
  const commission = new ElectionCommission({ candidates: CANDIDATES, bits: BITS, pickUnopened: () => UNOPENED });
  const voters = Array.from({ length: count }, (_, index) => new Voter(`В${index + 1}`, `АА ${index + 1}`));
  for (const voter of voters) commission.registerVoter(voter.name, voter.document);
  return { commission, voters };
}

function obtain(voter: Voter, commission: ElectionCommission, choicesFor?: (index: number) => readonly string[]) {
  const challenge = commission.requestSigning(voter.prepare(CANDIDATES, commission.publicKey, choicesFor));
  assert.equal(challenge.status, "challenge");
  if (challenge.status !== "challenge") throw new Error("unreachable");
  const result = commission.completeSigning(voter.name, voter.reveal(challenge.reveal));
  if (result.status === "signed") voter.acceptSignatures(result.blindSignatures, commission.publicKey);
  return result;
}

const rejection = (result: { status: string; reason?: string }) => result.status === "rejected" && result.reason;

describe("протокол зі сліпими підписами — позитивні сценарії", () => {
  test("ВК обирає 9 наборів для розкриття, десятий лишається таємним", () => {
    const { commission, voters } = session(1);
    const challenge = commission.requestSigning(voters[0]!.prepare(CANDIDATES, commission.publicKey));
    assert.deepEqual(
      challenge.status === "challenge" && challenge.reveal,
      [...Array(SET_COUNT).keys()].filter((index) => index !== UNOPENED),
    );
  });

  test("5 виборців, 2 кандидати: голоси рахуються, кожен знаходить свій ID", () => {
    const { commission, voters } = session(5);
    const choices = ["К1", "К2", "К1", "К2", "К1"];
    for (const [index, voter] of voters.entries()) {
      assert.equal(obtain(voter, commission).status, "signed");
      assert.equal(commission.receive(voter.vote(choices[index]!, commission.publicKey)).status, "accepted");
    }

    const results = commission.publishResults();
    assert.deepEqual([results.tally.get("К1"), results.tally.get("К2")], [3, 2]);
    assert.equal(results.leaders[0]?.id, "К1");
    assert.ok(voters.every((voter) => voter.checkPublished(results.published) === "counted"));
  });

  test("ВК не знає ID нерозкритого набору, яким виборець голосує", () => {
    const { commission, voters } = session(1);
    obtain(voters[0]!, commission);
    const id = parseBallot(voters[0]!.signed.get("К1")!.ballot).id;

    assert.equal(id, voters[0]!.preparedSets[UNOPENED]!.id);
    assert.equal(commission.knownIds.size, SET_COUNT - 1);
    assert.equal(commission.knownIds.has(id), false);
  });
});

describe("протокол зі сліпими підписами — негативні сценарії підписування", () => {
  test("особа поза списком не отримує підписаний набір", () => {
    const { commission } = session(1);
    const result = commission.requestSigning(new Voter("Стороння", "ВВ 1").prepare(CANDIDATES, commission.publicKey));
    assert.equal(rejection(result), "NOT_IN_LIST");
  });

  test("запит з чужим документом відхиляється", () => {
    const { commission } = session(1);
    const result = commission.requestSigning(new Voter("В1", "ВВ 1").prepare(CANDIDATES, commission.publicKey));
    assert.equal(rejection(result), "IDENTITY_MISMATCH");
  });

  test("повторно отримати підписаний набір неможливо", () => {
    const { commission, voters } = session(1);
    obtain(voters[0]!, commission);
    const again = commission.requestSigning(voters[0]!.prepare(CANDIDATES, commission.publicKey));
    assert.equal(rejection(again), "ALREADY_ISSUED");
  });

  test("запит не з 10 наборів відхиляється", () => {
    const { commission, voters } = session(1);
    const request = voters[0]!.prepare(CANDIDATES, commission.publicKey);
    const result = commission.requestSigning({ ...request, blindedSets: request.blindedSets.slice(1) });
    assert.equal(rejection(result), "MALFORMED_REQUEST");
  });

  test("некоректний набір серед розкритих: відмова, повторний запит також відхиляється", () => {
    const { commission, voters } = session(1);
    const result = obtain(voters[0]!, commission, (index) => (index === 2 ? ["К1", "К1"] : ["К1", "К2"]));

    assert.equal(rejection(result), "BAD_SET");
    assert.equal(commission.voterList[0]?.status, "refused");
    assert.equal(
      rejection(commission.requestSigning(voters[0]!.prepare(CANDIDATES, commission.publicKey))),
      "REFUSED_EARLIER",
    );
  });

  test("некоректний набір, що лишився нерозкритим, проходить — перевірка ймовірнісна", () => {
    const { commission, voters } = session(1);
    const result = obtain(voters[0]!, commission, (index) => (index === UNOPENED ? ["К1", "К1"] : ["К1", "К2"]));
    assert.equal(result.status, "signed");
  });

  test("розкритий бюлетень, що не відповідає замаскованому хешу, викривається", () => {
    const { commission, voters } = session(1);
    const challenge = commission.requestSigning(voters[0]!.prepare(CANDIDATES, commission.publicKey));
    if (challenge.status !== "challenge") throw new Error("очікувався виклик");
    const revealed = voters[0]!.reveal(challenge.reveal).map((set, index) =>
      index === 0 ? { ...set, ballots: [...set.ballots].reverse() } : set,
    );
    assert.equal(rejection(commission.completeSigning(voters[0]!.name, revealed)), "BAD_SET");
  });

  test("розкриття не тих наборів відхиляється", () => {
    const { commission, voters } = session(1);
    const challenge = commission.requestSigning(voters[0]!.prepare(CANDIDATES, commission.publicKey));
    if (challenge.status !== "challenge") throw new Error("очікувався виклик");
    const revealed = voters[0]!.reveal([...Array(SET_COUNT).keys()]);
    assert.equal(rejection(commission.completeSigning(voters[0]!.name, revealed)), "WRONG_REVEAL");
  });
});

describe("протокол зі сліпими підписами — негативні сценарії голосування", () => {
  test("з одного підписаного набору приймається лише перший бюлетень", () => {
    const { commission, voters } = session(1);
    const voter = voters[0]!;
    obtain(voter, commission);

    assert.equal(commission.receive(voter.vote("К1", commission.publicKey)).status, "accepted");
    const second = commission.receive({ cipher: sealFor(voter.signed.get("К2")!, commission.publicKey) });
    assert.equal(rejection(second), "DUPLICATE_ID");
    assert.deepEqual([...commission.publishResults().tally.values()], [1, 0]);
  });

  test("зміна вибору в підписаному бюлетені виявляється перевіркою ЕЦП", () => {
    const { commission, voters } = session(1);
    obtain(voters[0]!, commission);
    const signed = voters[0]!.signed.get("К2")!;
    const tampered = { ballot: signed.ballot.replace('"К2"', '"К1"'), signature: signed.signature };
    assert.equal(rejection(commission.receive({ cipher: sealFor(tampered, commission.publicKey) })), "BAD_SIGNATURE");
  });

  test("бюлетень без підпису ВК відхиляється", () => {
    const { commission } = session(0);
    const forged = { ballot: JSON.stringify({ id: "ffff", candidateId: "К1" }), signature: 12345n };
    assert.equal(rejection(commission.receive({ cipher: sealFor(forged, commission.publicKey) })), "BAD_SIGNATURE");
  });

  test("повідомлення, зашифроване чужим ключем, не розшифровується", () => {
    const { commission, voters } = session(1);
    obtain(voters[0]!, commission);
    const foreign = new ElectionCommission({ candidates: CANDIDATES, bits: BITS });
    assert.equal(rejection(commission.receive(voters[0]!.vote("К1", foreign.publicKey))), "UNDECRYPTABLE");
  });

  test("виборець помічає зміну або зникнення свого бюлетеня в опублікованому списку", () => {
    const { commission, voters } = session(1);
    obtain(voters[0]!, commission);
    commission.receive(voters[0]!.vote("К2", commission.publicKey));
    const { published } = commission.publishResults();

    const altered = published.map((entry) => ({ ...entry, ballot: entry.ballot.replace('"К2"', '"К1"') }));
    assert.equal(voters[0]!.checkPublished(altered), "altered");
    assert.equal(voters[0]!.checkPublished([]), "missing");
  });
});
