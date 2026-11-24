import assert from "node:assert/strict";
import { test } from "node:test";

import { fabricateBallot, findByLength, forgeWithWrongRp, peekTally } from "../src/attacks.ts";
import { formBallot } from "../src/ballot.ts";
import { castBallots, mix, publish, registerVoters, rosterFingerprint, type Hop, type Tamper } from "../src/election.ts";
import { generateKeyPair, sign } from "../src/rsa.ts";
import { serializeSet, type Candidate, type Rejection } from "../src/types.ts";
import type { Voter } from "../src/voter.ts";

const CANDIDATES: readonly Candidate[] = [
  { id: 1, name: "Олена Петренко" },
  { id: 2, name: "Іван Коваленко" },
];
const [FIRST, SECOND] = CANDIDATES as readonly [Candidate, Candidate];
const CHOICES = [FIRST, SECOND, FIRST, SECOND, FIRST];
const voters = registerVoters(["A", "B", "C", "D", "E"]);
const [A, B, C, D] = voters as [Voter, Voter, Voter, Voter, Voter];

const run = (tamper?: Tamper) => mix(voters, castBallots(voters, CHOICES, CANDIDATES), { tamper });
const isPass = (hop: Hop, from: string, round: number) => hop.kind === "pass" && hop.from === from && hop.round === round;

function assertDetected(tamper: Tamper, voter: string, reason: Rejection): void {
  const outcome = run(tamper);
  assert.equal(outcome.status, "aborted");
  if (outcome.status !== "aborted") return;
  assert.equal(outcome.voter, voter);
  assert.equal(outcome.failure.reason, reason);
}

test("усі виборці мають однакову копію списку з відкритими ключами", () => {
  assert.equal(new Set(voters.map((voter) => rosterFingerprint(voter.roster))).size, 1);
});

test("чесний прогін: 10 етапів, початкові бюлетені, однаковий підрахунок у всіх", () => {
  const outcome = run();
  assert.equal(outcome.status, "completed");
  if (outcome.status !== "completed") return;
  assert.equal(outcome.steps.length, 10);
  assert.deepEqual(
    [...outcome.final.ballots].sort(),
    CHOICES.map((choice) => formBallot(choice, CANDIDATES)).sort(),
  );

  const publication = publish(outcome.final, CANDIDATES);
  assert.deepEqual([...publication.announced.votes], [[1, 3], [2, 2]]);
  for (const voter of voters) assert.ok(voter.verifyPublication(publication, CANDIDATES).ok);
});

test("додавання бюлетеня виявляє перший виборець", () => {
  assertDetected(
    (hop, set) => (hop.kind === "collect" ? { ...set, ballots: [...set.ballots, fabricateBallot("x", A.roster)] } : set),
    "A",
    "COUNT_MISMATCH",
  );
});

test("видалення бюлетеня з чесним підписом виявляє наступний виборець", () => {
  assertDetected((hop, set) => (isPass(hop, "C", 0) ? C.signSet(set.ballots.slice(1)) : set), "D", "COUNT_MISMATCH");
});

test("зміна набору в каналі та підпис чужим ключем дають BAD_SIGNATURE", () => {
  const swap = (ballots: readonly string[]) => [...ballots].reverse();
  assertDetected((hop, set) => (isPass(hop, "B", 0) ? { ...set, ballots: swap(set.ballots) } : set), "C", "BAD_SIGNATURE");

  const mallory = generateKeyPair();
  assertDetected(
    (hop, set) =>
      isPass(hop, "B", 0) ? { kind: "signed", from: "B", ballots: swap(set.ballots), signature: sign(serializeSet("B", swap(set.ballots)), mallory.privateKey) } : set,
    "C",
    "BAD_SIGNATURE",
  );
});

test("набір не від попереднього учасника відхиляється", () => {
  assertDetected((hop, set) => (isPass(hop, "B", 0) ? A.signSet(set.ballots) : set), "C", "UNEXPECTED_SENDER");
});

test("замінений бюлетень без RP виявляє його власник у першому раунді", () => {
  const fake = fabricateBallot(formBallot(FIRST, CANDIDATES), A.roster);
  assertDetected(
    (hop, set) => (hop.kind === "collect" ? { ...set, ballots: set.ballots.map((ballot, index) => (index === 3 ? fake : ballot)) } : set),
    "D",
    "RP_NOT_FOUND",
  );
});

test("бюлетень з неправильним RP виявляє його власник у другому раунді", () => {
  assertDetected(
    (hop, set) => {
      if (!isPass(hop, "B", 1)) return set;
      const fake = forgeWithWrongRp(formBallot(SECOND, CANDIDATES), B.roster.slice(2), "C");
      const target = findByLength(set.ballots, fake.length);
      return B.signSet(set.ballots.map((ballot, index) => (index === target ? fake : ballot)));
    },
    "C",
    "RP_NOT_FOUND",
  );
});

test("копія чужого бюлетеня виявляється як повторний RP", () => {
  assertDetected(
    (hop, set) => (hop.kind === "collect" ? { ...set, ballots: set.ballots.map((ballot, index) => (index === 3 ? set.ballots[1]! : ballot)) } : set),
    "B",
    "RP_DUPLICATE",
  );
});

test("відмова учасника зупиняє протокол", () => {
  assertDetected((hop, set) => (isPass(hop, "C", 0) ? undefined : set), "D", "NOT_RECEIVED");
});

test("хибний оголошений підсумок і підмінений опублікований набір виявляє кожен", () => {
  const outcome = run();
  assert.equal(outcome.status, "completed");
  if (outcome.status !== "completed") return;
  const publication = publish(outcome.final, CANDIDATES);

  const wrongTally = { ...publication, announced: { votes: new Map([[1, 2], [2, 3]]), invalid: 0 } };
  for (const voter of voters) assert.equal(voter.verifyPublication(wrongTally, CANDIDATES).ok, false);

  const tampered = { ...publication, set: { ...publication.set, ballots: publication.set.ballots.slice(1) } };
  const result = D.verifyPublication(tampered, CANDIDATES);
  assert.ok(!result.ok && result.reason === "BAD_SIGNATURE");
});

test("після свого кроку в другому раунді D розпізнає голоси A–D", () => {
  const outcome = run();
  assert.equal(outcome.status, "completed");
  const stepOfD = outcome.steps.find((record) => record.round === 1 && record.voter === "D");
  assert.ok(stepOfD);
  const seen = peekTally(stepOfD.output.ballots, D.roster.slice(-1), CANDIDATES);
  assert.deepEqual([...seen], [[1, 2], [2, 2]]);
});
