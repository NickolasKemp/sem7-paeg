import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { assignCandidateIds, CentralCommission } from "../src/central-commission.ts";
import { PartCommission } from "../src/part-commission.ts";
import { encrypt } from "../src/rsa.ts";
import { factorPairs, hidingSplits } from "../src/split.ts";
import type { PartMessage } from "../src/types.ts";
import { checkPublications, checkResult, Voter } from "../src/voter.ts";

const BITS = 256;

function session(count = 3) {
  const cvk = new CentralCommission({ candidateNames: ["К1", "К2"], bits: BITS });
  const voters = Array.from({ length: count }, (_, index) => new Voter(`В${index + 1}`, BITS));
  for (const voter of voters) cvk.registerVoter(voter.name, voter.publicKey);
  const vk = [new PartCommission("ВК-1"), new PartCommission("ВК-2")] as const;
  for (const commission of vk) commission.loadVoterList(cvk.voterList());
  return { cvk, voters, vk };
}

function cast(s: ReturnType<typeof session>, voter: Voter, candidateId: bigint) {
  const ballot = voter.vote(candidateId, s.cvk.candidateIds, s.cvk.publicKey);
  const results = s.vk.map((commission, index) => commission.receive(ballot.messages[index]!));
  return { ballot, results };
}

describe("Поділ ID кандидата", () => {
  test("ЦВК видає ID 24 і 36, кожен має розклад, що не видає вибір", () => {
    const ids = assignCandidateIds(["К1", "К2"]).map((candidate) => candidate.id);
    assert.deepEqual(ids, [24n, 36n]);
    assert.deepEqual(hidingSplits(36n, ids), [[3n, 12n], [6n, 6n], [12n, 3n]]);
  });

  test("розклади, що видають вибір, відкидаються", () => {
    assert.ok(factorPairs(24n).some(([a, b]) => a === 3n && b === 8n));
    assert.ok(!hidingSplits(24n, [24n, 36n]).some(([a, b]) => a === 3n && b === 8n));
  });

  test("виборець ділить ID на множники, добуток яких дорівнює ID", () => {
    const { cvk, voters } = session(1);
    const { receipt } = voters[0]!.vote(24n, cvk.candidateIds, cvk.publicKey);
    assert.equal(receipt.split[0] * receipt.split[1], 24n);
  });
});

describe("ВК-1 та ВК-2", () => {
  test("приймають коректні повідомлення і публікують частини з однаковим ID виборця", () => {
    const s = session(1);
    const { ballot, results } = cast(s, s.voters[0]!, 24n);
    assert.deepEqual(results.map((result) => result.status), ["accepted", "accepted"]);
    const [first, second] = s.vk.map((commission) => commission.publish());
    assert.equal(first?.[0]?.voterId, ballot.receipt.voterId);
    assert.equal(second?.[0]?.voterId, ballot.receipt.voterId);
  });

  test("відхиляють незареєстрованого виборця", () => {
    const s = session(1);
    const stranger = new Voter("Стороння", BITS);
    const message = stranger.vote(24n, s.cvk.candidateIds, s.cvk.publicKey).messages[0];
    assert.deepEqual(s.vk[0].receive(message), { status: "rejected", voterName: "Стороння", reason: "NOT_IN_LIST" });
  });

  test("відхиляють повідомлення з підміненою частиною або чужим ЕЦП", () => {
    const s = session(2);
    const [message] = s.voters[0]!.vote(24n, s.cvk.candidateIds, s.cvk.publicKey).messages;
    const tampered: PartMessage = { ...message, part: { ...message.part, encryptedPart: encrypt(5n, s.cvk.publicKey) } };
    const foreign: PartMessage = { ...s.voters[1]!.vote(24n, s.cvk.candidateIds, s.cvk.publicKey).messages[0], senderName: "В1" };
    assert.equal(s.vk[0].receive(tampered).status, "rejected");
    assert.equal(s.vk[0].receive(foreign).status, "rejected");
    assert.equal(s.vk[0].receive(message).status, "accepted");
  });

  test("відхиляють повторне повідомлення від того самого виборця", () => {
    const s = session(1);
    cast(s, s.voters[0]!, 24n);
    const { results } = cast(s, s.voters[0]!, 36n);
    assert.deepEqual(results.map((result) => result.status === "rejected" && result.reason), ["ALREADY_VOTED", "ALREADY_VOTED"]);
  });
});

describe("ЦВК", () => {
  test("об'єднує частини до розшифрування, відновлює ID кандидатів і рахує голоси", () => {
    const s = session(3);
    const choices = [24n, 36n, 24n];
    s.voters.forEach((voter, index) => cast(s, voter, choices[index]!));
    const ballots = s.cvk.combine(s.vk[0].publish(), s.vk[1].publish());
    const results = s.cvk.tally(ballots);
    assert.deepEqual(ballots.map((ballot) => ballot.status === "accepted" && ballot.ballot), choices);
    assert.deepEqual([...results.tally], [[24n, 2], [36n, 1]]);
    assert.equal(results.leaders[0]?.id, 24n);
  });

  test("відкидає бюлетень, якщо ВК змінила свою частину і вийшов не ID кандидата", () => {
    const s = session(1);
    const { ballot } = cast(s, s.voters[0]!, 36n);
    const forged = s.vk[0].publish().map((entry) => ({ ...entry, encryptedPart: encrypt(5n, s.cvk.publicKey) }));
    const [combined] = s.cvk.combine(forged, s.vk[1].publish());
    assert.equal(combined?.status, "rejected");
    assert.equal(combined?.status === "rejected" && combined.reason, "NOT_A_CANDIDATE");
    assert.deepEqual(checkPublications(ballot.receipt, [forged, s.vk[1].publish()]), [false, true]);
  });

  test("відкидає ID, для якого опубліковано лише одну частину", () => {
    const s = session(1);
    cast(s, s.voters[0]!, 24n);
    const [combined] = s.cvk.combine(s.vk[0].publish(), []);
    assert.equal(combined?.status === "rejected" && combined.reason, "MISSING_PART");
  });
});

describe("Перевірки виборця", () => {
  test("чесні публікації ВК і ЦВК збігаються з квитанцією", () => {
    const s = session(1);
    const { ballot } = cast(s, s.voters[0]!, 24n);
    const published = [s.vk[0].publish(), s.vk[1].publish()] as const;
    assert.deepEqual(checkPublications(ballot.receipt, published), [true, true]);
    assert.equal(checkResult(ballot.receipt, s.cvk.combine(...published)), true);
  });

  test("підміна бюлетеня на боці ЦВК виявляється виборцем", () => {
    const s = session(1);
    const { ballot } = cast(s, s.voters[0]!, 24n);
    const ballots = s.cvk
      .combine(s.vk[0].publish(), s.vk[1].publish())
      .map((entry) => (entry.status === "accepted" ? { ...entry, ballot: 36n } : entry));
    assert.equal(checkResult(ballot.receipt, ballots), false);
  });
});
