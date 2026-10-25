import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { ElectionCommission } from "../src/commission.ts";
import { serializeBallot, type Candidate } from "../src/types.ts";
import { sealFor, Voter } from "../src/voter.ts";

const BITS = 256;

const CANDIDATES: readonly Candidate[] = [
  { id: "К1", name: "Іваненко Іван Іванович" },
  { id: "К2", name: "Петренко Петро Петрович" },
];

function session(names: readonly string[]) {
  const commission = new ElectionCommission({ candidates: CANDIDATES, bits: BITS });
  const voters = names.map((name) => new Voter(name, BITS));
  for (const voter of voters) commission.registerVoter(voter.name, voter.publicKey);
  return { commission, voters };
}

describe("простий протокол Е-голосування — позитивні сценарії", () => {
  test("коректний бюлетень приймається і фіксується факт голосування", () => {
    const { commission, voters } = session(["Виборець 1"]);
    const result = commission.receive(voters[0]!.vote("К1", commission.publicKey));

    assert.equal(result.status, "accepted");
    assert.equal(commission.voterList[0]?.hasVoted, true);
    assert.equal(commission.publishResults().tally.get("К1"), 1);
  });

  test("5 виборців і 2 кандидати: голоси рахуються, переможець визначається", () => {
    const names = ["В1", "В2", "В3", "В4", "В5"];
    const { commission, voters } = session(names);
    const choices = ["К1", "К2", "К1", "К2", "К1"];

    voters.forEach((voter, index) => {
      assert.equal(commission.receive(voter.vote(choices[index]!, commission.publicKey)).status, "accepted");
    });

    const results = commission.publishResults();
    assert.deepEqual([results.tally.get("К1"), results.tally.get("К2")], [3, 2]);
    assert.equal(results.isTie, false);
    assert.equal(results.leaders[0]?.id, "К1");
    assert.deepEqual(results.turnout, { voted: 5, registered: 5 });
  });

  test("рівний розподіл голосів визначається як нічия", () => {
    const { commission, voters } = session(["В1", "В2", "В3", "В4"]);
    const choices = ["К1", "К2", "К1", "К2"];
    voters.forEach((voter, index) => commission.receive(voter.vote(choices[index]!, commission.publicKey)));

    const results = commission.publishResults();
    assert.equal(results.isTie, true);
    assert.deepEqual(results.leaders.map((candidate) => candidate.id), ["К1", "К2"]);
  });
});

describe("простий протокол Е-голосування — негативні сценарії", () => {
  test("виборця немає у списку — бюлетень відхиляється", () => {
    const { commission } = session(["В1"]);
    const stranger = new Voter("Стороння особа", BITS);

    const result = commission.receive(stranger.vote("К1", commission.publicKey));
    assert.equal(result.status === "rejected" && result.reason, "NOT_IN_LIST");
    assert.equal(commission.publishResults().accepted, 0);
  });

  test("повторне голосування відхиляється і не змінює підрахунок", () => {
    const { commission, voters } = session(["В1"]);
    commission.receive(voters[0]!.vote("К1", commission.publicKey));

    const second = commission.receive(voters[0]!.vote("К2", commission.publicKey));
    assert.equal(second.status === "rejected" && second.reason, "ALREADY_VOTED");
    assert.deepEqual(
      [commission.publishResults().tally.get("К1"), commission.publishResults().tally.get("К2")],
      [1, 0],
    );
  });

  test("голосування від чужого імені відхиляється через ЕЦП", () => {
    const { commission, voters } = session(["Жертва", "Зловмисник"]);
    const [victim, attacker] = voters as [Voter, Voter];

    const forged = serializeBallot({
      voterName: victim.name,
      candidateId: "К2",
      issuedAt: new Date().toISOString(),
    });
    const envelope = {
      senderName: victim.name,
      cipher: sealFor({ ballot: forged, signature: attacker.fillAndSign("К2").signature }, commission.publicKey),
    };

    const result = commission.receive(envelope);
    assert.equal(result.status === "rejected" && result.reason, "BAD_SIGNATURE");
    assert.equal(commission.voterList[0]?.hasVoted, false);
  });

  test("підміна вмісту бюлетеня після підписання виявляється перевіркою ЕЦП", () => {
    const { commission, voters } = session(["В1"]);
    const signed = voters[0]!.fillAndSign("К1");
    const tampered = signed.ballot.replace('"candidateId":"К1"', '"candidateId":"К2"');

    const result = commission.receive({
      senderName: voters[0]!.name,
      cipher: sealFor({ ballot: tampered, signature: signed.signature }, commission.publicKey),
    });
    assert.equal(result.status === "rejected" && result.reason, "BAD_SIGNATURE");
  });

  test("правильний ЕЦП не рятує зіпсований бюлетень", () => {
    const { commission, voters } = session(["В1"]);
    const result = commission.receive(voters[0]!.vote("К9", commission.publicKey));

    assert.equal(result.status === "rejected" && result.reason, "INVALID_BALLOT");
    assert.equal(commission.voterList[0]?.hasVoted, false);
  });

  test("бюлетень, зашифрований чужим ключем, не розшифровується ВК", () => {
    const { commission, voters } = session(["В1"]);
    const foreign = new ElectionCommission({ candidates: CANDIDATES, bits: BITS });

    const result = commission.receive(voters[0]!.vote("К1", foreign.publicKey));
    assert.equal(result.status === "rejected" && result.reason, "UNDECRYPTABLE");
  });
});
