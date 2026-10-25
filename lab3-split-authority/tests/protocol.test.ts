import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { RegistrationBureau } from "../src/bureau.ts";
import { ElectionCommission } from "../src/commission.ts";
import { sign } from "../src/rsa.ts";
import { parseRnList, serializeRnList, type Candidate, type Citizen } from "../src/types.ts";
import { sealFor, Voter } from "../src/voter.ts";

const BITS = 256;

const CANDIDATES: readonly Candidate[] = [
  { id: "К1", name: "Іваненко Іван Іванович" },
  { id: "К2", name: "Петренко Петро Петрович" },
];

const CITIZENS: readonly Citizen[] = [
  { name: "В1", passport: "АА000001", birthDate: "1990-01-01" },
  { name: "В2", passport: "АА000002", birthDate: "1991-02-02" },
  { name: "В3", passport: "АА000003", birthDate: "1992-03-03" },
  { name: "В4", passport: "АА000004", birthDate: "1993-04-04" },
  { name: "В5", passport: "АА000005", birthDate: "1994-05-05" },
  { name: "Неповнолітній", passport: "АА000006", birthDate: "2008-10-26" },
];

const ELECTION_DATE = "2026-10-25";

/** Повна підготовка: реєстрація п’ятьох виборців у БР і передача списку RN до ВК. */
function session() {
  const bureau = new RegistrationBureau({ citizens: CITIZENS, electionDate: ELECTION_DATE, bits: BITS });
  const commission = new ElectionCommission({ candidates: CANDIDATES, bits: BITS });
  const voters = CITIZENS.slice(0, 5).map((citizen) => new Voter(citizen.name, citizen.passport, BITS));
  for (const voter of voters) {
    const result = bureau.register(voter.registrationRequest());
    assert.equal(result.status, "registered");
    if (result.status === "registered") voter.acceptRn(result.rn);
  }
  assert.equal(commission.importRnList(bureau.exportRnList(), bureau.publicKey).ok, true);
  return { bureau, commission, voters, voter: (index: number) => voters[index]! };
}

const reasonOf = (result: { status: string; reason?: string }) => result.reason;

describe("БР — реєстрація виборців", () => {
  test("кожен зареєстрований виборець отримує окремий унікальний RN", () => {
    const { bureau, voters } = session();
    assert.equal(new Set(voters.map((voter) => voter.rn)).size, 5);
    assert.deepEqual(
      bureau.registry.map((entry) => entry.rn),
      voters.map((voter) => voter.rn),
    );
  });

  test("повторна реєстрація того самого виборця (навіть з новим ключем) відхиляється", () => {
    const { bureau, voter } = session();
    const again = new Voter(voter(0).name, voter(0).passport, BITS);
    assert.equal(reasonOf(bureau.register(again.registrationRequest())), "ALREADY_REGISTERED");
    assert.equal(bureau.registry.length, 5);
  });

  test("особа поза реєстром, чужий паспорт і неповнолітній не отримують RN", () => {
    const { bureau } = session();
    const request = (name: string, passport: string) => new Voter(name, passport, BITS).registrationRequest();
    assert.equal(reasonOf(bureau.register(request("Стороння", "ХХ000000"))), "NOT_IN_ROLL");
    assert.equal(reasonOf(bureau.register(request("Самозванець", "АА000001"))), "IDENTITY_MISMATCH");
    assert.equal(reasonOf(bureau.register(request("Неповнолітній", "АА000006"))), "NO_VOTING_RIGHT");
  });

  test("список для ВК містить лише RN і відкриті ключі — без ПІБ і паспортів", () => {
    const { bureau, voters } = session();
    const { payload } = bureau.exportRnList();
    for (const voter of voters) {
      assert.equal(payload.includes(voter.name), false);
      assert.equal(payload.includes(voter.passport), false);
    }
    assert.deepEqual(
      parseRnList(payload).map((record) => record.rn).sort(),
      voters.map((voter) => voter.rn).sort(),
    );
  });
});

describe("передача списку RN від БР до ВК", () => {
  test("ВК відхиляє список, підписаний не БР, і список, змінений після підписання", () => {
    const { bureau } = session();
    const commission = new ElectionCommission({ candidates: CANDIDATES, bits: BITS });
    const forger = new Voter("Зловмисник", "—", BITS);

    const forged = serializeRnList([{ rn: "555555", publicKey: forger.publicKey }]);
    const signedByForger = { payload: forged, signature: sign(forged, forger.keys.privateKey) };
    assert.equal(commission.importRnList(signedByForger, bureau.publicKey).ok, false);

    const genuine = bureau.exportRnList();
    const extended = serializeRnList([...parseRnList(genuine.payload), { rn: "555555", publicKey: forger.publicKey }]);
    assert.equal(commission.importRnList({ payload: extended, signature: genuine.signature }, bureau.publicKey).ok, false);
    assert.equal(commission.rnRegister.length, 0);
  });
});

describe("ВК — приймання бюлетенів", () => {
  test("5 виборців і 2 кандидати: бюлетені приймаються, RN позначаються, голоси рахуються", () => {
    const { commission, voters } = session();
    const choices = ["К1", "К2", "К1", "К2", "К1"];
    voters.forEach((voter, index) => {
      const { envelope } = voter.vote(choices[index]!, commission.publicKey);
      assert.equal(commission.receive(envelope).status, "accepted");
    });

    const results = commission.publishResults();
    assert.equal(results.tally.get("К1"), 3);
    assert.equal(results.tally.get("К2"), 2);
    assert.equal(results.leaders[0]?.id, "К1");
    assert.equal(results.ballots.length, 5);
    assert.ok(commission.rnRegister.every((entry) => entry.used));
  });

  test("бюлетень з RN, якого немає у списку від БР, відхиляється", () => {
    const { commission } = session();
    const outsider = new Voter("Стороння", "ХХ000000", BITS);
    outsider.acceptRn("424242");
    assert.equal(reasonOf(commission.receive(outsider.vote("К1", commission.publicKey).envelope)), "UNKNOWN_RN");
  });

  test("повторне голосування з уже використаним RN відхиляється", () => {
    const { commission, voter } = session();
    commission.receive(voter(0).vote("К1", commission.publicKey).envelope);
    const second = sealFor(voter(0).prepare("К2"), commission.publicKey);
    assert.equal(reasonOf(commission.receive(second)), "RN_USED");
  });

  test("бюлетень з ID, який уже використаний, відхиляється, а RN залишається вільним", () => {
    const { commission, voter } = session();
    commission.receive(voter(0).vote("К1", commission.publicKey).envelope);
    const clash = sealFor(voter(1).prepare("К2", voter(0).castId), commission.publicKey);
    assert.equal(reasonOf(commission.receive(clash)), "DUPLICATE_ID");
    assert.equal(commission.receive(voter(1).vote("К2", commission.publicKey).envelope).status, "accepted");
  });

  test("ЕЦП чужим ключем під викраденим RN відхиляється", () => {
    const { commission, voter } = session();
    const thief = new Voter("Зловмисник", "—", BITS);
    thief.acceptRn(voter(2).rn);
    assert.equal(reasonOf(commission.receive(thief.vote("К1", commission.publicKey).envelope)), "BAD_SIGNATURE");
  });

  test("повідомлення, змінене після підписання, відхиляється", () => {
    const { commission, voter } = session();
    const signed = voter(3).prepare("К1");
    const text = signed.text.replace('"candidateId":"К1"', '"candidateId":"К2"');
    const result = commission.receive(sealFor({ text, signature: signed.signature }, commission.publicKey));
    assert.equal(reasonOf(result), "BAD_SIGNATURE");
  });

  test("бюлетень з неіснуючим кандидатом і повідомлення під чужим ключем відхиляються", () => {
    const { commission, voter } = session();
    assert.equal(reasonOf(commission.receive(sealFor(voter(4).prepare("К9"), commission.publicKey))), "INVALID_BALLOT");
    const stranger = new Voter("Чужий", "—", BITS);
    assert.equal(reasonOf(commission.receive(sealFor(voter(4).prepare("К1"), stranger.publicKey))), "UNDECRYPTABLE");
  });
});

describe("перевірка виборцем власного голосу", () => {
  test("чесна публікація підтверджується, підміна і вилучення бюлетеня виявляються", () => {
    const { commission, voter } = session();
    commission.receive(voter(0).vote("К1", commission.publicKey).envelope);
    commission.receive(voter(1).vote("К2", commission.publicKey).envelope);
    const { ballots } = commission.publishResults();

    assert.equal(voter(0).verifyPublication(ballots).status, "confirmed");
    assert.equal(voter(1).verifyPublication(ballots).status, "confirmed");

    const swapped = ballots.map((ballot) => (ballot.id === voter(1).castId ? { ...ballot, candidateId: "К1" } : ballot));
    assert.deepEqual(voter(1).verifyPublication(swapped), {
      status: "mismatch",
      id: voter(1).castId,
      expected: "К2",
      published: "К1",
    });
    assert.equal(voter(0).verifyPublication(ballots.filter((ballot) => ballot.id !== voter(0).castId)).status, "missing");
  });
});
