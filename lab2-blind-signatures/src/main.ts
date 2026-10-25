import { ElectionCommission, type CheckEvent } from "./commission.ts";
import { encrypt, short } from "./rsa.ts";
import {
  parseBallot,
  SET_COUNT,
  type Candidate,
  type ChallengeResult,
  type ElectionResults,
  type SigningResult,
  type VoteResult,
  type VoterRecord,
} from "./types.ts";
import { sealFor, Voter } from "./voter.ts";
import { banner, color, fail, info, note, ok, section, step, table } from "./ui.ts";

/**
 * Демонстрація протоколу Е-голосування зі сліпими підписами:
 * 2 кандидати, 5 виборців, RSA для сліпого ЕЦП і шифрування бюлетенів.
 * Показані як позитивні, так і негативні сценарії перевірок ВК.
 */

const KEY_BITS = 512;

const CANDIDATES: readonly Candidate[] = [
  { id: "К1", name: "Іваненко Іван Іванович" },
  { id: "К2", name: "Петренко Петро Петрович" },
];

const VOTERS = [
  { name: "Коваленко Андрій Сергійович", document: "АА 100001" },
  { name: "Шевченко Олена Миколаївна", document: "АА 100002" },
  { name: "Бондаренко Богдан Юрійович", document: "АА 100003" },
  { name: "Ткаченко Марія Василівна", document: "АА 100004" },
  { name: "Мельник Остап Ігорович", document: "АА 100005" },
] as const;

const CHOICES = ["К1", "К2", "К1", "К2", "К1"] as const;

const STATUS_LABELS: Record<VoterRecord["status"], string> = {
  registered: "зареєстрований",
  issued: "набір видано",
  refused: "відмовлено",
};

const CHECK_LABELS: Record<CheckEvent["check"], string> = {
  inList: "Наявність у списку виборців",
  identity: "Перевірка особи виборця",
  notIssued: "Підписаний набір раніше не видавався",
  requestShape: "Структура запиту",
  challenge: "Випадковий вибір 9 з 10 наборів",
  revealedIndices: "Розкрито саме обрані набори",
  setValid: "Перевірка розкритого набору",
  blindSign: "Сліпий підпис нерозкритого набору",
  decrypt: "Розшифрування закритим ключем ВК",
  signature: "Перевірка ЕЦП ВК",
  ballotValid: "Коректність бюлетеня",
  uniqueId: "Унікальність ID",
};

let verbose = true;
const observer = (event: CheckEvent) => {
  if (verbose) (event.passed ? ok : fail)(`${CHECK_LABELS[event.check]}: ${event.detail}`);
};

function verdict(result: ChallengeResult | SigningResult | VoteResult): void {
  switch (result.status) {
    case "rejected":
      fail(color.bold(color.red(`ВІДМОВА [${result.reason}]: ${result.message}`)));
      return;
    case "accepted":
      ok(color.bold(color.green(`БЮЛЕТЕНЬ ПРИЙНЯТО → голос за «${result.ballot.candidateId}» зараховано`)));
      return;
    case "signed":
      ok(color.bold(color.green(`ВК ВИДАЛА ${result.blindSignatures.length} СЛІПІ ПІДПИСИ`)));
      return;
    case "challenge":
      return;
  }
}

/** Кроки 2–10 без деталей: запит, розкриття 9 наборів, отримання й розмаскування підписів. */
function obtainSignedSet(voter: Voter, commission: ElectionCommission): SigningResult {
  const challenge = commission.requestSigning(voter.prepare(CANDIDATES, commission.publicKey));
  if (challenge.status !== "challenge") return challenge;
  const result = commission.completeSigning(voter.name, voter.reveal(challenge.reveal));
  if (result.status === "signed") voter.acceptSignatures(result.blindSignatures, commission.publicKey);
  return result;
}

function setupSession(voters: readonly { name: string; document: string }[], bits = KEY_BITS) {
  const commission = new ElectionCommission({ candidates: CANDIDATES, bits, observer });
  for (const voter of voters) commission.registerVoter(voter.name, voter.document);
  return { commission, voters: voters.map((voter) => new Voter(voter.name, voter.document)) };
}

function mainSession(): void {
  banner("ЛАБОРАТОРНА РОБОТА №2 — ПРОТОКОЛ Е-ГОЛОСУВАННЯ ЗІ СЛІПИМИ ПІДПИСАМИ (RSA)");

  section("КРОК 1. ВК формує списки виборців і кандидатів, генерує ключі RSA");
  const { commission, voters } = setupSession(VOTERS);

  note("Список виборців, сформований ВК:");
  table(
    ["№", "ПІБ", "Документ", "Статус"],
    commission.voterList.map((voter, index) => [String(index + 1), voter.name, voter.document, STATUS_LABELS[voter.status]]),
  );
  note("Список кандидатів:");
  table(["Код", "ПІБ кандидата"], CANDIDATES.map((candidate) => [candidate.id, candidate.name]));
  const { publicKey, privateKey, parameters } = commission.keys;
  note("Пара ключів RSA виборчої комісії:");
  info(`p = ${short(parameters.p)}, q = ${short(parameters.q)}`);
  info(`закритий ключ: d = ${short(privateKey.d)}`);
  note(`${color.bold("Опубліковано відкритий ключ ВК:")} e = ${publicKey.e}, n = ${short(publicKey.n, 14, 6)}`);

  const first = voters[0]!;
  section(`КРОКИ 2–4. Виборець №1 формує ${SET_COUNT} наборів бюлетенів і маскує їх хеші`);
  const request = first.prepare(CANDIDATES, commission.publicKey);
  table(
    ["Набір", "ID набору", "H'(К1) = H·rᵉ mod n", "H'(К2) = H·rᵉ mod n"],
    first.preparedSets.map((set, index) => [
      String(index + 1),
      set.id,
      short(set.blinded[0]!, 10, 4),
      short(set.blinded[1]!, 10, 4),
    ]),
  );
  const sample = first.preparedSets[0]!;
  note("Детально для першого бюлетеня набору №1:");
  info(`бюлетень: ${sample.ballots[0]}`);
  info(`H  = (H₍ᵢ₋₁₎ + Mᵢ)² mod n → ${short(sample.hashes[0]!)}`);
  info(`r  (НСД(r, n) = 1)       → ${short(sample.factors[0]!)}`);
  info(`H' = H·rᵉ mod n          → ${short(sample.blinded[0]!)}`);

  section("КРОКИ 5–6. Запит на сліпий підпис: перевірка особи та вибір наборів для розкриття");
  const challenge = commission.requestSigning(request);
  verdict(challenge);
  if (challenge.status !== "challenge") throw new Error("Очікувався виклик на розкриття");

  section("КРОКИ 7–9. Розкриття 9 наборів, перевірка ВК і сліпий підпис десятого");
  const revealed = first.reveal(challenge.reveal);
  const hidden = [...Array(SET_COUNT).keys()].find((index) => !challenge.reveal.includes(index)) ?? -1;
  info(`виборець передає бюлетені та множники r для ${revealed.length} наборів; набір №${hidden + 1} лишається таємним`);
  const signing = commission.completeSigning(first.name, revealed);
  verdict(signing);
  if (signing.status !== "signed") throw new Error("Очікувався підписаний набір");

  section("КРОК 10. Виборець знімає маскування: S = S'·r⁻¹ mod n");
  first.acceptSignatures(signing.blindSignatures, commission.publicKey);
  for (const [candidateId, signed] of first.signed) {
    const index = [...first.signed.keys()].indexOf(candidateId);
    info(`бюлетень ${signed.ballot}`);
    info(`  S' = ${short(signing.blindSignatures[index]!)}  →  S = ${short(signed.signature)}`);
  }
  ok("Sᵉ mod n = H для обох бюлетенів: отримано дійсні підписи ВК на незамасковані хеші");

  section("Інші виборці отримують підписані набори (ті самі кроки 2–10)");
  verbose = false;
  for (const voter of voters.slice(1)) {
    const result = obtainSignedSet(voter, commission);
    (result.status === "signed" ? ok : fail)(
      `${voter.name}: ${result.status === "signed" ? "9 наборів перевірено, нерозкритий набір підписано" : result.message}`,
    );
  }
  verbose = true;
  table(
    ["№", "ПІБ", "Статус у реєстрі ВК"],
    commission.voterList.map((voter, index) => [String(index + 1), voter.name, color.green(STATUS_LABELS[voter.status])]),
  );

  section("НЕГАТИВНІ СЦЕНАРІЇ: етап отримання підписаного набору");
  step("Сценарій 1. Стороння особа, якої немає у списку, просить підписати набір");
  verdict(commission.requestSigning(new Voter("Стороння Мальвіна Олегівна", "ВВ 999999").prepare(CANDIDATES, publicKey)));

  step("Сценарій 2. Хтось подає запит від імені виборця №2 з чужим документом");
  const impostor = new Voter(VOTERS[1].name, "ВВ 123456");
  verdict(commission.requestSigning(impostor.prepare(CANDIDATES, publicKey)));

  step("Сценарій 3. Виборець №1 вдруге просить підписаний набір");
  verdict(commission.requestSigning(new Voter(first.name, first.document).prepare(CANDIDATES, publicKey)));

  section("КРОКИ 11–13. Анонімне голосування: позитивні сценарії");
  for (const [index, voter] of voters.slice(0, 4).entries()) {
    step(`Виборець №${index + 1} голосує за ${CHOICES[index]}`);
    const envelope = voter.vote(CHOICES[index]!, publicKey);
    const signed = voter.signed.get(CHOICES[index]!)!;
    info(`обрано бюлетень ${signed.ballot} + підпис ВК ${short(signed.signature, 8, 4)}`);
    info(`шифротекст (${envelope.cipher.length} бл.): ${envelope.cipher.slice(0, 2).map((block) => short(block, 8, 4)).join(", ")}, … — без ПІБ`);
    verdict(commission.receive(envelope));
  }

  section("НЕГАТИВНІ СЦЕНАРІЇ: етап голосування");
  const fifth = voters[4]!;
  step("Сценарій 4. Виборець №5 надсилає обидва бюлетені свого підписаного набору");
  info("перший бюлетень — за К1:");
  verdict(commission.receive(fifth.vote("К1", publicKey)));
  info("другий бюлетень того самого набору — за К2:");
  verdict(commission.receive({ cipher: sealFor(fifth.signed.get("К2")!, publicKey) }));

  step("Сценарій 5. Перехоплений бюлетень виборця №2 надіслано повторно");
  verdict(commission.receive({ cipher: sealFor(voters[1]!.signed.get("К2")!, publicKey) }));

  step("Сценарій 6. Підміна вибору в підписаному бюлетені (К2 → К1, підпис той самий)");
  const original = voters[3]!.signed.get("К2")!;
  const tampered = original.ballot.replace('"К2"', '"К1"');
  info(`оригінал: ${original.ballot}`);
  info(`підміна:  ${tampered}`);
  verdict(commission.receive({ cipher: sealFor({ ballot: tampered, signature: original.signature }, publicKey) }));

  step("Сценарій 7. Самостійно сформований бюлетень без підпису ВК (випадкове S)");
  const forged = JSON.stringify({ id: "0123456789abcdef", candidateId: "К2" });
  verdict(commission.receive({ cipher: sealFor({ ballot: forged, signature: 0xc0ffeen ** 20n % publicKey.n }, publicKey) }));

  step("Сценарій 8. Повідомлення зашифровано не відкритим ключем ВК");
  const foreignKey = new ElectionCommission({ candidates: CANDIDATES, bits: KEY_BITS }).publicKey;
  verdict(commission.receive({ cipher: encrypt("{\"ballot\":\"…\"}", foreignKey) }));

  section("КРОК 14. Підрахунок голосів і публікація результатів");
  const results = commission.publishResults();
  printResults(results);

  note("Опубліковані бюлетені (ID — вибір — підпис ВК):");
  table(
    ["№", "ID", "Вибір", "Підпис ВК S"],
    results.published.map((entry, index) => [String(index + 1), entry.id, entry.candidateId, short(entry.signature, 14, 6)]),
  );

  note("Кожен виборець шукає свій ID (відомий лише йому) і звіряє вибір:");
  table(
    ["Виборець", "Свій ID", "Результат перевірки", "ВК знала ID?"],
    voters.map((voter, index) => {
      const check = voter.checkPublished(results.published);
      const id = parseBallot(voter.signed.get(CHOICES[index]!)!.ballot).id;
      return [
        voter.name,
        id,
        check === "counted" ? color.green("голос враховано правильно") : color.red(check),
        commission.knownIds.has(id) ? color.red("так") : color.green("ні"),
      ];
    }),
  );
  info(`ВК знає ${commission.knownIds.size} ID розкритих наборів; жоден з них не збігається з ID поданих бюлетенів`);

  step("Сценарій 9. ВК підмінює вибір у опублікованому записі виборця №2");
  const altered = results.published.map((entry, index) =>
    index === 1 ? { ...entry, candidateId: "К1", ballot: entry.ballot.replace('"К2"', '"К1"') } : entry,
  );
  const check = voters[1]!.checkPublished(altered);
  (check === "counted" ? ok : fail)(`виборець №2 перевіряє свій ID: ${check === "altered" ? "запис змінено — підміну викрито" : check}`);
}

function printResults(results: ElectionResults): void {
  table(
    ["Кандидат", "ПІБ", "Голоси", "Частка"],
    CANDIDATES.map((candidate) => {
      const votes = results.tally.get(candidate.id) ?? 0;
      const share = results.accepted === 0 ? 0 : Math.round((votes / results.accepted) * 100);
      return [candidate.id, candidate.name, String(votes), `${share}% ${"█".repeat(votes)}`];
    }),
  );
  info(`прийнято бюлетенів: ${results.accepted}, відхилено: ${results.rejected}`);
  if (results.leaders.length === 0) note(color.yellow("Жодного голосу не зараховано — переможця немає."));
  else if (results.isTie) note(color.bold(color.yellow("НІЧИЯ: голоси розподілилися порівну.")));
  else note(color.bold(color.green(`ПЕРЕМОЖЕЦЬ: ${results.leaders[0]?.name}`)));
}

/** Окрема сесія: виборці намагаються отримати підпис на некоректний набір. */
function cheatingSession(): void {
  banner("ДОДАТКОВА СЕСІЯ — ВИЯВЛЕННЯ НЕКОРЕКТНО СФОРМОВАНИХ НАБОРІВ");
  const { commission, voters } = setupSession([
    { name: "Гнатюк Тарас Олегович", document: "АВ 200001" },
    { name: "Лисенко Ірина Петрівна", document: "АВ 200002" },
  ]);
  const [cheater, swapper] = voters as [Voter, Voter];
  const publicKey = commission.publicKey;

  step("Сценарій 10. Набір №4 містить два бюлетені за К1 і жодного за К2");
  const challenge = commission.requestSigning(
    cheater.prepare(CANDIDATES, publicKey, (index) => (index === 3 ? ["К1", "К1"] : ["К1", "К2"])),
  );
  if (challenge.status !== "challenge") throw new Error("Очікувався виклик на розкриття");
  const result = commission.completeSigning(cheater.name, cheater.reveal(challenge.reveal));
  verdict(result);
  if (result.status === "signed") info("шахрайський набір випадково лишився нерозкритим (імовірність 10%)");

  step("Сценарій 11. Під час розкриття бюлетені набору переставлено: H·rᵉ не збігається з H'");
  const second = commission.requestSigning(swapper.prepare(CANDIDATES, publicKey));
  if (second.status !== "challenge") throw new Error("Очікувався виклик на розкриття");
  const reveals = swapper.reveal(second.reveal).map((set, index) =>
    index === 0 ? { ...set, ballots: [...set.ballots].reverse() } : set,
  );
  verdict(commission.completeSigning(swapper.name, reveals));

  step("Сценарій 12. Після відмови виборець подає новий запит");
  verbose = false;
  const retry = commission.requestSigning(swapper.prepare(CANDIDATES, publicKey));
  verbose = true;
  verdict(retry);

  section("Імовірність виявлення одного некоректного набору (статистичний експеримент)");
  const trials = 1000;
  verbose = false;
  const lab = new ElectionCommission({ candidates: CANDIDATES, bits: 256, observer });
  let caught = 0;
  for (let trial = 0; trial < trials; trial += 1) {
    const name = `Учасник ${trial}`;
    lab.registerVoter(name, String(trial));
    const voter = new Voter(name, String(trial));
    const badSet = trial % SET_COUNT;
    const asked = lab.requestSigning(voter.prepare(CANDIDATES, lab.publicKey, (index) => (index === badSet ? ["К1", "К1"] : ["К1", "К2"])));
    if (asked.status === "challenge" && lab.completeSigning(name, voter.reveal(asked.reveal)).status === "rejected") caught += 1;
  }
  verbose = true;
  info(`спроб: ${trials}, шахрайський набір виявлено: ${caught} (${((caught / trials) * 100).toFixed(1)}%)`);
  info("теоретична ймовірність: 9/10 = 90%; для двох і більше некоректних наборів — 100%");
}

function propertySummary(): void {
  section("Відповідність вимогам до ідеального протоколу");
  table(
    ["Вимога", "Стан", "Механізм у реалізації"],
    [
      ["Голосують лише ті, хто має право", color.green("забезпечено"), "підпис ВК видається лише за списком"],
      ["Не більше одного голосу", color.green("забезпечено"), "один підписаний набір + унікальність ID"],
      ["Таємниця голосування", color.green("забезпечено"), "сліпий підпис, бюлетень без ПІБ"],
      ["Неможливо проголосувати за іншого", color.yellow("частково"), "ВК може підписати бюлетені за неявку"],
      ["Неможливо таємно змінити голос", color.green("забезпечено"), "ID і вибір під підписом ВК"],
      ["Перевірка виборцем свого голосу", color.green("забезпечено"), "публікація ID і підписаних бюлетенів"],
    ],
  );
}

mainSession();
cheatingSession();
propertySummary();
console.log();
