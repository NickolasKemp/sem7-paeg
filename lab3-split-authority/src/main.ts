import { RegistrationBureau, type BureauCheck } from "./bureau.ts";
import { ElectionCommission, type CommissionCheck } from "./commission.ts";
import { hashMessage, short, sign } from "./rsa.ts";
import {
  parseRnList,
  parseVoteMessage,
  serializeRnList,
  type Candidate,
  type CheckEvent,
  type Citizen,
  type ElectionResults,
  type Envelope,
  type ProcessingResult,
  type PublishedBallot,
  type RegistrationResult,
  type RnListMessage,
} from "./types.ts";
import { sealFor, Voter } from "./voter.ts";
import { banner, color, fail, info, note, ok, section, step, table } from "./ui.ts";

/**
 * Демонстрація протоколу Е-голосування з розподілом повноважень між
 * бюро реєстрації (БР) та виборчою комісією (ВК): 2 кандидати, 5 виборців,
 * RSA для шифрування та ЕЦП. Для кожної перевірки показано позитивний і негативний сценарій.
 */

const KEY_BITS = 512;
const ELECTION_DATE = "2026-10-25";

const CANDIDATES: readonly Candidate[] = [
  { id: "К1", name: "Іваненко Іван Іванович" },
  { id: "К2", name: "Петренко Петро Петрович" },
];

/** Реєстр громадян, з яким БР звіряє особу виборця: п’ятеро виборців і неповнолітня особа. */
const CITIZENS: readonly Citizen[] = [
  { name: "Коваленко Андрій Сергійович", passport: "АА123456", birthDate: "1985-03-14" },
  { name: "Шевченко Олена Миколаївна", passport: "ВК654321", birthDate: "1992-07-02" },
  { name: "Бондаренко Богдан Юрійович", passport: "СН777001", birthDate: "2001-11-23" },
  { name: "Ткаченко Марія Василівна", passport: "КМ246810", birthDate: "1978-01-30" },
  { name: "Мельник Остап Ігорович", passport: "ТТ135790", birthDate: "2008-10-20" },
  { name: "Мельник Софія Ігорівна", passport: "ТТ135791", birthDate: "2008-10-26" },
];

const VOTERS = CITIZENS.slice(0, 5);
const MINOR = CITIZENS[5]!;

const bureauLabels: Record<BureauCheck, string> = {
  inRoll: "Наявність у реєстрі громадян",
  identity: "Перевірка особи (ПІБ ↔ паспорт)",
  votingRight: "Право голосу (вік ≥ 18)",
  notRegistered: "Відсутність попередньої реєстрації",
};

const commissionLabels: Record<CommissionCheck, string> = {
  rnListSignature: "ЕЦП БР під списком RN",
  decrypt: "Розшифрування закритим ключем ВК",
  rnInList: "Наявність RN у списку від БР",
  rnNotUsed: "RN ще не використаний",
  signature: "ЕЦП за ключем цього RN",
  idUnique: "Унікальність ID",
  ballotValid: "Коректність бюлетеня",
};

/** Поки `quiet`, перевірки не друкуються — щоб не повторювати однакові рядки для кожного виборця. */
let quiet = false;

const printer =
  <Check extends string>(labels: Record<Check, string>) =>
  (event: CheckEvent<Check>) => {
    if (!quiet) (event.passed ? ok : fail)(`${labels[event.check]}: ${event.detail}`);
  };

const bureau = new RegistrationBureau({
  citizens: CITIZENS,
  electionDate: ELECTION_DATE,
  bits: KEY_BITS,
  observer: printer(bureauLabels),
});
const commission = new ElectionCommission({
  candidates: CANDIDATES,
  bits: KEY_BITS,
  observer: printer(commissionLabels),
});
const voters = VOTERS.map((citizen) => new Voter(citizen.name, citizen.passport, KEY_BITS));
const voter = (index: number) => voters[index]!;

function registrationVerdict(result: RegistrationResult): void {
  if (result.status === "registered") ok(color.bold(color.green(`ЗАРЕЄСТРОВАНО → видано RN = ${result.rn}`)));
  else fail(color.bold(color.red(`ВІДМОВА [${result.reason}]: ${result.message}`)));
}

function ballotVerdict(result: ProcessingResult): void {
  if (result.status === "accepted") {
    ok(color.bold(color.green(`БЮЛЕТЕНЬ ПРИЙНЯТО → ID ${result.id}, голос за «${result.candidateId}»`)));
  } else {
    fail(color.bold(color.red(`БЮЛЕТЕНЬ ВІДХИЛЕНО [${result.reason}]: ${result.message}`)));
  }
}

function showMessage(signer: Voter, text: string, signature: bigint, envelope: Envelope): void {
  info(`повідомлення M: ${text}`);
  info(`H = (H₍ᵢ₋₁₎ + Mᵢ)² mod n → ${short(hashMessage(text, signer.publicKey.n))}`);
  info(`ЕЦП = H^d mod n → ${short(signature)}`);
  const shown = envelope.cipher.slice(0, 2).map((block) => short(block, 8, 4));
  info(`шифротекст для ВК (${envelope.cipher.length} бл.): ${shown.join(", ")}, …`);
}

function castVote(who: Voter, candidateId: string, label: string): void {
  step(label);
  const { signed, envelope } = who.vote(candidateId, commission.publicKey);
  showMessage(who, signed.text, signed.signature, envelope);
  ballotVerdict(commission.receive(envelope));
}

function register(who: Voter, label: string): void {
  step(label);
  const result = bureau.register(who.registrationRequest());
  registrationVerdict(result);
  if (result.status === "registered") who.acceptRn(result.rn);
}

/* ─────────────────────────────── Кроки 1–2: реєстрація ─────────────────────────────── */

function registrationStage(): void {
  section("КРОКИ 1–2. Реєстрація виборців у БР: перевірки та видача RN");
  note("Реєстр громадян, з яким БР звіряє особу виборця:");
  table(
    ["ПІБ", "Паспорт", "Дата народження"],
    CITIZENS.map((citizen) => [citizen.name, citizen.passport, citizen.birthDate]),
  );
  note("Кожен виборець самостійно згенерував пару ключів RSA для ЕЦП і передає БР відкритий ключ:");
  table(
    ["ПІБ виборця", "Відкритий ключ (e, n)", "Закритий ключ (d, n)"],
    voters.map((item) => [
      item.name,
      `e = ${item.publicKey.e}, n = ${short(item.publicKey.n, 8, 4)}`,
      `d = ${short(item.keys.privateKey.d, 8, 4)}`,
    ]),
  );

  register(voter(0), `Реєстрація «${voter(0).name}»`);
  step("Реєстрація решти виборців (ті самі чотири перевірки)");
  quiet = true;
  for (const item of voters.slice(1)) {
    const result = bureau.register(item.registrationRequest());
    if (result.status === "registered") item.acceptRn(result.rn);
    ok(`${item.name}: усі перевірки пройдено, RN = ${item.rn}`);
  }
  quiet = false;

  note("Реєстр БР: зв’язок «виборець — RN — відкритий ключ ЕЦП» зберігається лише в БР:");
  table(
    ["ПІБ", "Паспорт", "RN", "Відкритий ключ ЕЦП"],
    bureau.registry.map((entry) => [entry.name, entry.passport, entry.rn, short(entry.publicKey.n, 10, 4)]),
  );
}

function registrationNegative(): void {
  section("НЕГАТИВНІ СЦЕНАРІЇ РЕЄСТРАЦІЇ");

  step(`Сценарій Р1. «${voter(1).name}» намагається отримати другий RN`);
  info("виборець генерує нову пару ключів, щоб під новим ключем отримати ще один RN");
  const second = new Voter(voter(1).name, voter(1).passport, KEY_BITS);
  registrationVerdict(bureau.register(second.registrationRequest()));

  step("Сценарій Р2. Звертається особа, якої немає в реєстрі громадян");
  registrationVerdict(bureau.register(new Voter("Стороння Мальвіна Олегівна", "ХХ000000", KEY_BITS).registrationRequest()));

  step(`Сценарій Р3. Чужий паспорт: «Самозванець Петро» подає паспорт ${voter(3).passport}`);
  registrationVerdict(bureau.register(new Voter("Самозванець Петро Іванович", voter(3).passport, KEY_BITS).registrationRequest()));

  step(`Сценарій Р4. «${MINOR.name}» (нар. ${MINOR.birthDate}) не має права голосу`);
  registrationVerdict(bureau.register(new Voter(MINOR.name, MINOR.passport, KEY_BITS).registrationRequest()));
  info(`для порівняння: «${voter(4).name}» (нар. ${CITIZENS[4]!.birthDate}) уже зареєстрований — 18 р. виповнилося`);
}

/* ─────────────────────────── Крок 3: передача списку RN до ВК ─────────────────────────── */

function transferStage(): void {
  section("КРОК 3. Передача списку RN від БР до ВК, публікація ключа ВК");
  const message = bureau.exportRnList();
  note("БР формує список дійсних RN з відкритими ключами (без ПІБ і паспортів) і підписує його:");
  info(`payload: ${message.payload.slice(0, 82)}…`);
  info(`ЕЦП БР = ${short(message.signature)}`);

  step("Сценарій П1 (негативний). Підроблений список RN від імені БР");
  forgedList(message);

  step("Сценарій П2 (позитивний). ВК приймає справжній список від БР");
  const imported = commission.importRnList(message, bureau.publicKey);
  if (imported.ok) ok(color.bold(color.green(`СПИСОК ПРИЙНЯТО → у ВК ${imported.count} дійсних RN`)));

  note("Реєстр ВК: лише RN, відкритий ключ ЕЦП та позначка використання — персональних даних немає:");
  table(
    ["RN", "Відкритий ключ ЕЦП", "Використаний"],
    commission.rnRegister.map((entry) => [entry.rn, short(entry.publicKey.n, 10, 4), entry.used ? "так" : "ні"]),
  );
  note(`Відкритий ключ ВК (публікується): e = ${commission.publicKey.e}, n = ${short(commission.publicKey.n, 12, 6)}`);
  note("БР публікує список зареєстрованих виборців без RN:");
  table(["№", "ПІБ"], bureau.publishVoterList().map((name, index) => [String(index + 1), name]));
}

function forgedList(genuine: RnListMessage): void {
  const forger = new Voter("Зловмисник", "—", KEY_BITS);
  const payload = serializeRnList([{ rn: "555555", publicKey: forger.publicKey }]);
  info("зловмисник вписує власний RN 555555 зі своїм ключем і підписує список своїм ключем");
  const result = commission.importRnList({ payload, signature: sign(payload, forger.keys.privateKey) }, bureau.publicKey);
  if (!result.ok) fail(color.bold(color.red(`СПИСОК ВІДХИЛЕНО: ${result.error}`)));

  info("підміна: до справжнього підписаного списку дописано RN 555555, підпис БР залишено");
  const tampered = serializeRnList([{ rn: "555555", publicKey: forger.publicKey }, ...parseRnList(genuine.payload)]);
  const second = commission.importRnList({ payload: tampered, signature: genuine.signature }, bureau.publicKey);
  if (!second.ok) fail(color.bold(color.red(`СПИСОК ВІДХИЛЕНО: ${second.error}`)));
}

/* ──────────────────────────────── Кроки 4–5: голосування ──────────────────────────────── */

function votingStage(): void {
  section("КРОКИ 4–5. Голосування: повідомлення (ID; RN; бюлетень), перевірки ВК");
  castVote(voter(0), "К1", `«${voter(0).name}» (RN ${voter(0).rn}) голосує за К1`);
  castVote(voter(1), "К2", `«${voter(1).name}» (RN ${voter(1).rn}) голосує за К2`);
}

function votingNegative(): void {
  section("НЕГАТИВНІ СЦЕНАРІЇ ГОЛОСУВАННЯ");

  step("Сценарій Г1. Невалідний RN: стороння особа вгадує RN 424242");
  const outsider = new Voter("Стороння Мальвіна Олегівна", "ХХ000000", KEY_BITS);
  outsider.acceptRn("424242");
  info("діапазон RN 100000–999999, зареєстровано 5 — шанс вгадати 5 / 900000");
  ballotVerdict(commission.receive(outsider.vote("К2", commission.publicKey).envelope));

  step(`Сценарій Г2. Повторне голосування: «${voter(0).name}» вдруге з тим самим RN`);
  info("новий ID і новий вибір, ЕЦП правильний — але RN уже використаний");
  ballotVerdict(commission.receive(sealFor(voter(0).prepare("К2"), commission.publicKey)));

  step(`Сценарій Г3. Повторний ID: «${voter(2).name}» генерує ID, що збігся з уже прийнятим`);
  info(`ID ${voter(0).castId} уже прийнятий з бюлетенем виборця №1; RN і ЕЦП виборця №3 справжні`);
  ballotVerdict(commission.receive(sealFor(voter(2).prepare("К1", voter(0).castId), commission.publicKey)));

  step(`Сценарій Г4. Неправильний ЕЦП: викрадений RN ${voter(3).rn} підписано чужим ключем`);
  const thief = new Voter("Зловмисник", "—", KEY_BITS);
  thief.acceptRn(voter(3).rn);
  info("RN справжній і не використаний, але закритого ключа власника RN зловмисник не має");
  ballotVerdict(commission.receive(thief.vote("К2", commission.publicKey).envelope));

  step(`Сценарій Г5. Неправильний ЕЦП: підміна бюлетеня «${voter(3).name}» після підписання`);
  const signed = voter(3).prepare("К1");
  const tampered = signed.text.replace('"candidateId":"К1"', '"candidateId":"К2"');
  info(`оригінал: ${signed.text}`);
  info(`підміна:  ${tampered}`);
  ballotVerdict(commission.receive(sealFor({ text: tampered, signature: signed.signature }, commission.publicKey)));

  step(`Сценарій Г6. Зіпсований бюлетень «${voter(4).name}»: кандидата «К9» не існує`);
  info("ЕЦП підтверджує авторство, але не коректність заповнення");
  ballotVerdict(commission.receive(sealFor(voter(4).prepare("К9"), commission.publicKey)));

  step("Сценарій Г7. Повідомлення зашифровано не ключем ВК");
  ballotVerdict(commission.receive(sealFor(voter(4).prepare("К1"), thief.publicKey)));
}

function votingContinued(): void {
  section("ПРОДОВЖЕННЯ ГОЛОСУВАННЯ: відхилені спроби не «спалили» RN");
  castVote(voter(2), "К1", `«${voter(2).name}» голосує з новим ID`);
  castVote(voter(3), "К2", `«${voter(3).name}» голосує власноруч`);
  castVote(voter(4), "К1", `«${voter(4).name}» виправляє зіпсований бюлетень`);

  note("Реєстр ВК після голосування:");
  table(
    ["RN", "Використаний"],
    commission.rnRegister.map((entry) => [entry.rn, entry.used ? color.green("так") : color.red("ні")]),
  );
}

/* ─────────────────────────────── Крок 6: результати ─────────────────────────────── */

function printResults(results: ElectionResults): void {
  const total = results.ballots.length;
  table(
    ["Кандидат", "ПІБ", "Голоси", "Частка"],
    CANDIDATES.map((candidate) => {
      const votes = results.tally.get(candidate.id) ?? 0;
      const share = total === 0 ? 0 : Math.round((votes / total) * 100);
      return [candidate.id, candidate.name, String(votes), `${share}% ${"█".repeat(votes)}`];
    }),
  );
  info(`прийнято бюлетенів: ${total}, відхилено спроб: ${results.rejected}, RN у списку БР: ${results.registered}`);
  if (results.isTie) note(color.bold(color.yellow("НІЧИЯ — переможця не визначено")));
  else if (results.leaders[0]) note(color.bold(color.green(`ПЕРЕМОЖЕЦЬ: ${results.leaders[0].name}`)));

  note("Опубліковано список ID і відповідних підписаних бюлетенів:");
  table(
    ["ID", "Бюлетень", "RN", "ЕЦП виборця"],
    results.ballots.map((ballot) => [
      ballot.id,
      ballot.candidateId,
      parseVoteMessage(ballot.message).rn,
      short(ballot.signature, 10, 4),
    ]),
  );

  const published = bureau.publishVoterList().length;
  const audit = total <= published;
  (audit ? ok : fail)(
    `Контроль за списком БР: бюлетенів ${total} ${audit ? "≤" : ">"} зареєстрованих виборців ${published}` +
      (audit ? "" : " — ТРИВОГА!"),
  );
}

function verifyAll(ballots: readonly PublishedBallot[], label: string): void {
  step(label);
  for (const item of voters) {
    const result = item.verifyPublication(ballots);
    if (result.status === "confirmed") {
      ok(`${item.name}: ID ${result.id} знайдено, бюлетень збігається з власним вибором`);
    } else if (result.status === "missing") {
      fail(color.bold(color.red(`${item.name}: ТРИВОГА! ID ${result.id} відсутній у публікації ВК`)));
    } else {
      fail(
        color.bold(
          color.red(
            `${item.name}: ТРИВОГА! за ID ${result.id} опубліковано «${result.published}», а обрано «${result.expected}»`,
          ),
        ),
      );
    }
  }
}

function resultsStage(): ElectionResults {
  section("КРОК 6. Підрахунок голосів і публікація результатів");
  const results = commission.publishResults();
  printResults(results);

  section("ПЕРЕВІРКА ВИБОРЦЯМИ ВЛАСНИХ ГОЛОСІВ");
  verifyAll(results.ballots, "Позитивний сценарій: виборці перевіряють чесну публікацію ВК");

  const victim = voter(1).castId;
  const forgedPublication = results.ballots.flatMap((ballot) => {
    if (ballot.id === voter(4).castId) return [];
    if (ballot.id !== victim) return [ballot];
    return [{ ...ballot, candidateId: "К1", message: ballot.message.replace('"candidateId":"К2"', '"candidateId":"К1"') }];
  });
  verifyAll(
    forgedPublication,
    "Негативний сценарій: недобросовісна ВК змінила бюлетень виборця №2 і вилучила бюлетень №5",
  );
  return results;
}

/* ─────────────────────────────── Зведення ─────────────────────────────── */

function summary(): void {
  section("Розподіл знань між сторонами протоколу");
  table(
    ["Дані", "БР", "ВК", "Публічно"],
    [
      ["ПІБ і паспорт виборця", color.green("так"), color.red("ні"), "лише ПІБ (список БР)"],
      ["RN виборця", color.green("так"), color.green("так"), "у підписаних бюлетенях"],
      ["Відкритий ключ ЕЦП", color.green("так"), color.green("так"), "ні"],
      ["Зв’язок ПІБ ↔ RN", color.green("так"), color.red("ні"), "ні"],
      ["ID виборця", color.red("ні"), color.green("так"), "так"],
      ["Вміст бюлетеня", color.red("ні"), color.green("так"), "так"],
      ["Зв’язок ПІБ ↔ бюлетень", color.yellow("після публікації"), color.red("ні"), "ні"],
    ],
  );
}

/** Що може зробити БР, маючи власний реєстр і опубліковані ВК підписані бюлетені. */
function deanonymization(ballots: readonly PublishedBallot[]): void {
  section("АНАЛІЗ: деанонімізація з боку БР (або змови БР і ВК)");
  note("Опублікований підписаний бюлетень містить RN, а БР знає, кому видано кожен RN:");
  const owners = new Map(bureau.registry.map((entry) => [entry.rn, entry.name]));
  table(
    ["ПІБ (реєстр БР)", "RN", "ID (публікація ВК)", "Бюлетень"],
    ballots.map((ballot) => {
      const { rn } = parseVoteMessage(ballot.message);
      return [owners.get(rn) ?? "?", rn, ballot.id, ballot.candidateId];
    }),
  );
  fail(color.yellow("Публікація підписаних бюлетенів розкриває RN, тож БР сама зіставляє ПІБ і голос;"));
  fail(color.yellow("при змові ВК передає БР пари (RN; бюлетень) ще під час голосування."));
}

banner("ЛАБОРАТОРНА РОБОТА №3 — РОЗПОДІЛ ПОВНОВАЖЕНЬ МІЖ БР ТА ВК (RSA)");
registrationStage();
registrationNegative();
transferStage();
votingStage();
votingNegative();
votingContinued();
const results = resultsStage();
deanonymization(results.ballots);
summary();
console.log();
