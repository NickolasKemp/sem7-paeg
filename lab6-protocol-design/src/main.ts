import { CorruptBureau, CorruptLowerCommission, CorruptMiddleCommission, decodeByDictionary, type Tamper } from "./attacks.ts";
import { audit, AUDIT_FINDINGS, type AuditFinding } from "./audit.ts";
import { modPow } from "./bigint-math.ts";
import { RegistrationBureau } from "./bureau.ts";
import { CentralCommission, summarize } from "./central-commission.ts";
import { LowerCommission } from "./lower-commission.ts";
import { serialize, type Signed } from "./message.ts";
import { MiddleCommission } from "./middle-commission.ts";
import { encrypt, generateKeyPair, hashMessage, short, type PublicKey } from "./rsa.ts";
import {
  BRANCHES,
  DISTRICTS,
  lowerLabel,
  PART_REJECTIONS,
  REGISTRATION_REFUSALS,
  RESULT_REJECTIONS,
  type BallotPart,
  type Batch,
  type Branch,
  type Citizen,
  type District,
  type ElectionResults,
  type LowerLabel,
  type Observer,
  type PartResult,
  type RegistrationResult,
} from "./types.ts";
import { banner, color, fail, info, note, ok, section, step, table } from "./ui.ts";
import { isCountedCorrectly, isIncluded, Voter, type Receipt } from "./voter.ts";

/**
 * Демонстрація спроєктованого протоколу: БР (сліпий ЕЦП мандатів), 4 ДВК у двох гілках,
 * 2 СВК, ЦВК (об'єднання частин бюлетеня і розшифрування), публічний аудит.
 * Перша сесія — штатне голосування з негативними сценаріями, друга — атаки організаторів.
 */

const KEY_BITS = 512;
const ELECTION_DATE = "2026-11-15";

const CANDIDATE_NAMES = ["Іваненко Іван Іванович", "Петренко Петро Петрович", "Сидоренко Олена Василівна"] as const;

const CITIZENS: readonly Citizen[] = [
  { name: "Коваленко Андрій Сергійович", passport: "АА100001", birthDate: "1990-03-12", district: 1 },
  { name: "Шевченко Олена Миколаївна", passport: "АА100002", birthDate: "1985-07-01", district: 1 },
  { name: "Бондаренко Богдан Юрійович", passport: "АА100003", birthDate: "2001-11-20", district: 1 },
  { name: "Ткаченко Марія Василівна", passport: "АА100004", birthDate: "1978-02-14", district: 1 },
  { name: "Мельник Остап Ігорович", passport: "ВВ200001", birthDate: "1995-05-05", district: 2 },
  { name: "Кравченко Ірина Олегівна", passport: "ВВ200002", birthDate: "1999-09-09", district: 2 },
  { name: "Олійник Тарас Петрович", passport: "ВВ200003", birthDate: "1969-12-30", district: 2 },
  { name: "Лисенко Дарина Андріївна", passport: "ВВ200004", birthDate: "2003-04-18", district: 2 },
  { name: "Савченко Максим Ігорович", passport: "ВВ200005", birthDate: "2009-01-10", district: 2 },
];
const ELIGIBLE = CITIZENS.slice(0, 8);
const UNDERAGE = CITIZENS[8]!;

const CHECK_LABELS: Record<string, string> = {
  inRoll: "Реєстр громадян",
  identity: "Звірка ПІБ",
  votingRight: "Право голосу",
  district: "Виборча дільниця",
  once: "Одноразовість",
  commission: "Адреса частини",
  eligibility: "Сліпий ЕЦП БР на мандаті",
  signature: "ЕЦП виборця",
  sender: "Відправник пакета",
  batchSignature: "ЕЦП пакета",
  part: "Повторна перевірка частин",
  appeal: "Скарга виборця",
};

let echo = true;
const observer: Observer = (event) => {
  if (echo) (event.passed ? ok : fail)(`[${event.actor}] ${CHECK_LABELS[event.check] ?? event.check}: ${event.detail}`);
};

const hex = (value: bigint) => {
  const digits = value.toString(16);
  return digits.length <= 12 ? `0x${digits}` : `0x${digits.slice(0, 6)}…${digits.slice(-4)}`;
};
const shortId = (voterId: bigint) => `${voterId.toString().slice(0, 6)}…`;
const initials = (name: string) => {
  const [surname, ...rest] = name.split(" ");
  return [surname, ...rest.map((part) => `${part.charAt(0)}.`)].join(" ");
};
const mark = (passed: boolean) => (passed ? color.green("✔") : color.red("✘"));

type Network = {
  bureau: RegistrationBureau;
  lower: Readonly<Record<LowerLabel, LowerCommission>>;
  middle: Readonly<Record<Branch, MiddleCommission>>;
  cvk: CentralCommission;
};

type Corruption = {
  bureau?: true;
  lower?: Partial<Record<LowerLabel, Tamper>>;
  middle?: Partial<Record<Branch, Tamper>>;
};

function setupNetwork(corruption: Corruption = {}): Network {
  const bureauOptions = { citizens: CITIZENS, electionDate: ELECTION_DATE, bits: KEY_BITS, observer };
  const bureau = corruption.bureau ? new CorruptBureau(bureauOptions) : new RegistrationBureau(bureauOptions);
  const bureauKeys = bureau.publicKeys;

  const makeLower = (branch: Branch, district: District) => {
    const options = { branch, district, bureauKeys, bits: KEY_BITS, observer };
    const tamper = corruption.lower?.[lowerLabel(branch, district)];
    return tamper ? new CorruptLowerCommission(options, tamper) : new LowerCommission(options);
  };
  const lower = {
    "ДВК-1.1": makeLower(1, 1),
    "ДВК-1.2": makeLower(1, 2),
    "ДВК-2.1": makeLower(2, 1),
    "ДВК-2.2": makeLower(2, 2),
  };

  const makeMiddle = (branch: Branch) => {
    const lowerKeys = { 1: lower[lowerLabel(branch, 1)].publicKey, 2: lower[lowerLabel(branch, 2)].publicKey };
    const options = { branch, lowerKeys, bureauKeys, bits: KEY_BITS, observer };
    const tamper = corruption.middle?.[branch];
    return tamper ? new CorruptMiddleCommission(options, tamper) : new MiddleCommission(options);
  };
  const middle = { 1: makeMiddle(1), 2: makeMiddle(2) };

  const cvk = new CentralCommission({
    candidateNames: CANDIDATE_NAMES,
    bureauKeys,
    middleKeys: { 1: middle[1].publicKey, 2: middle[2].publicKey },
    bits: KEY_BITS,
  });
  return { bureau, lower, middle, cvk };
}

function register(network: Network, voter: Voter): RegistrationResult {
  const key = network.bureau.publicKey(voter.citizen.district);
  const result = network.bureau.register(voter.requestRegistration(key));
  voter.completeRegistration(result, key);
  return result;
}

function registrationVerdict(result: RegistrationResult): void {
  if (result.status === "registered") ok(color.green("БР: сліпий ЕЦП поставлено, мандат видано"));
  else fail(color.bold(color.red(`БР: ВІДМОВА [${result.reason}] ${REGISTRATION_REFUSALS[result.reason]}`)));
}

const commissionFor = (network: Network, part: BallotPart, district: District = part.credential.district) =>
  network.lower[lowerLabel(part.branch, district)];

function partVerdict(label: string, result: PartResult): void {
  if (result.status === "accepted") ok(color.green(`${label}: частину прийнято`));
  else fail(color.bold(color.red(`${label}: ВІДХИЛЕНО [${result.reason}] ${PART_REJECTIONS[result.reason]}`)));
}

function deliver(network: Network, receipt: Receipt): readonly PartResult[] {
  return receipt.parts.map((part) => {
    const commission = commissionFor(network, part);
    const result = commission.receive(part);
    if (echo) partVerdict(commission.label, result);
    return result;
  });
}

function showBallot(receipt: Receipt, cvkKey: PublicKey): void {
  const [m1, m2] = receipt.split;
  info(`бюлетень m = ID кандидата = ${receipt.candidateId}`);
  info(`m₁ — випадкове з Z*ₙ: ${short(m1, 10, 4)};  m₂ = m · m₁⁻¹ mod n: ${short(m2, 10, 4)}`);
  info(`перевірка поділу: m₁ · m₂ mod n = ${(m1 * m2) % cvkKey.n}`);
  receipt.parts.forEach((part, index) => {
    const sub = "₁₂".charAt(index);
    info(`C${sub} = m${sub}ᵉ mod n = ${short(part.encryptedPart, 10, 4)};  ЕЦП ключем мандата = ${short(part.signature, 10, 4)}`);
  });
}

type Voted = { readonly voter: Voter; readonly receipt: Receipt };

function castVote(network: Network, voter: Voter, candidateId: bigint, verbose: boolean): Voted {
  const receipt = voter.vote(candidateId, network.cvk.publicKey);
  if (verbose) {
    step(`${voter.name} (дільниця №${voter.citizen.district}) голосує за ID ${candidateId}`);
    showBallot(receipt, network.cvk.publicKey);
  }
  echo = verbose;
  deliver(network, receipt);
  echo = true;
  return { voter, receipt };
}

const publishLower = (network: Network) => Object.values(network.lower).map((commission) => commission.publish());

function collectAll(network: Network, lowerPublications: readonly Signed<Batch>[]): void {
  for (const branch of BRANCHES) {
    for (const district of DISTRICTS) {
      const publication = lowerPublications.find((batch) => batch.body.from === lowerLabel(branch, district));
      if (publication) network.middle[branch].collect(publication);
    }
  }
}

function printInclusion(voted: readonly Voted[], lower: readonly Signed<Batch>[], middle: readonly Signed<Batch>[]): void {
  const find = (list: readonly Signed<Batch>[], label: string) => list.find((batch) => batch.body.from === label);
  table(
    ["Виборець", "Дільн.", "ДВК-1.x", "ДВК-2.x", "СВК-1", "СВК-2"],
    voted.map(({ voter, receipt }) => {
      const district = voter.citizen.district;
      const check = (batch: Signed<Batch> | undefined) => mark(batch !== undefined && isIncluded(receipt, batch));
      return [
        voter.name,
        String(district),
        check(find(lower, lowerLabel(1, district))),
        check(find(lower, lowerLabel(2, district))),
        check(find(middle, "СВК-1")),
        check(find(middle, "СВК-2")),
      ];
    }),
  );
}

function printRows(results: ElectionResults): void {
  table(
    ["ID виборця", "Дільн.", "C₁ (СВК-1)", "C₂ (СВК-2)", "C = C₁·C₂ mod n", "m = Cᵈ mod n", "Статус"],
    results.rows.map((row) => [
      shortId(row.voterId),
      String(row.district),
      row.parts[0] === undefined ? color.red("—") : hex(row.parts[0]),
      row.parts[1] === undefined ? color.red("—") : hex(row.parts[1]),
      "combined" in row ? hex(row.combined) : "—",
      "ballot" in row ? color.bold(row.ballot.toString().length > 6 ? hex(row.ballot) : String(row.ballot)) : "—",
      row.status === "accepted" ? color.green("✔ прийнято") : color.red(`✘ ${row.reason}`),
    ]),
  );
  for (const row of results.rows) {
    if (row.status === "rejected") fail(color.red(`ID ${shortId(row.voterId)}: ${RESULT_REJECTIONS[row.reason]}`));
  }
  for (const entry of results.excluded) {
    fail(color.red(`ЦВК відкинула частину від ${entry.from}, ID ${shortId(entry.voterId)} [${entry.reason}]`));
  }
}

function printTally(network: Network, results: ElectionResults): void {
  table(
    ["ID", "Кандидат", "Дільниця №1", "Дільниця №2", "Разом"],
    network.cvk.candidates.map((candidate) => {
      const total = results.tally.get(candidate.id) ?? 0;
      return [
        String(candidate.id),
        candidate.name,
        String(results.byDistrict[1].get(candidate.id) ?? 0),
        String(results.byDistrict[2].get(candidate.id) ?? 0),
        `${total} ${"█".repeat(total)}`,
      ];
    }),
  );
  const max = Math.max(...results.tally.values());
  const leaders = network.cvk.candidates.filter((candidate) => results.tally.get(candidate.id) === max);
  if (leaders.length === 1) note(color.bold(color.green(`ПЕРЕМОЖЕЦЬ: ${leaders[0]!.name} (ID ${leaders[0]!.id})`)));
  else note(color.bold(color.yellow(`НІЧИЯ між: ${leaders.map((leader) => leader.name).join(", ")}`)));
}

function printResultChecks(voted: readonly Voted[], results: ElectionResults): void {
  table(
    ["Виборець", "Мій ID", "Голосував за", "ЦВК опублікувала", "Перевірка"],
    voted.map(({ voter, receipt }) => {
      const row = results.rows.find((entry) => entry.voterId === receipt.voterId);
      const shown = row && "ballot" in row ? (row.ballot.toString().length > 6 ? hex(row.ballot) : String(row.ballot)) : "—";
      const correct = isCountedCorrectly(receipt, results);
      return [voter.name, shortId(receipt.voterId), String(receipt.candidateId), shown, correct ? color.green("✔ збігається") : color.red("✘ НЕ збігається")];
    }),
  );
}

function printAudit(findings: readonly AuditFinding[]): void {
  const checks = Object.entries(AUDIT_FINDINGS) as [AuditFinding["kind"], string][];
  table(
    ["Перевірка публічного аудиту", "Результат"],
    checks.map(([kind, description]) => {
      const hits = findings.filter((finding) => finding.kind === kind);
      const details = hits.map((hit) => hit.detail.replace(/\d{10,}/g, (digits) => `${digits.slice(0, 6)}…`)).join("; ");
      return [description, hits.length === 0 ? color.green("✔ порушень немає") : color.red(`✘ ${details}`)];
    }),
  );
}

function publicAudit(network: Network, lower: readonly Signed<Batch>[], middle: readonly Signed<Batch>[], results: ElectionResults) {
  return audit({
    lower,
    middle,
    results,
    registered: network.bureau.publishRegistered(),
    candidates: network.cvk.candidates,
    bureauKeys: network.bureau.publicKeys,
    cvkKey: network.cvk.publicKey,
  });
}

function mainSession(): void {
  banner("ЛАБОРАТОРНА РОБОТА №6 — ПРОЄКТУВАННЯ ПРОТОКОЛУ Е-ГОЛОСУВАННЯ");
  section("КРОК 0. Учасники протоколу та опубліковані відкриті ключі");
  const network = setupNetwork();
  const { bureau, cvk } = network;
  table(
    ["Учасник", "Функція", "Опубліковано"],
    [
      ["БР", "реєстрація, сліпий ЕЦП мандатів", `ключ дільниці №1: n = ${hex(bureau.publicKey(1).n)}; №2: n = ${hex(bureau.publicKey(2).n)}`],
      ...Object.values(network.lower).map((commission) => [
        commission.label,
        `прийом частини ${commission.branch}, дільниця №${commission.district}`,
        `ключ ЕЦП пакетів: n = ${hex(commission.publicKey.n)}`,
      ]),
      ...BRANCHES.map((branch) => [
        network.middle[branch].label,
        `зведення гілки ${branch} від ДВК-${branch}.1, ДВК-${branch}.2`,
        `ключ ЕЦП пакетів: n = ${hex(network.middle[branch].publicKey.n)}`,
      ]),
      ["ЦВК", "кандидати, об'єднання, розшифрування", `ключ шифрування: e = ${cvk.publicKey.e}, n = ${hex(cvk.publicKey.n)}`],
    ],
  );
  note("ЦВК публікує список кандидатів:");
  table(["ID", "Кандидат"], cvk.candidates.map((candidate) => [String(candidate.id), candidate.name]));

  section("КРОК 1. Реєстрація у БР: перевірка особи і сліпий ЕЦП на анонімному мандаті");
  const voters = ELIGIBLE.map((citizen) => new Voter(citizen, KEY_BITS));
  const first = voters[0]!;
  step(`${first.name}: мандат = (випадковий ID, власний відкритий ключ ЕЦП)`);
  const key = bureau.publicKey(1);
  const request = first.requestRegistration(key);
  info(`маскування: H' = H · rᵉ mod n = ${short(request.blindedToken, 10, 4)} — БР бачить лише H'`);
  const result = bureau.register(request);
  registrationVerdict(result);
  if (result.status === "registered") info(`S' = (H')ᵈ mod n = ${short(result.blindSignature, 10, 4)}`);
  const unblinded = first.completeRegistration(result, key);
  info(`зняття маски S = S' · r⁻¹ mod n; перевірка Sᵉ mod n = H(мандат): ${unblinded ? "так" : "ні"}`);
  info(`H(мандат) = ${short(hashMessage(serialize(first.credential!.token), key.n), 10, 4)} ≠ H' — БР не знає, який мандат підписала`);

  echo = false;
  const rest = voters.slice(1).map((voter) => [voter, register(network, voter)] as const);
  echo = true;
  table(
    ["Виборець", "Дільниця", "Результат"],
    rest.map(([voter, outcome]) => [voter.name, String(voter.citizen.district), outcome.status === "registered" ? color.green("✔ мандат отримано") : color.red(outcome.reason)]),
  );

  step("Негативні сценарії реєстрації");
  const attempts: readonly (readonly [string, Citizen])[] = [
    ["Особа відсутня в реєстрі громадян", { name: "Стороння Мальвіна Олегівна", passport: "ХХ999999", birthDate: "1990-01-01", district: 1 }],
    ["Чужий паспорт: інше ПІБ", { ...CITIZENS[0]!, name: "Підставний Петро Петрович" }],
    ["Неповнолітній громадянин", UNDERAGE],
    ["Запит мандата іншої дільниці", { ...CITIZENS[4]!, district: 1 }],
    ["Повторна реєстрація", CITIZENS[0]!],
  ];
  for (const [label, citizen] of attempts) {
    note(color.bold(`  ${label}: «${citizen.name}», ${citizen.passport}`));
    const impostor = new Voter(citizen, KEY_BITS);
    registrationVerdict(bureau.register(impostor.requestRegistration(bureau.publicKey(citizen.district))));
  }
  const registered = bureau.publishRegistered();
  note("БР публікує списки зареєстрованих по дільницях (без мандатів):");
  table(["Дільниця", "Зареєстровано", "Виборці"], DISTRICTS.map((district) => [String(district), String(registered[district].length), registered[district].map(initials).join(", ")]));

  section("КРОК 2. Голосування: поділ бюлетеня, шифрування ключем ЦВК, ЕЦП, перевірки ДВК");
  const ids = cvk.candidates.map((candidate) => candidate.id);
  const choices = [ids[0]!, ids[1]!, ids[0]!, ids[2]!, ids[1]!, ids[0]!, ids[0]!, ids[1]!];
  const voted = [castVote(network, voters[0]!, choices[0]!, true), castVote(network, voters[4]!, choices[4]!, true)];

  section("НЕГАТИВНІ СЦЕНАРІЇ ПЕРЕВІРОК ДВК");
  const target = voters[1]!;
  step("Сценарій 1. Стороння особа підписує мандат власним ключем замість БР");
  const fakeKeys = generateKeyPair(KEY_BITS);
  const stranger = new Voter({ name: "Стороння Мальвіна Олегівна", passport: "ХХ999999", birthDate: "1990-01-01", district: 1 }, KEY_BITS);
  const strangerRequest = stranger.requestRegistration(fakeKeys.publicKey);
  stranger.completeRegistration({ status: "registered", blindSignature: modPow(strangerRequest.blindedToken, fakeKeys.privateKey.d, fakeKeys.privateKey.n) }, fakeKeys.publicKey);
  info("мандат з ЕЦП, що перевіряється лише її власним ключем, а не ключем БР дільниці №1");
  deliver(network, stranger.vote(ids[1]!, cvk.publicKey));

  step(`Сценарій 2. Перехоплений мандат «${target.name}» з підписом ключем зловмисника`);
  const thief = new Voter({ ...target.citizen, name: "Зловмисник" }, KEY_BITS);
  const stolen = thief.signPart({ credential: target.credential!, branch: 1, encryptedPart: encrypt(ids[2]!, cvk.publicKey) });
  info("ЕЦП БР на мандаті справжній, але закритого ключа з мандата має лише його власник");
  partVerdict("ДВК-1.1", network.lower["ДВК-1.1"].receive(stolen));

  step("Сценарій 3. Підміна зашифрованої частини по дорозі до ДВК");
  const honest = target.vote(choices[1]!, cvk.publicKey);
  const [part1, part2] = honest.parts;
  const forged: BallotPart = { ...part1, encryptedPart: encrypt(ids[2]!, cvk.publicKey) };
  info(`оригінал C₁ = ${hex(part1.encryptedPart)}, підміна C₁' = RSA(${ids[2]}) = ${hex(forged.encryptedPart)}`);
  partVerdict("ДВК-1.1", network.lower["ДВК-1.1"].receive(forged));
  info("виборець надсилає оригінальні частини:");
  partVerdict("ДВК-1.1", network.lower["ДВК-1.1"].receive(part1));
  partVerdict("ДВК-2.1", network.lower["ДВК-2.1"].receive(part2));
  voted.splice(1, 0, { voter: target, receipt: honest });

  step("Сценарій 4. Частина не за адресою: інша гілка, інша дільниця, підроблена дільниця");
  const third = voters[2]!.vote(choices[2]!, cvk.publicKey);
  echo = false;
  const wrongBranch = network.lower["ДВК-2.1"].receive(third.parts[0]);
  const wrongDistrict = network.lower["ДВК-1.2"].receive(third.parts[0]);
  const fakeDistrict = network.lower["ДВК-1.2"].receive({ ...third.parts[0], credential: { ...third.parts[0].credential, district: 2 } });
  echo = true;
  partVerdict("частина 1 → ДВК-2.1", wrongBranch);
  partVerdict("частина 1 дільниці №1 → ДВК-1.2", wrongDistrict);
  partVerdict("мандат з дільницею №2 → ДВК-1.2", fakeDistrict);
  echo = false;
  deliver(network, third);
  echo = true;
  voted.push({ voter: voters[2]!, receipt: third });
  info("потім виборець надсилає частини за правильними адресами — прийнято");

  step(`Сценарій 5. Повторне голосування «${first.name}»`);
  deliver(network, first.vote(ids[2]!, cvk.publicKey));

  section("ПРОДОВЖЕННЯ ГОЛОСУВАННЯ");
  for (const index of [3, 5, 6, 7]) voted.push(castVote(network, voters[index]!, choices[index]!, false));
  table(
    ["Виборець", "Дільниця", "Частина 1 →", "Частина 2 →", "Статус"],
    voted.slice(3).map(({ voter }) => [voter.name, String(voter.citizen.district), lowerLabel(1, voter.citizen.district), lowerLabel(2, voter.citizen.district), color.green("✔ обидві прийнято")]),
  );

  section("КРОК 3. ДВК публікують підписані пакети і передають їх до СВК");
  const lower = publishLower(network);
  table(
    ["ДВК", "Частин", "ЕЦП пакета", "Приклад запису: ID → C"],
    lower.map((batch) => {
      const sample = batch.body.parts[0];
      return [batch.body.from, String(batch.body.parts.length), hex(batch.signature), sample ? `${shortId(sample.credential.token.voterId)} → ${hex(sample.encryptedPart)}` : "—"];
    }),
  );
  collectAll(network, lower);

  section("КРОК 4. СВК публікують зведені пакети і передають їх до ЦВК; виборці звіряють публікації");
  const middle = BRANCHES.map((branch) => network.middle[branch].publish());
  info(`СВК-1: ${middle[0]!.body.parts.length} частин, СВК-2: ${middle[1]!.body.parts.length} частин`);
  printInclusion(voted, lower, middle);

  section("КРОК 5. ЦВК: перевірка пакетів і частин, об'єднання C₁·C₂, розшифрування, підрахунок");
  const results = cvk.count(middle);
  printRows(results);
  printTally(network, results);

  section("КРОК 6. Перевірка: кожен виборець звіряє свій голос, будь-хто проводить публічний аудит");
  printResultChecks(voted, results);
  printAudit(publicAudit(network, lower, middle, results));
}

/** Нечесні учасники змінюють лише свої публікації — підписати чужі дані вони не можуть. */
function attackSession(): void {
  banner("АТАКИ ОРГАНІЗАТОРІВ ГОЛОСУВАННЯ ТА ЇХ ВИЯВЛЕННЯ");
  const voters = ELIGIBLE.map((citizen) => new Voter(citizen, KEY_BITS));
  const [kovalenko, , , tkachenko, melnyk, kravchenko, oliinyk] = voters as [Voter, Voter, Voter, Voter, Voter, Voter, Voter];
  const id = (voter: Voter) => voter.credential!.token.voterId;

  let ghostPart: BallotPart | undefined;
  const network = setupNetwork({
    bureau: true,
    lower: {
      "ДВК-1.1": (parts) => parts.map((part) => (part.credential.token.voterId === id(kovalenko) ? { ...part, encryptedPart: encrypt(103n, network.cvk.publicKey) } : part)),
      "ДВК-1.2": (parts) => (ghostPart ? [...parts, ghostPart] : parts),
      "ДВК-2.2": (parts) => parts.filter((part) => part.credential.token.voterId !== id(melnyk)),
    },
    middle: {
      2: (parts) => parts.map((part) => (part.credential.token.voterId === id(kravchenko) ? { ...part, encryptedPart: encrypt(102n, network.cvk.publicKey) } : part)),
    },
  });
  const bureau = network.bureau as CorruptBureau;
  echo = false;
  for (const voter of voters) register(network, voter);

  const ids = network.cvk.candidates.map((candidate) => candidate.id);
  const plan: readonly (readonly [Voter, bigint])[] = [
    [voters[0]!, ids[0]!], [voters[1]!, ids[0]!], [voters[2]!, ids[1]!], [voters[3]!, ids[0]!],
    [voters[4]!, ids[1]!], [voters[5]!, ids[0]!], [voters[6]!, ids[2]!],
  ];
  const voted = plan.map(([voter, candidateId]) => castVote(network, voter, candidateId, false));
  echo = true;

  section("Сценарій A. Нечесна БР видає мандати «мертвим душам»");
  const ghosts = ([1, 2] as const).map((district) => {
    const ghost = new Voter({ name: `Привид дільниці №${district}`, passport: "—", birthDate: "1900-01-01", district }, KEY_BITS);
    const key = bureau.publicKey(district);
    ghost.completeRegistration(bureau.issueGhost(ghost.requestRegistration(key)), key);
    return ghost;
  });
  info("дільниця №1: проголосували всі 4 зареєстровані — привид стає п'ятим бюлетенем");
  info("дільниця №2: Лисенко Д. А. зареєструвалася, але не голосує — її місце займає привид");
  for (const ghost of ghosts) {
    echo = false;
    deliver(network, ghost.vote(ids[1]!, network.cvk.publicKey));
    echo = true;
  }
  fail("ДВК приймають частини привидів: мандати мають справжній сліпий ЕЦП БР");

  section("Сценарій B. ДВК-1.2 вкидає частину з підробленим мандатом");
  const outsider = new Voter({ name: "Вкинутий", passport: "—", birthDate: "1900-01-01", district: 2 }, KEY_BITS);
  const fakeBureau = generateKeyPair(KEY_BITS);
  const outsiderRequest = outsider.requestRegistration(fakeBureau.publicKey);
  outsider.completeRegistration({ status: "registered", blindSignature: modPow(outsiderRequest.blindedToken, fakeBureau.privateKey.d, fakeBureau.privateKey.n) }, fakeBureau.publicKey);
  ghostPart = outsider.vote(ids[1]!, network.cvk.publicKey).parts[0];
  info("ДВК підписує власний пакет, але сліпого ЕЦП БР під чужим мандатом підробити не може");

  section("Сценарій C. ДВК-1.1 підміняє частину Коваленка А. С., ДВК-2.2 «губить» частину Мельника О. І.");
  const lower = publishLower(network);
  collectAll(network, lower);
  note("Виборці звіряють публікації своїх ДВК і подають скарги до СВК з власною підписаною частиною:");
  for (const { voter, receipt } of voted.filter(({ voter }) => voter === kovalenko || voter === melnyk)) {
    const missing = receipt.parts.find((part) => !isIncluded(receipt, lower.find((batch) => batch.body.from === commissionFor(network, part).label)!));
    if (!missing) continue;
    fail(`${voter.name}: своєї частини ${missing.branch} у публікації ${commissionFor(network, missing).label} не знайдено`);
    network.middle[missing.branch].appeal(missing);
  }

  section("Сценарій D. СВК-2 підміняє частину Кравченко І. О. у зведеному пакеті");
  const middle = BRANCHES.map((branch) => network.middle[branch].publish());
  info("СВК-2 підписує пакет своїм ключем, але ЕЦП виборця під частиною перерахувати не може");
  printInclusion(voted, lower, middle);

  section("Сценарій E. Нечесна ЦВК: змінює голос Ткаченко М. В. і «губить» бюлетень Олійника Т. П.");
  const honest = network.cvk.count(middle);
  const rows = honest.rows
    .filter((row) => row.voterId !== id(oliinyk))
    .map((row) => (row.voterId === id(tkachenko) && row.status === "accepted" ? { ...row, ballot: ids[1]! } : row));
  info("підсумки перераховано узгоджено зі зміненими рядками — арифметика публікації сходиться");
  const rigged: ElectionResults = { ...honest, rows, ...summarize(rows, network.cvk.candidates) };
  printRows(rigged);
  printTally(network, rigged);

  section("Виявлення: виборці звіряють результати, спостерігачі проводять публічний аудит");
  printResultChecks(voted, rigged);
  printAudit(publicAudit(network, lower, middle, rigged));
  note(color.yellow("Не виявлено: привид дільниці №2 скористався правом зареєстрованої виборниці, яка не голосувала."));
}

/** Спроби пов'язати особу виборця з його голосом. */
function linkingSession(): void {
  banner("СПРОБИ ВСТАНОВИТИ ЗВ'ЯЗОК «ВИБОРЕЦЬ — ГОЛОС»");
  const network = setupNetwork({ bureau: true });
  const voters = ELIGIBLE.slice(0, 4).map((citizen) => new Voter(citizen, KEY_BITS));
  echo = false;
  for (const voter of voters) register(network, voter);
  const receipts = voters.map((voter, index) => castVote(network, voter, 101n + BigInt(index % 3), false).receipt);
  echo = true;

  section("Сценарій F. ДВК перебирає можливі значення своєї частини відкритим ключем ЦВК");
  const maxId = network.cvk.candidates.at(-1)!.id;
  table(
    ["ID виборця", "C₁ у ДВК-1.1", "Підібране mᵢ ≤ " + maxId, "C₁ = RSA(ID кандидата)?"],
    receipts.map((receipt) => {
      const cipher = receipt.parts[0].encryptedPart;
      const decoded = decodeByDictionary(cipher, network.cvk.publicKey, maxId);
      const isCandidate = network.cvk.candidates.some((candidate) => encrypt(candidate.id, network.cvk.publicKey) === cipher);
      return [shortId(receipt.voterId), hex(cipher), decoded === undefined ? color.green("не знайдено") : color.red(String(decoded)), isCandidate ? color.red("так") : color.green("ні")];
    }),
  );
  info("m₁ рівномірно випадкове в Z*ₙ, тому RSA(m₁) не корелює з вибором; перебір 2⁵¹² значень неможливий");

  section("Сценарій G. Змова БР і ЦВК: зіставлення записів реєстрації з ID виборців у результатах");
  const bureau = network.bureau as CorruptBureau;
  const registry = bureau.leakRegistry();
  const key = bureau.publicKey(1);
  const tokenHashes = voters.map((voter) => hashMessage(serialize(voter.credential!.token), key.n));
  table(
    ["Запис БР: ПІБ", "H' (бачила БР)", "Збіг з H(мандат) будь-кого в результатах"],
    registry.map((entry) => [entry.name, hex(entry.blindedToken), tokenHashes.includes(entry.blindedToken) ? color.red("так") : color.green("немає")]),
  );
  info("для будь-якої пари (H', H) існує r: H' = H · rᵉ mod n — будь-яке зіставлення однаково ймовірне");
  info("зв'язок «особа — мандат» знає лише виборець, який зберігає r");
}

/** Зведення: як протокол забезпечує вимоги і що лишається поза його захистом. */
function propertySummary(): void {
  section("Властивості спроєктованого протоколу");
  table(
    ["Вимога / загроза", "Стан", "Механізм"],
    [
      ["Голосують лише ті, хто має право", color.green("забезпечено"), "перевірки БР + сліпий ЕЦП БР на мандаті"],
      ["Не більше одного голосу", color.green("забезпечено"), "один мандат на особу; відмітка в ДВК; ключ дільниці"],
      ["Таємниця голосу", color.green("забезпечено"), "сліпий підпис; частини випадкові в Z*ₙ"],
      ["Неможливо голосувати за іншого", color.green("забезпечено"), "ЕЦП частини закритим ключем з мандата"],
      ["Зміна бюлетеня без виявлення", color.green("неможлива"), "ЕЦП виборця; повторні перевірки СВК, ЦВК"],
      ["Перевірка свого голосу", color.green("забезпечено"), "квитанція + публікації ДВК, СВК, ЦВК"],
      ["Вкидання голосів комісіями", color.green("запобігається"), "без ЕЦП БР частину не приймуть"],
      ["Підміна / втрата частини ДВК", color.yellow("виявляється"), "СВК відкидає; скарга виборця відновлює"],
      ["Нечесна ЦВК", color.yellow("виявляється"), "аудит mᵉ mod n = C₁·C₂; перевірка виборцем"],
      ["«Мертві душі» від БР", color.yellow("частково"), "виявляється, лише якщо бюлетенів > зареєстрованих"],
      ["Продаж голосу / примус", color.red("не захищено"), "квитанція доводить вибір"],
      ["Аналіз трафіку і часу", color.red("не захищено"), "потрібен анонімний канал"],
    ],
  );
}

mainSession();
attackSession();
linkingSession();
propertySummary();
console.log();
