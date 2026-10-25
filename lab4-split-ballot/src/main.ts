import { decodeByDictionary } from "./attacks.ts";
import { CentralCommission } from "./central-commission.ts";
import { PartCommission, type VkEvent } from "./part-commission.ts";
import { decrypt, encrypt, multiplyCiphers, short, type PublicKey } from "./rsa.ts";
import { candidatesSharing, factorPairs, hidingSplits, type Split } from "./split.ts";
import {
  CVK_REJECTIONS,
  PART_COMMISSIONS,
  VK_REJECTIONS,
  type BallotPart,
  type CombinedBallot,
  type ElectionResults,
  type PartMessage,
  type VkResult,
} from "./types.ts";
import { checkPublications, checkResult, Voter, type Ballot, type Receipt } from "./voter.ts";
import { banner, color, fail, info, note, ok, section, step, table } from "./ui.ts";

/**
 * Демонстрація протоколу Е-голосування з розділенням бюлетеня між ВК-1 та ВК-2:
 * 2 кандидати, 5 виборців, RSA для шифрування частин бюлетеня та ЕЦП.
 * Показані позитивні й негативні сценарії перевірок, а також атаки нечесних комісій.
 */

const KEY_BITS = 512;

const CANDIDATE_NAMES = ["Іваненко Іван Іванович", "Петренко Петро Петрович"] as const;

const VOTER_NAMES = [
  "Коваленко Андрій Сергійович",
  "Шевченко Олена Миколаївна",
  "Бондаренко Богдан Юрійович",
  "Ткаченко Марія Василівна",
  "Мельник Остап Ігорович",
] as const;

const CHECK_LABELS: Record<VkEvent["check"], string> = {
  inList: "Наявність у списку виборців",
  signature: "Перевірка ЕЦП відкритим ключем виборця",
  notVotedYet: "Перевірка повторного надсилання",
};

const observer = (event: VkEvent) =>
  (event.passed ? ok : fail)(`[${event.commission}] ${CHECK_LABELS[event.check]}: ${event.detail}`);

const hex = (value: bigint) => {
  const digits = value.toString(16);
  return digits.length <= 12 ? `0x${digits}` : `0x${digits.slice(0, 6)}…${digits.slice(-4)}`;
};

const formatSplit = (split: Split) => `${split[0]} × ${split[1]}`;

type Session = {
  cvk: CentralCommission;
  commissions: readonly [PartCommission, PartCommission];
  voters: Voter[];
};

/** Крок 1: ключі виборців, список ЦВК, ID кандидатів, передача списку до ВК-1 та ВК-2. */
function setupSession(verbose: boolean): Session {
  const cvk = new CentralCommission({ candidateNames: CANDIDATE_NAMES, bits: KEY_BITS });
  const voters = VOTER_NAMES.map((name) => new Voter(name, KEY_BITS));
  for (const voter of voters) cvk.registerVoter(voter.name, voter.publicKey);

  const commissions = [
    new PartCommission("ВК-1", verbose ? observer : undefined),
    new PartCommission("ВК-2", verbose ? observer : undefined),
  ] as const;
  for (const commission of commissions) commission.loadVoterList(cvk.voterList());

  return { cvk, commissions, voters };
}

function verdict(result: VkResult, commission: string): void {
  if (result.status === "accepted") {
    ok(color.green(`${commission}: частину бюлетеня прийнято та збережено разом з ID`));
  } else {
    fail(color.bold(color.red(`${commission}: ВІДХИЛЕНО [${result.reason}] ${VK_REJECTIONS[result.reason]}`)));
  }
}

function deliver(session: Session, messages: readonly [PartMessage, PartMessage]): void {
  session.commissions.forEach((commission, index) => verdict(commission.receive(messages[index]!), commission.label));
}

function showBallot(ballot: Ballot, cvkKey: PublicKey): void {
  const { receipt, messages } = ballot;
  info(`ID виборця (згенерований самостійно, 64 біти): ${receipt.voterId}`);
  info(`поділ ID кандидата на множники: ${receipt.candidateId} = ${formatSplit(receipt.split)}`);
  receipt.split.forEach((factor, index) => {
    info(`бюлетень ${index + 1}: RSA(${factor}) = ${factor}^${cvkKey.e} mod n → ${short(receipt.encryptedParts[index]!, 10, 4)}`);
  });
  messages.forEach((message, index) => {
    info(`ЕЦП(RSA(EVP${index + 1}), ID) → ${short(message.part.signature, 10, 4)}  ⇒ ${PART_COMMISSIONS[index]}`);
  });
}

function castVote(session: Session, voter: Voter, candidateId: bigint, label: string): Voted {
  step(label);
  const ballot = voter.vote(candidateId, session.cvk.candidateIds, session.cvk.publicKey);
  showBallot(ballot, session.cvk.publicKey);
  deliver(session, ballot.messages);
  return { voter, receipt: ballot.receipt };
}

function publications(session: Session): readonly [BallotPart[], BallotPart[]] {
  return [session.commissions[0].publish(), session.commissions[1].publish()];
}

function printPublications(published: readonly [readonly BallotPart[], readonly BallotPart[]]): void {
  published.forEach((list, index) => {
    note(`${PART_COMMISSIONS[index]} публікує ID виборців і зашифровані частини (без ПІБ):`);
    table(["ID виборця", "RSA(EVP)"], list.map((entry) => [String(entry.voterId), hex(entry.encryptedPart)]));
  });
}

const mark = (passed: boolean) => (passed ? color.green("✔ збігається") : color.red("✘ НЕ збігається"));

/** Виборець і квитанція його прийнятого голосування. */
type Voted = { readonly voter: Voter; readonly receipt: Receipt };

function printPublicationChecks(voted: readonly Voted[], published: readonly [BallotPart[], BallotPart[]]): void {
  table(
    ["Виборець", "ВК-1 опублікувала моє RSA(EVP1)", "ВК-2 опублікувала моє RSA(EVP2)"],
    voted.map(({ voter, receipt }) => {
      const [first, second] = checkPublications(receipt, published);
      return [voter.name, mark(first), mark(second)];
    }),
  );
}

function statusCell(ballot: CombinedBallot): string {
  if (ballot.status === "accepted") return color.green("✔ ID кандидата");
  return color.red(`✘ ${ballot.reason}`);
}

function printCombination(ballots: readonly CombinedBallot[]): void {
  table(
    ["ID виборця", "C₁ від ВК-1", "C₂ від ВК-2", "C = C₁·C₂ mod n", "C^d mod n", "Перевірка"],
    ballots.map((ballot) => [
      String(ballot.voterId),
      ballot.parts[0] === undefined ? color.red("—") : hex(ballot.parts[0]),
      ballot.parts[1] === undefined ? color.red("—") : hex(ballot.parts[1]),
      "combined" in ballot ? hex(ballot.combined) : "—",
      "ballot" in ballot ? color.bold(String(ballot.ballot)) : "—",
      statusCell(ballot),
    ]),
  );
  for (const ballot of ballots) {
    if (ballot.status === "rejected") fail(color.red(`ID ${ballot.voterId}: ${CVK_REJECTIONS[ballot.reason]}`));
  }
}

function printResults(cvk: CentralCommission, results: ElectionResults): void {
  const accepted = results.ballots.filter((ballot) => ballot.status === "accepted").length;
  table(
    ["ID кандидата", "ПІБ", "Голоси"],
    cvk.candidates.map((candidate) => {
      const votes = results.tally.get(candidate.id) ?? 0;
      return [String(candidate.id), candidate.name, `${votes} ${"█".repeat(votes)}`];
    }),
  );
  info(`прийнято бюлетенів: ${accepted}, відкинуто ЦВК: ${results.ballots.length - accepted}`);

  const [leader] = results.leaders;
  if (!leader) note(color.yellow("Жодного голосу не зараховано — переможця немає."));
  else if (results.isTie) note(color.bold(color.yellow("НІЧИЯ: голоси розподілилися порівну.")));
  else note(color.bold(color.green(`ПЕРЕМОЖЕЦЬ: ${leader.name} (ID ${leader.id})`)));
}

function printResultChecks(voted: readonly Voted[], ballots: readonly CombinedBallot[]): void {
  table(
    ["Виборець", "Мій ID", "Голосував за", "ЦВК опублікувала", "Перевірка"],
    voted.map(({ voter, receipt }) => {
      const published = ballots.find((ballot) => ballot.voterId === receipt.voterId);
      const shown = published && "ballot" in published ? String(published.ballot) : "—";
      return [voter.name, String(receipt.voterId), String(receipt.candidateId), shown, mark(checkResult(receipt, ballots))];
    }),
  );
}

/** Приклад з методичних вказівок: RSA(a) · RSA(b) = RSA(a · b) mod n при ключах (7, 33) і (3, 33). */
function homomorphismDemo(): void {
  banner("ЛАБОРАТОРНА РОБОТА №4 — РОЗПОДІЛ БЮЛЕТЕНЯ МІЖ ВК-1 ТА ВК-2 (RSA)");
  section("Мультиплікативна гомоморфність RSA: відкритий ключ (7, 33), закритий ключ (3, 33)");

  const publicKey = { e: 7n, n: 33n };
  const privateKey = { d: 3n, n: 33n };
  const whole = encrypt(24n, publicKey);
  note(`24^7 mod 33 = ${whole};   ${whole}^3 mod 33 = ${decrypt(whole, privateKey)}`);

  table(
    ["Множники", "Шифрування", "Множення", "Дешифрування"],
    [1n, 2n, 3n, 4n].map((a) => {
      const b = 24n / a;
      const [ca, cb] = [encrypt(a, publicKey), encrypt(b, publicKey)];
      const product = multiplyCiphers(ca, cb, publicKey);
      return [
        `${a} та ${b}`,
        `${a}^7 mod 33 = ${ca};  ${b}^7 mod 33 = ${cb}`,
        `(${ca} × ${cb}) mod 33 = ${product}`,
        `${product}^3 mod 33 = ${decrypt(product, privateKey)}`,
      ];
    }),
  );
  ok("для кожного поділу добуток шифротекстів дорівнює RSA(24) = 18, а його розшифрування — 24");
}

function mainSession(): void {
  section("КРОК 1. Ключі виборців, список ЦВК, ID кандидатів, ключ шифрування ЦВК");
  const session = setupSession(true);
  const { cvk, voters } = session;

  note("Кожен виборець самостійно згенерував пару ключів RSA для ЕЦП і надіслав відкритий ключ до ЦВК:");
  table(
    ["№", "ПІБ виборця", "Відкритий ключ ЕЦП (e, n)", "Закритий ключ (d)"],
    voters.map((voter, index) => [
      String(index + 1),
      voter.name,
      `e = ${voter.publicKey.e}, n = ${hex(voter.publicKey.n)}`,
      `d = ${hex(voter.keys.privateKey.d)}`,
    ]),
  );

  const ids = cvk.candidateIds;
  note("ЦВК надала кандидатам ID зі спільними множниками та опублікувала їх:");
  table(
    ["ID", "ПІБ кандидата", "Розклади, що не видають вибір"],
    cvk.candidates.map((candidate) => [
      String(candidate.id),
      candidate.name,
      hidingSplits(candidate.id, ids).map(formatSplit).join(", "),
    ]),
  );
  const factors = [...new Set(ids.flatMap((id) => factorPairs(id).map(([factor]) => factor)))].sort((a, b) => Number(a - b));
  const [shared, revealing] = [
    factors.filter((factor) => candidatesSharing(factor, ids) >= 2),
    factors.filter((factor) => candidatesSharing(factor, ids) < 2),
  ];
  info(`множники ${shared.join(", ")} ділять обидва ID — за ними вибір не визначити`);
  info(`множники ${revealing.join(", ")} трапляються лише в одному ID, тому виборець їх не використовує`);

  note(`ЦВК згенерувала ключі шифрування і опублікувала відкритий ключ: e = ${cvk.publicKey.e}, n = ${short(cvk.publicKey.n, 14, 6)}`);
  ok(`ЦВК → ВК-1, ВК-2: список з ${cvk.voterList().length} виборців і їх відкритих ключів ЕЦП передано`);

  section("КРОКИ 2–4. Поділ ID, шифрування частин, ЕЦП, перевірки ВК-1 та ВК-2");
  const [first, second] = cvk.candidates;
  if (!first || !second) throw new Error("Потрібно два кандидати");
  const voted = [
    castVote(session, voters[0]!, first.id, `Виборець №1 голосує за ID ${first.id}`),
    castVote(session, voters[1]!, second.id, `Виборець №2 голосує за ID ${second.id}`),
    castVote(session, voters[2]!, first.id, `Виборець №3 голосує за ID ${first.id}`),
  ];

  section("НЕГАТИВНІ СЦЕНАРІЇ ПЕРЕВІРОК ВК");
  step("Сценарій 1. Повідомлення від незареєстрованого виборця");
  const stranger = new Voter("Стороння Мальвіна Олегівна", KEY_BITS);
  info("ключі згенеровані, але відкритий ключ не надсилався до ЦВК — її немає у списку");
  deliver(session, stranger.vote(first.id, ids, cvk.publicKey).messages);

  step("Сценарій 2. Повідомлення з неправильним ЕЦП: підміна RSA(EVP1) по дорозі до ВК-1");
  const fourth = voters[3]!;
  const ballot = fourth.vote(second.id, ids, cvk.publicKey);
  const [toFirst, toSecond] = ballot.messages;
  const forged: PartMessage = { ...toFirst, part: { ...toFirst.part, encryptedPart: encrypt(5n, cvk.publicKey) } };
  info(`оригінал: RSA(${ballot.receipt.split[0]}) = ${hex(toFirst.part.encryptedPart)}, підміна: RSA(5) = ${hex(forged.part.encryptedPart)}`);
  info("відкритий ключ ЦВК доступний усім, але ЕЦП виборця без його закритого ключа не перерахувати");
  verdict(session.commissions[0].receive(forged), "ВК-1");
  info("виборець №4 надсилає оригінальні повідомлення до обох ВК:");
  verdict(session.commissions[0].receive(toFirst), "ВК-1");
  verdict(session.commissions[1].receive(toSecond), "ВК-2");
  voted.push({ voter: fourth, receipt: ballot.receipt });

  step("Сценарій 3. Повідомлення, підписане чужим закритим ключем");
  const [firstVoter, , , , fifth] = voters;
  if (!firstVoter || !fifth) throw new Error("Потрібно п'ять виборців");
  const fake = firstVoter.vote(first.id, ids, cvk.publicKey).messages[1];
  info(`«${firstVoter.name}» підписує своїм ключем, а надсилає до ВК-2 від імені «${fifth.name}»`);
  verdict(session.commissions[1].receive({ ...fake, senderName: fifth.name }), "ВК-2");

  step("Сценарій 4. Повторне голосування виборця №1");
  info("новий бюлетень коректно підписаний, але від цього виборця обидві ВК вже прийняли частини");
  deliver(session, firstVoter.vote(second.id, ids, cvk.publicKey).messages);

  section("ПРОДОВЖЕННЯ ГОЛОСУВАННЯ");
  voted.push(castVote(session, fifth, first.id, `Виборець №5 голосує за ID ${first.id}`));

  section("КРОК 5. ВК-1 та ВК-2 публікують ID виборців і зашифровані частини");
  const published = publications(session);
  printPublications(published);
  note("Кожен виборець звіряє опубліковане з тим, що надсилав:");
  printPublicationChecks(voted, published);

  section("КРОК 6. ЦВК: зіставлення за ID → об'єднання C₁·C₂ → розшифрування → перевірка ID кандидата");
  const ballots = cvk.combine(...published);
  printCombination(ballots);
  info("ЦВК не розшифровує частини окремо: закритий ключ застосовується лише до об'єднаного бюлетеня");

  section("Підсумки голосування та публікація ЦВК: ID виборця → відновлений бюлетень");
  const results = cvk.tally(ballots);
  printResults(cvk, results);
  note("Кожен виборець звіряє опублікований ЦВК бюлетень зі своїм вибором:");
  printResultChecks(voted, results.ballots);
}

/**
 * Окрема сесія з атаками: щоб результат був відтворюваним, виборці використовують
 * фіксовані розклади, а нечесні комісії змінюють лише опубліковані ними дані.
 */
function attackSession(): void {
  banner("АТАКИ НЕЧЕСНИХ КОМІСІЙ ТА ЇХ ВИЯВЛЕННЯ ВИБОРЦЯМИ");
  const session = setupSession(false);
  const { cvk, voters } = session;
  const ids = cvk.candidateIds;
  const [first, second] = cvk.candidates;
  if (!first || !second) throw new Error("Потрібно два кандидати");

  const plan: readonly (readonly [bigint, Split])[] = [
    [first.id, [12n, 2n]],
    [second.id, [12n, 3n]],
    [first.id, [4n, 6n]],
    [second.id, [6n, 6n]],
    [first.id, [2n, 12n]],
  ];
  const voted = voters.map((voter, index): Voted => {
    const [candidateId, split] = plan[index]!;
    const ballot = voter.vote(candidateId, ids, cvk.publicKey, split);
    session.commissions.forEach((commission, part) => commission.receive(ballot.messages[part]!));
    return { voter, receipt: ballot.receipt };
  });
  table(
    ["Виборець", "ID виборця", "Вибір", "Поділ (ВК-1 × ВК-2)"],
    voted.map(({ voter, receipt }) => [voter.name, String(receipt.voterId), String(receipt.candidateId), formatSplit(receipt.split)]),
  );
  const [first1, second1] = publications(session);
  const honest = cvk.combine(first1, second1);
  info(`чесний підсумок: ID ${first.id} — ${honest.filter((b) => "ballot" in b && b.ballot === first.id).length}, ` +
    `ID ${second.id} — ${honest.filter((b) => "ballot" in b && b.ballot === second.id).length}`);

  const maxId = ids.reduce((max, id) => (id > max ? id : max), 0n);
  section("Сценарій A. ВК-1 підбирає свої множники перебором і підміняє 12 → 18 (хоче перетворити 24 на 36)");
  const decoded = first1.map((entry) => decodeByDictionary(entry.encryptedPart, cvk.publicKey, maxId));
  table(
    ["ID виборця", "RSA(EVP1)", "Підібраний множник", "Може бути частиною ID"],
    first1.map((entry, index) => {
      const factor = decoded[index];
      return [
        String(entry.voterId),
        hex(entry.encryptedPart),
        String(factor ?? "?"),
        factor === undefined ? "?" : ids.filter((id) => id % factor === 0n).join(" або "),
      ];
    }),
  );
  info("RSA без доповнень детермінований: RSA(k) для малих k можна перебрати відкритим ключем ЦВК");
  info("але кожен множник ділить обидва ID — за однією частиною вибір не визначити");
  const substitute = encrypt(18n, cvk.publicKey);
  const tampered1 = first1.map((entry, index) =>
    decoded[index] === 12n ? { ...entry, encryptedPart: substitute } : entry,
  );

  section("Сценарій B. ВК-2 «губить» частину бюлетеня виборця №4");
  const dropped = second1.filter((entry) => entry.voterId !== voted[3]!.receipt.voterId);
  info(`ВК-2 опублікувала ${dropped.length} з ${second1.length} частин`);

  section("Сценарій C. Змова ВК-1 та ВК-2: обидві частини виборця №3 замінено на 6 × 6 = 36");
  const victim = voted[2]!.receipt.voterId;
  const six = encrypt(6n, cvk.publicKey);
  const colluded1 = tampered1.map((entry) => (entry.voterId === victim ? { ...entry, encryptedPart: six } : entry));
  const colluded2 = dropped.map((entry) => (entry.voterId === victim ? { ...entry, encryptedPart: six } : entry));
  info("для нового шифротексту потрібен лише відкритий ключ ЦВК, тому разом ВК отримують коректний ID іншого кандидата");

  section("ЦВК об'єднує те, що опублікували нечесні ВК");
  const combined = cvk.combine(colluded1, colluded2);
  printCombination(combined);

  section("Сценарій D. Нечесна ЦВК публікує для виборця №5 бюлетень 36 замість 24");
  const target = voted[4]!.receipt.voterId;
  const published = combined.map((ballot) =>
    ballot.voterId === target && ballot.status === "accepted" ? { ...ballot, ballot: second.id } : ballot,
  );
  const results = cvk.tally(published);
  printResults(cvk, results);
  info(`чесний результат був би ${first.id}: 3, ${second.id}: 2 — атаки змінили переможця`);

  section("Виявлення: кожен виборець звіряє публікації ВК-1, ВК-2 і ЦВК зі своєю квитанцією");
  printPublicationChecks(voted, [colluded1, colluded2]);
  printResultChecks(voted, results.ballots);
  note(color.yellow("Виборці №1–4 мають докази підміни частин у публікаціях ВК, виборець №5 — підміни на боці ЦВК."));
  note(color.yellow("Бюлетень 54 = 18 × 3 не є ID кандидата — ЦВК бачить сліди втручання ВК-1 навіть без скарг."));
}

/** Зведення: що протокол із розділенням бюлетеня забезпечує, а що ні. */
function propertySummary(): void {
  section("Властивості протоколу з розділенням бюлетеня");
  table(
    ["Вимога / загроза", "Стан", "Механізм у реалізації"],
    [
      ["Голосують лише зареєстровані", color.green("забезпечено"), "список ЦВК у ВК-1 та ВК-2"],
      ["Не більше одного голосу", color.green("забезпечено"), "відмітка про отримання у кожній ВК"],
      ["Неможливо голосувати за іншого", color.green("забезпечено"), "ЕЦП RSA кожного повідомлення"],
      ["ВК не знає вибору виборця", color.green("частково"), "частина зашифрована, множник спільний для ID"],
      ["ЦВК не знає ПІБ виборця", color.green("забезпечено"), "ЦВК бачить лише ID виборця"],
      ["Підміна однією ВК", color.yellow("виявляється"), "невалідний ID + перевірка публікацій виборцем"],
      ["Змова ВК-1 і ВК-2", color.red("не захищено"), "виявляє лише виборець за квитанцією"],
      ["Перебір множників ВК", color.red("можливий"), "RSA детермінований; рятує лише спільність множників"],
    ],
  );
}

homomorphismDemo();
mainSession();
attackSession();
propertySummary();
console.log();
