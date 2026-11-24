import { ballotLength, fabricateBallot, findByLength, forgeWithWrongRp, peekTally } from "./attacks.ts";
import { formBallot, randomRp } from "./ballot.ts";
import { castBallots, mix, publish, registerVoters, rosterFingerprint, type MixOutcome, type StepRecord, type Tamper } from "./election.ts";
import { decryptLayer, encryptLayer, encryptSymbolwise, generateKeyPair, sign } from "./rsa.ts";
import { REJECTIONS, ROUNDS, RP_LENGTH, serializeSet, type Candidate, type Publication, type Tally } from "./types.ts";
import { banner, color, fail, hex, info, note, ok, section, step, table } from "./ui.ts";
import type { Voter } from "./voter.ts";

const CANDIDATES: readonly Candidate[] = [
  { id: 1, name: "Олена Петренко" },
  { id: 2, name: "Іван Коваленко" },
];
const [FIRST, SECOND] = CANDIDATES as readonly [Candidate, Candidate];
const NAMES = ["A", "B", "C", "D", "E"] as const;
const CHOICES: readonly Candidate[] = [FIRST, SECOND, FIRST, SECOND, FIRST];

const yes = color.green("✔");
const formatTally = (tally: Tally) =>
  CANDIDATES.map(({ id, name }) => `${name}: ${tally.votes.get(id) ?? 0}`).join(", ") + `, недійсних: ${tally.invalid}`;
const lengths = (ballots: readonly string[]) => ballots.map((ballot) => ballot.length).join(", ");
const commonPrefix = (first: string, second: string) => {
  let length = 0;
  while (length < first.length && first[length] === second[length]) length += 1;
  return length;
};

banner("ЛАБОРАТОРНА РОБОТА №5 — ПРОТОКОЛ Е-ГОЛОСУВАННЯ БЕЗ ВИБОРЧОЇ КОМІСІЇ");

/* ─────────────── Крок 1: спільний список і обмін ключами ─────────────── */

section("КРОК 1. СПІЛЬНИЙ ВПОРЯДКОВАНИЙ СПИСОК ВИБОРЦІВ І ОБМІН ВІДКРИТИМИ КЛЮЧАМИ");
const voters = registerVoters(NAMES);
const [A, B, C, D, E] = voters as [Voter, Voter, Voter, Voter, Voter];

step("Кожен виборець самостійно генерує пару ключів RSA (p, q — 16-бітні прості, n — 32 біти)");
table(
  ["Позиція", "Виборець", "p", "q", "n (відкритий)", "e (відкритий)", "d (закритий, лише у власника)"],
  voters.map((voter, index) => [
    String(index + 1),
    voter.name,
    String(voter.keys.parameters.p),
    String(voter.keys.parameters.q),
    String(voter.publicKey.n),
    String(voter.publicKey.e),
    String(voter.keys.privateKey.d),
  ]),
);

step("Обмін відкритими ключами: кожен складає власну копію списку");
table(
  ["Виборець", "Учасників у копії", "Порядок", "Відбиток копії (SHA-256)"],
  voters.map((voter) => [voter.name, String(voter.roster.length), voter.roster.map(({ name }) => name).join(" → "), rosterFingerprint(voter.roster)]),
);
const fingerprints = new Set(voters.map((voter) => rosterFingerprint(voter.roster)));
if (fingerprints.size === 1) ok("усі п’ять копій однакові: однаковий склад, порядок і відкриті ключі");
else fail("копії списку різняться");

step("Список кандидатів і послідовність виконання протоколу");
for (const candidate of CANDIDATES) info(`кандидат №${candidate.id}: ${candidate.name}`);
info(`шифрування (кожен раунд): ${[...NAMES].reverse().join(" → ")}, раундів: ${ROUNDS}`);
info(`розшифрування (кожен раунд): ${NAMES.join(" → ")}, раундів: ${ROUNDS}; публікує результат ${E.name}`);

/* ─────────────── Посимвольне багатошарове RSA ─────────────── */

section("ПОСИМВОЛЬНЕ БАГАТОШАРОВЕ RSA-ШИФРУВАННЯ");
step(`Один шар: символи шифруються окремо ключем ${A.name} (e = ${A.publicKey.e}, n = ${A.publicKey.n})`);
const sample = "Олена";
const layer = encryptLayer(sample, A.publicKey);
note(`  cᵢ = ((mᵢ + cᵢ₊₁) mod n)^e mod n — кожен символ залежить від шифротексту символу праворуч`);
table(
  ["i", "Символ", "mᵢ", "cᵢ₊₁", "cᵢ", "cᵢ у шифротексті (2 символи)"],
  [...sample].map((symbol, index) => {
    const value = (offset: number) => {
      const position = (index + offset) * 2;
      if (position >= layer.length) return 0n;
      return (BigInt(layer.charCodeAt(position)) << 16n) | BigInt(layer.charCodeAt(position + 1));
    };
    return [String(index + 1), symbol, String(symbol.charCodeAt(0)), String(value(1)), String(value(0)), hex(layer.slice(index * 2, index * 2 + 2), 2)];
  }),
);
ok(`розшифрування закритим ключем ${A.name}: «${decryptLayer(layer, A.keys.privateKey)}»`);

step("Навіщо зчеплення: два шифрування EVP || RP з різними RP");
const evp = formBallot(FIRST, CANDIDATES);
const [rp1, rp2] = [randomRp(), randomRp()];
const independent = [encryptSymbolwise(evp + rp1, A.publicKey), encryptSymbolwise(evp + rp2, A.publicKey)] as const;
const chained = [encryptLayer(evp + rp1, A.publicKey), encryptLayer(evp + rp2, A.publicKey)] as const;
table(
  ["Режим", "RSA(EVP || RP₁)", "RSA(EVP || RP₂)", "Спільний префікс"],
  [
    ["незалежні символи", hex(independent[0], 5), hex(independent[1], 5), `${commonPrefix(...independent)} з ${independent[0].length} символів`],
    ["зі зчепленням", hex(chained[0], 5), hex(chained[1], 5), `${commonPrefix(...chained)} з ${chained[0].length} символів`],
  ],
);
fail("без зчеплення RSA(EVP || RP) = RSA(EVP) || RSA(RP): будь-хто зашифрує ім’я кандидата відкритим ключем і впізнає голос");
ok("зі зчепленням RP, дописаний у кінець, змінює кожен символ шару — однакові EVP стають непорівнюваними");

step("Багатошаровість: результат шару — вхідні дані наступного (порядок E → D → C → B → A)");
let onion = evp;
const growth: string[][] = [];
for (const voter of [...voters].reverse()) {
  const before = onion.length;
  onion = encryptLayer(onion, voter.publicKey);
  growth.push([`RSA_${voter.name}`, String(before), String(onion.length), hex(onion, 4)]);
}
table(["Шар", "Символів на вході", "Символів на виході", "Початок шифротексту"], growth);
let peeled = onion;
for (const voter of voters) peeled = decryptLayer(peeled, voter.keys.privateKey) ?? "";
ok(`послідовне зняття шарів A → B → C → D → E повертає «${peeled}»`);

/* ─────────────── Крок 2: бюлетені та два раунди шифрування ─────────────── */

section("КРОК 2. ФОРМУВАННЯ ТА БАГАТОШАРОВЕ ШИФРУВАННЯ БЮЛЕТЕНІВ");
const traces: string[][] = [];
let encryptedSymbols = 0;
const ballots = castBallots(voters, CHOICES, CANDIDATES, (name, trace) => {
  encryptedSymbols += trace.length / 2;
  if (name === C.name) traces.push([String(trace.round + 1), `RSA_${trace.layer}`, trace.rpAdded ? color.yellow(`так: RP${trace.round === 0 ? "¹" : "²"}_C`) : "—", String(trace.length)]);
});
step(`Шари бюлетеня виборця ${C.name}: C₂ = RSA_A(RSA_B(RSA_C(RSA_D(RSA_E(C₁)) || RP²_C)))`);
table(["Раунд", "Шар", "RP перед шаром", "Довжина, символів"], traces);

step("Бюлетені всіх виборців (RP зберігаються у власників)");
table(
  ["Виборець", "EVP (вибір)", "RP¹ (раунд 1)", "RP² (раунд 2)", "Довжина шифротексту", "Початок шифротексту"],
  voters.map((voter, index) => [
    voter.name,
    CHOICES[index]?.name ?? "",
    hex(voter.rpFor(ROUNDS - 1)),
    hex(voter.rpFor(0)),
    String(ballots[index]?.length),
    hex(ballots[index] ?? "", 3),
  ]),
);
ok(`усі ${ballots.length} повністю зашифрованих бюлетенів передано виборцю ${A.name}`);

/* ─────────────── Кроки 3–4: два раунди розшифрування ─────────────── */

const ROUND_TITLES = [
  "КРОК 3. ПЕРШИЙ РАУНД РОЗШИФРУВАННЯ (A → B → C → D → E, перевірка RP²)",
  "КРОК 4. ДРУГИЙ РАУНД РОЗШИФРУВАННЯ (A → B → C → D → E, перевірка RP¹)",
];
let rows: string[][] = [];
const flush = () => {
  table(["Виборець", "Від кого / ЕЦП", "Кількість", "Власний RP", "Після кроку: довжини (перемішано)", "ЕЦП набору"], rows);
  rows = [];
};
const describeStep = (record: StepRecord) => {
  const voter = voters.find(({ name }) => name === record.voter);
  if (record.voter === A.name) {
    if (record.round > 0) flush();
    section(ROUND_TITLES[record.round] ?? "");
  }
  rows.push([
    record.voter,
    record.verifiedSender === undefined ? "зібрано від усіх" : `${record.verifiedSender} ${yes}`,
    `${record.received} ${yes}`,
    `${hex(voter?.rpFor(record.round) ?? "", 2)} знайдено, видалено ${yes}`,
    lengths(record.output.ballots),
    `0x${record.output.signature.toString(16)}`,
  ]);
};
const honest = mix(voters, ballots, { onStep: describeStep });
flush();
if (honest.status !== "completed") throw new Error("Чесний прогін протоколу має завершитися");
step(`Після останнього кроку ${E.name} всі шари зняті — початкові бюлетені:`);
for (const ballot of honest.final.ballots) info(`«${ballot.trimEnd()}»`);

/* ─────────────── Крок 5: публікація і підрахунок ─────────────── */

section("КРОК 5. ПУБЛІКАЦІЯ НАБОРУ ТА НЕЗАЛЕЖНИЙ ПІДРАХУНОК");
const publication = publish(honest.final, CANDIDATES);
step(`${E.name} публікує підписаний набір відкритих бюлетенів і свій підрахунок`);
info(`ЕЦП_${E.name} = 0x${publication.set.signature.toString(16)}`);
info(`оголошено: ${formatTally(publication.announced)}`);

step("Кожен учасник перевіряє ЕЦП, кількість і повторює підрахунок");
const verifyAll = (target: Publication) =>
  voters.map((voter) => {
    const result = voter.verifyPublication(target, CANDIDATES);
    return [voter.name, result.ok ? `${yes} ${formatTally(result.tally)}` : color.red(`✘ ${result.reason}: ${result.detail}`)];
  });
table(["Виборець", "Результат перевірки та власний підрахунок"], verifyAll(publication));
const recounts = voters.map((voter) => voter.verifyPublication(publication, CANDIDATES));
if (recounts.every((result) => result.ok)) ok("підрахунки всіх п’яти учасників однакові й збігаються з оголошеним");
const winner = [...publication.announced.votes].sort(([, a], [, b]) => b - a)[0];
note(color.bold(`  Переможець: ${CANDIDATES.find(({ id }) => id === winner?.[0])?.name} (${winner?.[1]} з ${voters.length} голосів)`));

/* ─────────────── Негативні сценарії ─────────────── */

section("НЕГАТИВНІ СЦЕНАРІЇ");

const ROUND_NAMES = ["перший", "другий"];
function runScenario(title: string, tamper: Tamper): MixOutcome {
  step(title);
  const outcome = mix(voters, castBallots(voters, CHOICES, CANDIDATES), { tamper });
  if (outcome.status === "completed") {
    fail("порушення не виявлено — протокол завершився");
    return outcome;
  }
  fail(`${outcome.voter}, ${ROUND_NAMES[outcome.round]} раунд розшифрування: ${color.bold(outcome.failure.reason)} — ${outcome.failure.detail}`);
  info(`${REJECTIONS[outcome.failure.reason]}; протокол зупинено, бюлетені не розшифровано до кінця`);
  return outcome;
}

const isPass = (from: string, round: number) => (hop: Parameters<Tamper>[0]) =>
  hop.kind === "pass" && hop.from === from && hop.round === round;

runScenario("Сценарій 1. Додавання бюлетеня: сторонній додає 6-й бюлетень до набору, який збирає A", (hop, set) => {
  if (hop.kind !== "collect") return set;
  return { ...set, ballots: [...set.ballots, fabricateBallot(formBallot(SECOND, CANDIDATES), A.roster)] };
});

runScenario("Сценарій 2. Видалення бюлетеня: нечесний C видаляє один бюлетень і чесно підписує набір", (hop, set) =>
  isPass(C.name, 0)(hop) ? C.signSet(set.ballots.slice(1)) : set,
);

const replaceFirst = (ballots: readonly string[]) => ballots.map((ballot, index) => (index === 0 ? (ballots[1] ?? ballot) : ballot));

runScenario("Сценарій 3. Підміна в каналі: у наборі B → C один бюлетень замінено, ЕЦП B залишено", (hop, set) => {
  if (!isPass(B.name, 0)(hop) || set.kind !== "signed") return set;
  return { ...set, ballots: replaceFirst(set.ballots) };
});

const mallory = generateKeyPair();
runScenario("Сценарій 4. Підробка ЕЦП: зловмисник підписує набір своїм ключем від імені B", (hop, set) => {
  if (!isPass(B.name, 0)(hop) || set.kind !== "signed") return set;
  const ballots = replaceFirst(set.ballots);
  return { ...set, ballots, signature: sign(serializeSet(B.name, ballots), mallory.privateKey) };
});

runScenario("Сценарій 5. Відсутній RP: нечесний A замінює бюлетень D на сфабрикований (кількість не змінюється)", (hop, set) => {
  if (hop.kind !== "collect") return set;
  const fake = fabricateBallot(formBallot(FIRST, CANDIDATES), A.roster);
  return { ...set, ballots: set.ballots.map((ballot, index) => (index === voters.indexOf(D) ? fake : ballot)) };
});

runScenario("Сценарій 6. Неправильний RP: у другому раунді B знаходить бюлетень C за довжиною і підміняє його", (hop, set) => {
  if (!isPass(B.name, 1)(hop)) return set;
  const fake = forgeWithWrongRp(formBallot(SECOND, CANDIDATES), B.roster.slice(2), C.name);
  const target = findByLength(set.ballots, fake.length);
  info(`B: бюлетень C має довжину ${fake.length} — позиція ${target + 1} у перемішаному наборі; підставлено голос «${SECOND.name}» з чужим RP`);
  return B.signSet(set.ballots.map((ballot, index) => (index === target ? fake : ballot)));
});

runScenario("Сценарій 7. Копіювання: A замінює бюлетень D копією бюлетеня B, щоб дізнатися вибір B", (hop, set) => {
  if (hop.kind !== "collect") return set;
  const copy = set.ballots[voters.indexOf(B)] ?? "";
  return { ...set, ballots: set.ballots.map((ballot, index) => (index === voters.indexOf(D) ? copy : ballot)) };
});

runScenario("Сценарій 8. Відмова учасника: C не передає набір далі", (hop, set) => (isPass(C.name, 0)(hop) ? undefined : set));

step("Сценарій 9. Хибний результат: E публікує правильний набір, але оголошує інший підрахунок");
const forgedTally: Tally = { votes: new Map([[FIRST.id, 2], [SECOND.id, 3]]), invalid: 0 };
info(`оголошено E: ${formatTally(forgedTally)}`);
table(["Виборець", "Результат перевірки"], verifyAll({ ...publication, announced: forgedTally }));

/* ─────────────── Аналіз ─────────────── */

section("АНАЛІЗ ВЛАСТИВОСТЕЙ І ОБМЕЖЕНЬ");

step("Довжина бюлетеня залежить від позиції власника (RP дописується перед різними шарами)");
table(
  ["Власник", "Позиція в списку", "Довжина зашифрованого бюлетеня, символів"],
  voters.map((voter, index) => [voter.name, String(index + 1), String(ballots[index]?.length)]),
);
info("перемішування не приховує, чий бюлетень, поки RP власника не видалено; вміст при цьому прихований зчепленням");

step(`Що бачить ${D.name} після свого кроку в другому раунді розшифрування`);
const stepOfD = honest.steps.find((record) => record.round === ROUNDS - 1 && record.voter === D.name);
if (stepOfD) {
  const seen = peekTally(stepOfD.output.ballots, D.roster.slice(-1), CANDIDATES);
  const seenTotal = [...seen.values()].reduce((sum, count) => sum + count, 0);
  info(`бюлетені A–D мають вигляд RSA_E(EVP) без RP — ${D.name} шифрує обидва EVP ключем E і рахує збіги:`);
  info(CANDIDATES.map(({ id, name }) => `${name}: ${seen.get(id)}`).join(", ") + ` (розпізнано ${seenTotal} з ${voters.length})`);
  const leaked = CANDIDATES.find(({ id }) => (publication.announced.votes.get(id) ?? 0) - (seen.get(id) ?? 0) === 1);
  fail(`порівнявши з оголошеним результатом, ${D.name} дізнається вибір ${E.name}: ${leaked?.name}`);
}

step("Складність: кількість операцій RSA і обсяг даних");
const layers = voters.length * ROUNDS * voters.length;
const setSize = (set: readonly string[]) => set.reduce((sum, ballot) => sum + ballot.length, 0);
const transferred = setSize(ballots) + honest.steps.reduce((sum, record) => sum + setSize(record.output.ballots), 0);
info(`шарів: ${layers} накладено і ${layers} знято; RSA над окремими символами: ${encryptedSymbols} шифрувань і стільки ж розшифрувань`);
info(`ЕЦП наборів: ${honest.steps.length}, перевірок ЕЦП: ${honest.steps.length - 1 + voters.length}; передано між учасниками: ${transferred} символів`);
table(
  ["Виборців", "Шарів на бюлетень", "Найдовший бюлетень, символів", "Набір, МБ (2 байти на символ)"],
  [3, 4, 5, 7, 10].map((count) => {
    const longest = ballotLength(count, count - 1, evp.length);
    return [String(count), String(count * ROUNDS), longest.toLocaleString("uk-UA"), ((longest * count * 2) / 2 ** 20).toFixed(2)];
  }),
);
info(`кожен шар подвоює довжину (символ → 32-бітне число = 2 символи), RP = ${RP_LENGTH} символи`);
console.log();
