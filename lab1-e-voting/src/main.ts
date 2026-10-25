import { ElectionCommission, type CheckEvent } from "./commission.ts";
import { hashMessage, short } from "./rsa.ts";
import { serializeBallot, type Candidate, type Envelope, type ProcessingResult } from "./types.ts";
import { sealFor, Voter } from "./voter.ts";
import { banner, color, fail, info, note, ok, section, step, table } from "./ui.ts";

/**
 * Демонстрація простого протоколу електронного голосування:
 * 2 кандидати, 5 виборців, RSA для шифрування та ЕЦП.
 * Показані як позитивні, так і негативні сценарії перевірок ВК.
 */

const KEY_BITS = 512;

const CANDIDATES: readonly Candidate[] = [
  { id: "К1", name: "Іваненко Іван Іванович" },
  { id: "К2", name: "Петренко Петро Петрович" },
];

const VOTER_NAMES = [
  "Коваленко Андрій Сергійович",
  "Шевченко Олена Миколаївна",
  "Бондаренко Богдан Юрійович",
  "Ткаченко Марія Василівна",
  "Мельник Остап Ігорович",
] as const;

/** Спостерігач друкує кожну перевірку ВК окремим рядком. */
const observer = (event: CheckEvent) => (event.passed ? ok : fail)(describe(event));

function describe(event: CheckEvent): string {
  const labels: Record<CheckEvent["check"], string> = {
    decrypt: "Розшифрування закритим ключем ВК",
    inList: "Наявність у списку виборців",
    signature: "Перевірка ЕЦП відкритим ключем виборця",
    identity: "Відповідність ПІБ у бюлетені",
    notVotedYet: "Перевірка повторного голосування",
    ballotValid: "Коректність заповнення бюлетеня",
  };
  return `${labels[event.check]}: ${event.detail}`;
}

function showEnvelope(voter: Voter, signedText: string, signature: bigint, cipher: readonly bigint[]): void {
  info(`бюлетень: ${signedText}`);
  info(`H = (H₍ᵢ₋₁₎ + Mᵢ)² mod n → ${short(hashMessage(signedText, voter.publicKey.n))}`);
  info(`ЕЦП = H^d mod n → ${short(signature)}`);
  const shown = cipher.slice(0, 3).map((block) => short(block, 8, 4));
  info(`шифротекст для ВК (${cipher.length} бл.): ${shown.join(", ")}${cipher.length > 3 ? ", …" : ""}`);
}

function verdict(result: ProcessingResult): void {
  if (result.status === "accepted") {
    ok(color.bold(color.green(`БЮЛЕТЕНЬ ПРИЙНЯТО → голос за «${result.candidateId}» зараховано`)));
  } else {
    fail(color.bold(color.red(`БЮЛЕТЕНЬ ВІДХИЛЕНО [${result.reason}]: ${result.message}`)));
  }
}

/** Штатне голосування: виборець заповнює, підписує, шифрує та надсилає бюлетень. */
function castVote(voter: Voter, candidateId: string, commission: ElectionCommission, label: string): void {
  step(label);
  const signed = voter.fillAndSign(candidateId);
  const envelope = voter.seal(signed, commission.publicKey);
  showEnvelope(voter, signed.ballot, signed.signature, envelope.cipher);
  verdict(commission.receive(envelope));
}

function setupSession(voterNames: readonly string[], verbose = true) {
  const commission = new ElectionCommission({
    candidates: CANDIDATES,
    bits: KEY_BITS,
    ...(verbose ? { observer } : {}),
  });
  const voters = voterNames.map((name) => new Voter(name, KEY_BITS));
  for (const voter of voters) commission.registerVoter(voter.name, voter.publicKey);
  return { commission, voters };
}

function printResults(commission: ElectionCommission): void {
  const results = commission.publishResults();
  const total = results.accepted;

  table(
    ["Кандидат", "ПІБ", "Голоси", "Частка"],
    CANDIDATES.map((candidate) => {
      const votes = results.tally.get(candidate.id) ?? 0;
      const share = total === 0 ? 0 : Math.round((votes / total) * 100);
      return [candidate.id, candidate.name, String(votes), `${share}% ${"█".repeat(votes)}`];
    }),
  );

  info(`прийнято бюлетенів: ${results.accepted}, відхилено спроб: ${results.rejected}`);
  info(`проголосувало ${results.turnout.voted} з ${results.turnout.registered} допущених виборців`);

  if (results.leaders.length === 0) {
    note(color.yellow("Жодного голосу не зараховано — переможця немає."));
  } else if (results.isTie) {
    note(
      color.bold(
        color.yellow(
          `НІЧИЯ: голоси розподілилися порівну між ${results.leaders
            .map((candidate) => `«${candidate.name}»`)
            .join(" та ")} — потрібен другий тур.`,
        ),
      ),
    );
  } else {
    note(color.bold(color.green(`ПЕРЕМОЖЕЦЬ: ${results.leaders[0]?.name}`)));
  }
}

function mainSession(): void {
  banner("ЛАБОРАТОРНА РОБОТА №1 — ПРОСТИЙ ПРОТОКОЛ Е-ГОЛОСУВАННЯ (RSA)");

  section("КРОК 1. Підготовка: ключі, список виборців, список кандидатів");
  const { commission, voters } = setupSession(VOTER_NAMES);

  note("Кожен виборець самостійно згенерував власну пару ключів RSA для ЕЦП:");
  table(
    ["ПІБ виборця", "Відкритий ключ (e, n)", "Закритий ключ (d, n)"],
    voters.map((voter) => [
      voter.name,
      `e = ${voter.publicKey.e}, n = ${short(voter.publicKey.n, 10, 4)}`,
      `d = ${short(voter.keys.privateKey.d, 10, 4)}`,
    ]),
  );

  note("Список допущених виборців, сформований ВК (ПІБ + відкритий ключ для перевірки ЕЦП):");
  table(
    ["№", "ПІБ", "Відкритий ключ ЕЦП", "Проголосував"],
    commission.voterList.map((voter, index) => [
      String(index + 1),
      voter.name,
      short(voter.publicKey.n, 10, 4),
      voter.hasVoted ? "так" : "ні",
    ]),
  );

  note("Список кандидатів, сформований ВК:");
  table(["Код", "ПІБ кандидата"], CANDIDATES.map((candidate) => [candidate.id, candidate.name]));

  note(
    `Відкритий ключ ВК для шифрування бюлетенів (публікується у вільному доступі): ` +
      `e = ${commission.publicKey.e}, n = ${short(commission.publicKey.n, 14, 6)}`,
  );

  section("КРОКИ 2–3. Голосування та перевірки ВК (позитивні сценарії)");
  castVote(voters[0]!, "К1", commission, "Виборець №1 голосує за К1 — коректний бюлетень");
  castVote(voters[1]!, "К2", commission, "Виборець №2 голосує за К2 — коректний бюлетень");

  section("НЕГАТИВНІ СЦЕНАРІЇ: як ВК відхиляє некоректні бюлетені");
  negativeDoubleVote(voters[0]!, commission);
  negativeStranger(commission);
  negativeImpersonation(voters[2]!, voters[1]!, commission);
  negativeTampering(voters[2]!, commission);
  negativeSpoiledBallot(voters[3]!, commission);

  section("ПРОДОВЖЕННЯ ГОЛОСУВАННЯ: виборці, чиї спроби були зіпсовані, голосують коректно");
  castVote(voters[2]!, "К1", commission, "Виборець №3 надсилає власний непідроблений бюлетень");
  castVote(voters[3]!, "К2", commission, "Виборець №4 виправляє зіпсований бюлетень");
  castVote(voters[4]!, "К1", commission, "Виборець №5 голосує за К1");

  section("КРОК 4. Підрахунок голосів і публікація результатів");
  printResults(commission);

  section("Підсумкова відмітка у списку виборців");
  table(
    ["№", "ПІБ", "Проголосував"],
    commission.voterList.map((voter, index) => [
      String(index + 1),
      voter.name,
      voter.hasVoted ? color.green("так") : color.red("ні"),
    ]),
  );
}

/** Негативний сценарій 1: повторне голосування того самого виборця. */
function negativeDoubleVote(voter: Voter, commission: ElectionCommission): void {
  step("Сценарій 1. Повторне голосування (виборець №1 голосує вдруге)");
  info("бюлетень коректний і підписаний тим самим закритим ключем, змінено лише кандидата");
  verdict(commission.receive(voter.vote("К2", commission.publicKey)));
}

/** Негативний сценарій 2: особа, якої немає у списку допущених виборців. */
function negativeStranger(commission: ElectionCommission): void {
  step("Сценарій 2. Голосує стороння особа, якої немає у списку виборців");
  const stranger = new Voter("Стороння Мальвіна Олегівна", KEY_BITS);
  info("ключі згенеровані самостійно, але ВК їх не реєструвала");
  verdict(commission.receive(stranger.vote("К2", commission.publicKey)));
}

/** Негативний сценарій 3: спроба проголосувати від імені іншого виборця. */
function negativeImpersonation(attacker: Voter, victim: Voter, commission: ElectionCommission): void {
  step(`Сценарій 3. Голосування від чужого імені («${attacker.name}» видає себе за «${victim.name}»)`);
  const forged = serializeBallot({
    voterName: victim.name,
    candidateId: "К2",
    issuedAt: new Date().toISOString(),
  });
  // Закритого ключа жертви зловмисник не має, тому підписує власним.
  const signature = attacker.fillAndSign("К2").signature;
  const envelope: Envelope = {
    senderName: victim.name,
    cipher: sealFor({ ballot: forged, signature }, commission.publicKey),
  };
  info("ЕЦП сформовано закритим ключем зловмисника, а перевірятиметься ключем жертви");
  verdict(commission.receive(envelope));
}

/** Негативний сценарій 4: підміна вмісту бюлетеня після підписання. */
function negativeTampering(voter: Voter, commission: ElectionCommission): void {
  step(`Сценарій 4. Підміна бюлетеня «${voter.name}» по дорозі до ВК`);
  const signed = voter.fillAndSign("К1");
  const tampered = signed.ballot.replace('"candidateId":"К1"', '"candidateId":"К2"');
  info("відкритий ключ ВК доступний усім, тому підмінений бюлетень можна перешифрувати");
  info(`оригінал:  ${signed.ballot}`);
  info(`підміна:   ${tampered}`);
  const envelope: Envelope = {
    senderName: voter.name,
    cipher: sealFor({ ballot: tampered, signature: signed.signature }, commission.publicKey),
  };
  verdict(commission.receive(envelope));
}

/** Негативний сценарій 5: коректний ЕЦП, але зіпсоване заповнення бюлетеня. */
function negativeSpoiledBallot(voter: Voter, commission: ElectionCommission): void {
  step(`Сценарій 5. Зіпсований бюлетень «${voter.name}»: кандидата «К9» не існує`);
  info("ЕЦП правильний — він підтверджує авторство, але не коректність заповнення");
  verdict(commission.receive(voter.vote("К9", commission.publicKey)));
}

/** Окрема сесія: рівномірний розподіл голосів між кандидатами. */
function tieSession(): void {
  banner("ДОДАТКОВА СЕСІЯ — РІВНОМІРНИЙ РОЗПОДІЛ ГОЛОСІВ (НІЧИЯ)");
  const { commission, voters } = setupSession(VOTER_NAMES.slice(0, 4), false);

  note("Чотири виборці, два кандидати, голоси розподіляються порівну:");
  const choices = ["К1", "К2", "К1", "К2"] as const;
  voters.forEach((voter, index) => {
    const result = commission.receive(voter.vote(choices[index]!, commission.publicKey));
    note(
      result.status === "accepted"
        ? `  ${color.green("✔")} ${voter.name} → ${choices[index]}`
        : `  ${color.red("✘")} ${voter.name}: ${result.message}`,
    );
  });

  section("Результати сесії з рівним розподілом голосів");
  printResults(commission);
}

/** Зведення: які вимоги до ідеального протоколу забезпечує простий протокол. */
function propertySummary(): void {
  section("Відповідність вимогам до ідеального протоколу");
  table(
    ["Вимога", "Стан", "Механізм у реалізації"],
    [
      ["Голосують лише ті, хто має право", color.green("забезпечено"), "перевірка ПІБ у списку виборців ВК"],
      ["Не більше одного голосу", color.green("забезпечено"), "позначка hasVoted після прийняття бюлетеня"],
      ["Неможливо проголосувати за іншого", color.green("забезпечено"), "ЕЦП RSA закритим ключем виборця"],
      ["Неможливо таємно змінити голос", color.green("забезпечено"), "перевірка H = H_c після розшифрування"],
      ["Таємниця голосування", color.red("не забезпечено"), "ВК бачить ПІБ і вміст бюлетеня"],
      ["Перевірка виборцем свого голосу", color.red("не забезпечено"), "підрахунок повністю на боці ВК"],
    ],
  );
}

mainSession();
tieSession();
propertySummary();
console.log();
