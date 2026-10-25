import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Запускає демонстрацію протоколу, зберігає повний вивід і нарізає його
 * на окремі HTML-«скріншоти» терміналу (ANSI → HTML), які далі
 * перетворюються на PNG через headless Chrome (див. tools/shots.sh).
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const assets = join(root, "assets");
mkdirSync(assets, { recursive: true });

const ESC = String.fromCharCode(27);
const ANSI = new RegExp(`${ESC}\\[([0-9;]*)m`, "g");

const COLORS: Record<string, string> = {
  "31": "#f38ba8",
  "32": "#a6e3a1",
  "33": "#f9e2af",
  "35": "#cba6f7",
  "36": "#89dceb",
};

const plain = (text: string) => text.replace(ANSI, "");
const escapeHtml = (text: string) =>
  text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Перетворює ANSI-послідовності у вкладені <span> зі стилями. */
function ansiToHtml(text: string): string {
  let html = "";
  let index = 0;
  let open = 0;

  for (const match of text.matchAll(ANSI)) {
    html += escapeHtml(text.slice(index, match.index));
    index = match.index + match[0].length;

    const code = match[1] ?? "";
    if (code === "0" || code === "") {
      html += "</span>".repeat(open);
      open = 0;
      continue;
    }
    const style =
      code === "1" ? "font-weight:700" : code === "2" ? "opacity:.62" : `color:${COLORS[code] ?? "#cdd6f4"}`;
    html += `<span style="${style}">`;
    open += 1;
  }
  html += escapeHtml(text.slice(index)) + "</span>".repeat(open);
  return html;
}

const FONT_SIZE = 15;
const LINE_HEIGHT = 21;
const CHAR_WIDTH = 9.03; // Menlo 15px
const PADDING = 26;

function page(title: string, lines: readonly string[]): { html: string; width: number; height: number } {
  const columns = Math.max(60, ...lines.map((line) => plain(line).length));
  const width = Math.ceil(columns * CHAR_WIDTH) + PADDING * 2 + 4;
  const height = lines.length * LINE_HEIGHT + PADDING * 2 + 34 + 6;

  const html = `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
  html,body{margin:0;background:#11111b;}
  .window{width:${width}px;box-sizing:border-box;background:#1e1e2e;border-radius:10px;overflow:hidden;
    font-family:Menlo,'SF Mono',monospace;font-size:${FONT_SIZE}px;line-height:${LINE_HEIGHT}px;color:#cdd6f4;}
  .bar{height:34px;display:flex;align-items:center;gap:8px;padding:0 14px;background:#181825;}
  .dot{width:11px;height:11px;border-radius:50%;}
  .bar span.t{margin-left:10px;color:#9399b2;font-size:12px;}
  pre{margin:0;padding:${PADDING}px;white-space:pre;}
</style>
<div class="window">
  <div class="bar">
    <div class="dot" style="background:#f38ba8"></div>
    <div class="dot" style="background:#f9e2af"></div>
    <div class="dot" style="background:#a6e3a1"></div>
    <span class="t">${escapeHtml(title)}</span>
  </div>
  <pre>${lines.map(ansiToHtml).join("\n")}</pre>
</div>`;

  return { html, width, height };
}

type Shot = { file: string; title: string; from: string; to?: string };

const SHOTS: readonly Shot[] = [
  {
    file: "01-setup",
    title: "node src/main.ts — крок 1: ключі, список виборців, список кандидатів",
    from: "ЛАБОРАТОРНА РОБОТА №1",
    to: "КРОКИ 2–3",
  },
  {
    file: "02-positive",
    title: "node src/main.ts — кроки 2–3: коректні бюлетені та перевірки ВК",
    from: "КРОКИ 2–3",
    to: "НЕГАТИВНІ СЦЕНАРІЇ",
  },
  {
    file: "03-negative-1",
    title: "node src/main.ts — негативні сценарії 1–3",
    from: "НЕГАТИВНІ СЦЕНАРІЇ",
    to: "Сценарій 4.",
  },
  {
    file: "04-negative-2",
    title: "node src/main.ts — негативні сценарії 4–5",
    from: "Сценарій 4.",
    to: "ПРОДОВЖЕННЯ ГОЛОСУВАННЯ",
  },
  {
    file: "05-results",
    title: "node src/main.ts — крок 4: підрахунок голосів і публікація результатів",
    from: "КРОК 4.",
    to: "ДОДАТКОВА СЕСІЯ",
  },
  {
    file: "06-tie",
    title: "node src/main.ts — рівний розподіл голосів і відповідність вимогам протоколу",
    from: "ДОДАТКОВА СЕСІЯ",
  },
];

const output = execFileSync("node", [join(root, "src", "main.ts")], {
  encoding: "utf8",
  env: { ...process.env, FORCE_COLOR: "1" },
});
writeFileSync(join(assets, "demo-output.txt"), plain(output));

const lines = output.split("\n");
const findLine = (needle: string, start = 0) =>
  lines.findIndex((line, index) => index >= start && plain(line).includes(needle));

/** Верхня рамка банера стоїть рядком вище за його текст — беремо її разом. */
const isBoxBorder = (line: string | undefined) => {
  const text = plain(line ?? "x");
  return /[╔╚╗╝═║]/.test(text) && /^[╔╚╗╝═║\s]+$/.test(text);
};

for (const shot of SHOTS) {
  const found = findLine(shot.from);
  if (found < 0) throw new Error(`Не знайдено початок фрагмента: ${shot.from}`);
  const start = isBoxBorder(lines[found - 1]) ? found - 1 : found;
  const end = shot.to ? findLine(shot.to, start + 1) : lines.length;

  const fragment = lines.slice(start, end < 0 ? lines.length : end);
  while (fragment.length > 0 && plain(fragment[0] ?? "").trim() === "") fragment.shift();
  while (fragment.length > 0 && (plain(fragment.at(-1) ?? "").trim() === "" || isBoxBorder(fragment.at(-1)))) {
    fragment.pop();
  }

  const { html, width, height } = page(shot.title, fragment);
  writeFileSync(join(assets, `${shot.file}.html`), html);
  writeFileSync(join(assets, `${shot.file}.size`), `${width}x${height}`);
  console.log(`${shot.file}: ${fragment.length} рядків, ${width}x${height}`);
}

/** Окремо готуємо скріншот запуску тестів. */
const tests = execFileSync("node", ["--test", "tests/rsa.test.ts", "tests/protocol.test.ts"], {
  cwd: root,
  encoding: "utf8",
  env: { ...process.env, FORCE_COLOR: "1" },
});
const testLines = tests.split("\n").filter((line) => {
  const text = plain(line);
  return text.trim() !== "" && !/^ℹ (suites|cancelled|skipped|todo)/.test(text);
});
const testPage = page("node --test tests/*.test.ts — модульні тести", testLines);
writeFileSync(join(assets, "07-tests.html"), testPage.html);
writeFileSync(join(assets, "07-tests.size"), `${testPage.width}x${testPage.height}`);
console.log(`07-tests: ${testLines.length} рядків, ${testPage.width}x${testPage.height}`);
