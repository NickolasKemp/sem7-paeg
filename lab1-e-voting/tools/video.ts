import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SCENES, type Scene } from "./scenes.ts";

/**
 * Збирає відеопояснення роботи:
 *   1) кожна сцена рендериться у PNG (headless Chrome, 1920×1080);
 *   2) текст диктора озвучується системним синтезатором (`say`, голос Lesya);
 *   3) картинка + звук склеюються у фрагмент mp4 (ffmpeg) із плавними переходами;
 *   4) фрагменти зшиваються в один файл video/lab1-demo.mp4.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = join(root, "video", "build");
const assets = join(root, "assets");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const WIDTH = 1920;
const HEIGHT = 1080;
const FADE = 0.4;
const TAIL = 1.0;

const escapeHtml = (text: string) =>
  text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const KEYWORDS =
  /\b(export|function|return|const|let|class|readonly|new|if|else|for|of|in|type|interface|import|from|throw|this|true|false|null|void|async|await)\b/g;
const TYPES =
  /\b(string|number|bigint|boolean|KeyPair|PublicKey|PrivateKey|Envelope|SignedBallot|ProcessingResult|Voter)\b/g;
const COMMENTS = /\/\*\*?[\s\S]*?\*\/|\/\/[^\n]*/g;
const STRINGS = /(&quot;|&#39;|["'`])(?:\\.|(?!\1)[^\\])*\1/g;
const NUMBERS = /\b(\d+n?)\b/g;

const MARK = String.fromCharCode(0xe000); // службовий символ приватної зони Unicode
const ALPHABET = "ABCDEFGHIJ";

/**
 * Мінімальне підсвічування синтаксису TypeScript для слайдів із кодом.
 * Коментарі та рядки ховаються під літерні мітки (цифри не використовуємо,
 * бо їх зачепило б правило підсвічування чисел) і повертаються в кінці.
 */
function highlight(code: string): string {
  const kept: string[] = [];
  const label = (index: number) =>
    MARK + ALPHABET[index % 10] + ALPHABET[Math.floor(index / 10)] + MARK;
  const keep = (html: string) => {
    kept.push(html);
    return label(kept.length - 1);
  };

  const html = escapeHtml(code)
    .replace(COMMENTS, (match) => keep(`<span class="c">${match}</span>`))
    .replace(STRINGS, (match) => keep(`<span class="s">${match}</span>`))
    .replace(KEYWORDS, '<span class="k">$1</span>')
    .replace(TYPES, '<span class="t">$1</span>')
    .replace(NUMBERS, '<span class="n">$1</span>');

  const restore = new RegExp(`${MARK}([A-J])([A-J])${MARK}`, "g");
  return html.replace(
    restore,
    (_, ones: string, tens: string) => kept[ALPHABET.indexOf(tens) * 10 + ALPHABET.indexOf(ones)] ?? "",
  );
}

const SHELL = `
  *{box-sizing:border-box}
  html,body{margin:0;width:${WIDTH}px;height:${HEIGHT}px;overflow:hidden}
  body{background:radial-gradient(1200px 700px at 78% -10%, #2a2a45 0%, #11111b 62%);
    color:#cdd6f4;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
  .frame{width:100%;height:100%;padding:64px 80px;display:flex;flex-direction:column;position:relative}
  .accent{position:absolute;left:0;top:0;width:10px;height:100%;
    background:linear-gradient(180deg,#89dceb,#cba6f7 55%,#f9e2af)}
  h1{font-size:60px;line-height:1.14;margin:0 0 26px;font-weight:700;letter-spacing:-.5px}
  h2{font-size:46px;line-height:1.16;margin:0 0 10px;font-weight:700;letter-spacing:-.3px;color:#f9e2af}
  .caption{font-size:24px;color:#9399b2;margin:0 0 30px;font-family:Menlo,monospace}
  ul{list-style:none;padding:0;margin:14px 0 0;display:flex;flex-direction:column;gap:26px}
  li{font-size:33px;line-height:1.34;padding-left:52px;position:relative;color:#e6e9f5}
  li:before{content:'';position:absolute;left:0;top:14px;width:22px;height:22px;border-radius:6px;
    background:linear-gradient(135deg,#89dceb,#cba6f7)}
  pre{margin:0;background:#181825;border:1px solid #2a2b3c;border-radius:16px;padding:34px 38px;
    font-family:Menlo,'SF Mono',monospace;white-space:pre;overflow:hidden;color:#cdd6f4}
  .k{color:#cba6f7}.s{color:#a6e3a1}.c{color:#7f849c;font-style:italic}.t{color:#89dceb}.n{color:#fab387}
  .shot{flex:1;display:flex;align-items:center;justify-content:center;min-height:0}
  .shot img{max-width:100%;max-height:100%;border-radius:14px;box-shadow:0 26px 70px rgba(0,0,0,.55)}
  .footer{position:absolute;right:80px;bottom:52px;font-size:22px;color:#6c7086;letter-spacing:2px}
`;

const DIAGRAM = `
<div style="flex:1;display:flex;flex-direction:column;justify-content:center;gap:26px;font-size:24px">
  <div style="display:flex;align-items:stretch;gap:26px">
    <div style="flex:1;background:#181825;border:1px solid #2a2b3c;border-radius:18px;padding:28px 30px">
      <div style="color:#89dceb;font-size:27px;font-weight:700;margin-bottom:16px">Виборець (×5)</div>
      <div style="line-height:1.62;color:#bac2de">
        1. Генерує пару ключів RSA<br>
        2. Заповнює бюлетень<br>
        3. ЕЦП = H<sup>d</sup> mod n<br>
        4. Шифрує ключем ВК: c = m<sup>e</sup> mod n
      </div>
    </div>
    <div style="align-self:center;text-align:center;color:#f9e2af;font-size:26px;min-width:290px">
      <div style="font-family:Menlo,monospace;font-size:20px;color:#9399b2;margin-bottom:10px">відкритий ключ ЕЦП</div>
      <div style="font-size:40px;color:#585b70">──────────▶</div>
      <div style="margin-top:26px;font-family:Menlo,monospace;font-size:20px;color:#9399b2">зашифрований бюлетень</div>
      <div style="font-size:40px;color:#585b70">──────────▶</div>
    </div>
    <div style="flex:1;background:#181825;border:1px solid #2a2b3c;border-radius:18px;padding:28px 30px">
      <div style="color:#cba6f7;font-size:27px;font-weight:700;margin-bottom:16px">Виборча комісія</div>
      <div style="line-height:1.62;color:#bac2de">
        1. Список виборців + їх відкриті ключі<br>
        2. Список кандидатів<br>
        3. Публікує власний відкритий ключ<br>
        4. m = c<sup>d</sup> mod n, перевірки, підрахунок
      </div>
    </div>
  </div>
  <div style="display:flex;gap:18px;justify-content:center;flex-wrap:wrap;margin-top:6px">
    ${["у списку виборців?", "ЕЦП справжній?", "не голосував раніше?", "бюлетень коректний?"]
      .map(
        (check) =>
          `<div style="background:#1e1e2e;border:1px solid #45475a;border-radius:999px;padding:14px 26px;color:#a6e3a1;font-size:23px">✔ ${check}</div>`,
      )
      .join("")}
  </div>
</div>`;

function slideHtml(scene: Scene): string {
  const body = (() => {
    switch (scene.kind) {
      case "title":
        return `<div class="frame" style="justify-content:center;align-items:flex-start">
          <div style="font-size:26px;letter-spacing:6px;color:#89dceb;margin-bottom:26px">${escapeHtml(scene.subtitle.toUpperCase())}</div>
          <h1 style="font-size:82px;max-width:1500px">${escapeHtml(scene.title)}</h1>
          <div style="font-size:30px;color:#9399b2;margin-top:12px">${escapeHtml(scene.footer)}</div>
        </div>`;
      case "bullets":
        return `<div class="frame">
          <h2>${escapeHtml(scene.heading)}</h2>
          <ul>${scene.items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        </div>`;
      case "code": {
        const lines = scene.code.split("\n").length;
        const size = lines > 18 ? 22 : lines > 14 ? 25 : 28;
        return `<div class="frame">
          <h2>${escapeHtml(scene.heading)}</h2>
          <p class="caption">${escapeHtml(scene.caption)}</p>
          <pre style="font-size:${size}px;line-height:${Math.round(size * 1.5)}px">${highlight(scene.code)}</pre>
        </div>`;
      }
      case "image":
        return `<div class="frame">
          <h2>${escapeHtml(scene.heading)}</h2>
          <p class="caption">${escapeHtml(scene.caption)}</p>
          <div class="shot"><img src="file://${join(assets, scene.image)}"></div>
        </div>`;
      case "diagram":
        return `<div class="frame"><h2>${escapeHtml(scene.heading)}</h2>${DIAGRAM}</div>`;
    }
  })();

  return `<!doctype html><meta charset="utf-8"><style>${SHELL}</style><div class="accent"></div>${body}
    <div class="footer">ПАЕГ · ЛР №1</div>`;
}

function run(command: string, args: readonly string[]): string {
  return execFileSync(command, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

function durationOf(file: string): number {
  const output = run("ffprobe", [
    "-v",
    "error",
    "-show_entries",
    "format=duration",
    "-of",
    "default=noprint_wrappers=1:nokey=1",
    file,
  ]);
  return Number.parseFloat(output.trim());
}

rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });

const segments: string[] = [];

for (const scene of SCENES) {
  const html = join(work, `${scene.id}.html`);
  const png = join(work, `${scene.id}.png`);
  const aiff = join(work, `${scene.id}.aiff`);
  const mp4 = join(work, `${scene.id}.mp4`);

  writeFileSync(html, slideHtml(scene));
  run(CHROME, [
    "--headless",
    "--disable-gpu",
    "--hide-scrollbars",
    "--virtual-time-budget=2000",
    `--window-size=${WIDTH},${HEIGHT}`,
    `--screenshot=${png}`,
    `file://${html}`,
  ]);

  run("say", ["-v", "Lesya", "-r", "168", "-o", aiff, scene.narration]);
  const speech = durationOf(aiff);
  const total = FADE + speech + TAIL;

  run("ffmpeg", [
    "-y",
    "-loglevel",
    "error",
    "-loop",
    "1",
    "-i",
    png,
    "-i",
    aiff,
    "-filter_complex",
    `[0:v]scale=${WIDTH}:${HEIGHT},fade=t=in:st=0:d=${FADE},fade=t=out:st=${(total - FADE).toFixed(2)}:d=${FADE},format=yuv420p[v];` +
      `[1:a]adelay=${Math.round(FADE * 1000)}|${Math.round(FADE * 1000)},apad=whole_dur=${total.toFixed(2)}[a]`,
    "-map",
    "[v]",
    "-map",
    "[a]",
    "-t",
    total.toFixed(2),
    "-r",
    "30",
    "-c:v",
    "libx264",
    "-preset",
    "medium",
    "-crf",
    "20",
    "-tune",
    "stillimage",
    "-c:a",
    "aac",
    "-b:a",
    "160k",
    "-ar",
    "44100",
    "-ac",
    "2",
    mp4,
  ]);

  segments.push(mp4);
  console.log(`${scene.id}: озвучення ${speech.toFixed(1)} с → фрагмент ${total.toFixed(1)} с`);
}

const listFile = join(work, "segments.txt");
writeFileSync(listFile, segments.map((file) => `file '${file}'`).join("\n"));

const output = join(root, "video", "lab1-demo.mp4");
run("ffmpeg", ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", listFile, "-c", "copy", output]);

/** Текст диктора зберігаємо поруч — зручно для звіту та перевірки. */
writeFileSync(
  join(root, "video", "narration.txt"),
  SCENES.map((scene) => `[${scene.id}]\n${scene.narration}`).join("\n\n"),
);

const total = durationOf(output);
console.log(`\nГотово: ${output} (${Math.floor(total / 60)} хв ${Math.round(total % 60)} с)`);
