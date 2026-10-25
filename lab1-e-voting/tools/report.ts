import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AlignmentType,
  Document,
  ImageRun,
  LevelFormat,
  PageBreak,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from "docx";

import { REPORT, TITLE_PAGE, type Block } from "./report-content.ts";

/**
 * Формує звіт до лабораторної роботи у двох форматах з одного джерела:
 *   report/Звіт_ЛР1_ПАЕГ.docx — основний документ (Times New Roman 14, інтервал 1.5,
 *                               абзацний відступ 1.25 см, вирівнювання по ширині);
 *   report/Звіт_ЛР1_ПАЕГ.pdf  — той самий текст для швидкого перегляду (headless Chrome).
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const assets = join(root, "assets");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const CM = 567; // 1 см у twips
const FONT = "Times New Roman";
const SIZE = 28; // 14 pt у півпунктах
const LINE = 360; // інтервал 1.5
const INDENT = Math.round(1.25 * CM);
const CONTENT_WIDTH_PX = 620; // ширина сторінки за вирахуванням полів, у пікселях 96 dpi

/** Розміри PNG беремо з блоку IHDR, щоб зберегти пропорції зображення. */
function pngSize(file: string): { width: number; height: number } {
  const buffer = readFileSync(file);
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

function imageBox(file: string): { width: number; height: number } {
  const { width, height } = pngSize(file);
  return { width: CONTENT_WIDTH_PX, height: Math.round((CONTENT_WIDTH_PX * height) / width) };
}

const text = (value: string, bold = false) => new TextRun({ text: value, bold, font: FONT, size: SIZE });

const bodyParagraph = (value: string) =>
  new Paragraph({
    children: [text(value)],
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: LINE },
    indent: { firstLine: INDENT },
  });

const headingParagraph = (value: string) =>
  new Paragraph({
    children: [text(value, true)],
    alignment: AlignmentType.LEFT,
    spacing: { line: LINE, before: 240, after: 120 },
  });

const captionParagraph = (value: string) =>
  new Paragraph({
    children: [new TextRun({ text: value, font: FONT, size: 24 })],
    alignment: AlignmentType.CENTER,
    spacing: { line: 240, before: 60, after: 240 },
  });

const codeParagraph = (line: string, first: boolean, last: boolean) =>
  new Paragraph({
    children: [new TextRun({ text: line === "" ? " " : line, font: "Courier New", size: 20 })],
    alignment: AlignmentType.LEFT,
    spacing: { line: 240, before: first ? 60 : 0, after: last ? 120 : 0 },
    shading: { type: ShadingType.CLEAR, fill: "F4F4F4" },
  });

function tableBlock(block: Extract<Block, { kind: "table" }>): (Table | Paragraph)[] {
  const cell = (value: string, bold: boolean, width: number) =>
    new TableCell({
      width: { size: width, type: WidthType.DXA },
      shading: bold ? { type: ShadingType.CLEAR, fill: "EFEFEF" } : undefined,
      children: [
        new Paragraph({
          children: [new TextRun({ text: value, bold, font: FONT, size: 24 })],
          alignment: AlignmentType.LEFT,
          spacing: { line: 240, before: 40, after: 40 },
        }),
      ],
    });

  const table = new Table({
    columnWidths: [...block.widths],
    width: { size: block.widths.reduce((sum, value) => sum + value, 0), type: WidthType.DXA },
    rows: [
      new TableRow({
        tableHeader: true,
        children: block.headers.map((header, index) => cell(header, true, block.widths[index] ?? 2000)),
      }),
      ...block.rows.map(
        (row) =>
          new TableRow({
            children: row.map((value, index) => cell(value, false, block.widths[index] ?? 2000)),
          }),
      ),
    ],
  });

  return [table, captionParagraph(block.caption)];
}

let listInstance = 0;

function renderBlock(block: Block): (Paragraph | Table)[] {
  switch (block.kind) {
    case "heading":
      return [headingParagraph(block.text)];
    case "paragraph":
      return [bodyParagraph(block.text)];
    case "question":
      return [
        new Paragraph({
          children: [text(block.text, true)],
          alignment: AlignmentType.JUSTIFIED,
          spacing: { line: LINE, before: 120 },
          indent: { firstLine: INDENT },
        }),
      ];
    case "bullets":
    case "numbered": {
      // Окремий instance змушує Word почати нумерацію кожного списку з 1.
      listInstance += 1;
      const instance = listInstance;
      return block.items.map(
        (item) =>
          new Paragraph({
            children: [text(item)],
            alignment: AlignmentType.JUSTIFIED,
            spacing: { line: LINE },
            numbering: { reference: block.kind === "bullets" ? "dashes" : "decimals", level: 0, instance },
          }),
      );
    }
    case "code": {
      const lines = block.code.split("\n");
      return [
        ...lines.map((line, index) => codeParagraph(line, index === 0, index === lines.length - 1)),
        captionParagraph(block.caption),
      ];
    }
    case "figure": {
      const file = join(assets, block.image);
      return [
        new Paragraph({
          children: [new ImageRun({ type: "png", data: readFileSync(file), transformation: imageBox(file) })],
          alignment: AlignmentType.CENTER,
          spacing: { before: 120, after: 60 },
        }),
        captionParagraph(block.caption),
      ];
    }
    case "table":
      return tableBlock(block);
    case "pagebreak":
      return [new Paragraph({ children: [new PageBreak()] })];
  }
}

function titlePage(): Paragraph[] {
  const centered = (value: string, options: { bold?: boolean; size?: number; before?: number } = {}) =>
    new Paragraph({
      children: [new TextRun({ text: value, bold: options.bold ?? false, font: FONT, size: options.size ?? SIZE })],
      alignment: AlignmentType.CENTER,
      spacing: { line: LINE, before: options.before ?? 0 },
    });

  const right = (value: string) =>
    new Paragraph({
      children: [text(value)],
      alignment: AlignmentType.RIGHT,
      spacing: { line: LINE },
    });

  return [
    centered(TITLE_PAGE.ministry),
    centered(`Дисципліна: ${TITLE_PAGE.discipline}`, { before: 240 }),
    centered("ЗВІТ", { bold: true, size: 32, before: 2400 }),
    centered("до лабораторної роботи №1", { bold: true, size: 32 }),
    centered(TITLE_PAGE.topic, { before: 480 }),
    right(TITLE_PAGE.author),
    new Paragraph({ children: [text(TITLE_PAGE.authorName)], alignment: AlignmentType.RIGHT, spacing: { line: LINE, before: 1200 } }),
    right(TITLE_PAGE.reviewer),
    centered(TITLE_PAGE.year, { before: 1800 }),
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

const document = new Document({
  creator: "Лабораторна робота №1 (ПАЕГ)",
  title: "Звіт до лабораторної роботи №1 — простий протокол Е-голосування",
  styles: {
    default: {
      document: {
        run: { font: FONT, size: SIZE },
        paragraph: { spacing: { line: LINE }, alignment: AlignmentType.JUSTIFIED },
      },
    },
  },
  numbering: {
    config: [
      {
        reference: "dashes",
        levels: [
          {
            level: 0,
            format: LevelFormat.BULLET,
            text: "–",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: INDENT + 284, hanging: 284 } } },
          },
        ],
      },
      {
        reference: "decimals",
        levels: [
          {
            level: 0,
            format: LevelFormat.DECIMAL,
            text: "%1.",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: INDENT + 284, hanging: 284 } } },
          },
        ],
      },
    ],
  },
  sections: [
    {
      properties: {
        page: { margin: { top: 2 * CM, bottom: 2 * CM, left: 3 * CM, right: Math.round(1.5 * CM) } },
      },
      children: [...titlePage(), ...REPORT.flatMap(renderBlock)],
    },
  ],
});

const docxPath = join(root, "report", "Звіт_ЛР1_ПАЕГ.docx");
writeFileSync(docxPath, await Packer.toBuffer(document));
console.log(`Створено ${docxPath}`);

/* ------------------------------ PDF-версія ------------------------------ */

const escapeHtml = (value: string) =>
  value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function blockHtml(block: Block): string {
  switch (block.kind) {
    case "heading":
      return `<h2>${escapeHtml(block.text)}</h2>`;
    case "paragraph":
      return `<p>${escapeHtml(block.text)}</p>`;
    case "question":
      return `<p class="question">${escapeHtml(block.text)}</p>`;
    case "bullets":
      return `<ul>${block.items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
    case "numbered":
      return `<ol>${block.items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`;
    case "code":
      return `<pre>${escapeHtml(block.code)}</pre><div class="caption">${escapeHtml(block.caption)}</div>`;
    case "figure":
      return `<figure><img src="file://${join(assets, block.image)}"><figcaption>${escapeHtml(block.caption)}</figcaption></figure>`;
    case "table":
      return `<table>
        <tr>${block.headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr>
        ${block.rows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(value)}</td>`).join("")}</tr>`).join("")}
      </table><div class="caption">${escapeHtml(block.caption)}</div>`;
    case "pagebreak":
      return `<div class="page-break"></div>`;
  }
}

const html = `<!doctype html><meta charset="utf-8">
<style>
  @page{size:A4;margin:2cm 1.5cm 2cm 3cm}
  body{font-family:'Times New Roman',serif;font-size:14pt;line-height:1.5;text-align:justify;color:#000;margin:0}
  p{margin:0;text-indent:1.25cm}
  h2{font-size:14pt;font-weight:700;text-align:left;margin:12pt 0 6pt}
  p.question{font-weight:700;margin-top:6pt}
  ul,ol{margin:0 0 0 1.25cm;padding-left:0.6cm}
  li{margin:0}
  pre{font-family:'Courier New',monospace;font-size:10pt;line-height:1.2;background:#f4f4f4;
    padding:6pt 8pt;white-space:pre-wrap;text-align:left;margin:6pt 0 0;page-break-inside:avoid}
  .caption{text-align:center;font-size:12pt;text-indent:0;margin:3pt 0 12pt}
  figure{margin:6pt 0 0;text-align:center;page-break-inside:avoid}
  figure img{max-width:100%}
  figcaption{text-align:center;font-size:12pt;margin:3pt 0 12pt}
  table{border-collapse:collapse;width:100%;font-size:12pt;page-break-inside:avoid}
  th,td{border:1px solid #000;padding:3pt 5pt;text-align:left;vertical-align:top;line-height:1.2}
  th{background:#efefef}
  .page-break{page-break-after:always}
  .title-page{text-align:center;page-break-after:always}
  .title-page .work{font-size:16pt;font-weight:700;margin-top:6cm}
  .title-page .who{text-align:right;margin-top:4cm}
  .title-page .year{margin-top:3cm}
</style>
<div class="title-page">
  <p style="text-indent:0">${escapeHtml(TITLE_PAGE.ministry)}</p>
  <p style="text-indent:0">Дисципліна: ${escapeHtml(TITLE_PAGE.discipline)}</p>
  <p class="work" style="text-indent:0">ЗВІТ<br>до лабораторної роботи №1</p>
  <p style="text-indent:0;margin-top:1cm">${escapeHtml(TITLE_PAGE.topic)}</p>
  <div class="who">
    <p style="text-indent:0">${escapeHtml(TITLE_PAGE.author)}</p>
    <p style="text-indent:0;margin-top:1cm">${escapeHtml(TITLE_PAGE.authorName)}</p>
    <p style="text-indent:0">${escapeHtml(TITLE_PAGE.reviewer)}</p>
  </div>
  <p class="year" style="text-indent:0">${escapeHtml(TITLE_PAGE.year)}</p>
</div>
${REPORT.map(blockHtml).join("\n")}`;

const htmlPath = join(root, "report", "report.html");
const pdfPath = join(root, "report", "Звіт_ЛР1_ПАЕГ.pdf");
writeFileSync(htmlPath, html);

execFileSync(CHROME, [
  "--headless",
  "--disable-gpu",
  "--no-pdf-header-footer",
  "--virtual-time-budget=5000",
  `--print-to-pdf=${pdfPath}`,
  `file://${htmlPath}`,
]);
console.log(`Створено ${pdfPath}`);
