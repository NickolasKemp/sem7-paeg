/** Дрібні хелпери для читабельного виводу протоколу в термінал. */

const ESC = String.fromCharCode(27);
const enabled = process.env["NO_COLOR"] === undefined;
const wrap = (code: string) => (text: string) =>
  enabled ? `${ESC}[${code}m${text}${ESC}[0m` : text;

export const color = {
  bold: wrap("1"),
  dim: wrap("2"),
  red: wrap("31"),
  green: wrap("32"),
  yellow: wrap("33"),
  blue: wrap("36"),
  magenta: wrap("35"),
};

export const WIDTH = 94;

const ANSI_PATTERN = new RegExp(`${ESC}\\[[0-9;]*m`, "g");
const visibleLength = (text: string) => text.replace(ANSI_PATTERN, "").length;

export function banner(text: string): void {
  const line = "═".repeat(WIDTH);
  const padding = Math.max(0, Math.floor((WIDTH - visibleLength(text)) / 2));
  console.log(color.blue(`╔${line}╗`));
  console.log(
    color.blue("║") +
      " ".repeat(padding) +
      color.bold(text) +
      " ".repeat(Math.max(0, WIDTH - padding - visibleLength(text))) +
      color.blue("║"),
  );
  console.log(color.blue(`╚${line}╝`));
}

export function section(text: string): void {
  console.log();
  console.log(color.bold(color.yellow(`▌ ${text}`)));
  console.log(color.dim("─".repeat(WIDTH)));
}

export function step(text: string): void {
  console.log(color.bold(color.magenta(`\n  ▸ ${text}`)));
}

export const ok = (text: string) => console.log(`    ${color.green("✔")} ${text}`);
export const fail = (text: string) => console.log(`    ${color.red("✘")} ${text}`);
export const info = (text: string) => console.log(`    ${color.dim("·")} ${color.dim(text)}`);
export const note = (text: string) => console.log(`  ${text}`);

/** Проста таблиця з вирівнюванням стовпців. */
export function table(headers: readonly string[], rows: readonly (readonly string[])[]): void {
  const widths = headers.map((header, index) =>
    Math.max(visibleLength(header), ...rows.map((row) => visibleLength(row[index] ?? ""))),
  );
  const line = (left: string, mid: string, right: string) =>
    color.dim(left + widths.map((w) => "─".repeat(w + 2)).join(mid) + right);

  const render = (cells: readonly string[]) =>
    color.dim("│") +
    cells
      .map((cell, index) => ` ${cell}${" ".repeat((widths[index] ?? 0) - visibleLength(cell))} `)
      .join(color.dim("│")) +
    color.dim("│");

  console.log(line("┌", "┬", "┐"));
  console.log(render(headers.map((header) => color.bold(header))));
  console.log(line("├", "┼", "┤"));
  for (const row of rows) console.log(render(row));
  console.log(line("└", "┴", "┘"));
}
