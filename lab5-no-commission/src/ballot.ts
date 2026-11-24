import { randomBytes } from "node:crypto";

import { encryptLayer } from "./rsa.ts";
import { RP_LENGTH, type Candidate, type Roster, type RosterEntry, type Tally } from "./types.ts";

/**
 * Електронний бюлетень (EVP) — ім'я кандидата, доповнене пробілами до спільної довжини:
 * інакше довжина шифротексту видавала б вибір.
 */
export function formBallot(candidate: Candidate, candidates: readonly Candidate[]): string {
  const width = Math.max(...candidates.map(({ name }) => name.length));
  return candidate.name.padEnd(width, " ");
}

export function readBallot(evp: string, candidates: readonly Candidate[]): Candidate | undefined {
  return candidates.find((candidate) => formBallot(candidate, candidates) === evp);
}

/** Підрахунок, який кожен учасник виконує самостійно над опублікованими бюлетенями. */
export function countVotes(ballots: readonly string[], candidates: readonly Candidate[]): Tally {
  const votes = new Map(candidates.map(({ id }) => [id, 0]));
  let invalid = 0;
  for (const evp of ballots) {
    const candidate = readBallot(evp, candidates);
    if (candidate === undefined) {
      invalid += 1;
      continue;
    }
    votes.set(candidate.id, (votes.get(candidate.id) ?? 0) + 1);
  }
  return { votes, invalid };
}

export function sameTally(first: Tally, second: Tally): boolean {
  if (first.invalid !== second.invalid || first.votes.size !== second.votes.size) return false;
  return [...first.votes].every(([id, count]) => second.votes.get(id) === count);
}

/** Випадковий рядок RP із криптографічно стійкого генератора. */
export function randomRp(): string {
  const bytes = randomBytes(RP_LENGTH * 2);
  let rp = "";
  for (let index = 0; index < RP_LENGTH; index += 1) rp += String.fromCharCode(bytes.readUInt16BE(index * 2));
  return rp;
}

export type LayerTrace = { readonly layer: string; readonly rpAdded: boolean; readonly length: number };

/**
 * Один раунд багатошарового шифрування: шари накладаються у порядку, зворотному
 * до порядку розшифрування (для A, B, C, D, E — це E → D → C → B → A),
 * результат кожного шару є вхідними даними наступного. Перед шаром учасника,
 * для якого задано RP, цей RP дописується в кінець поточного повідомлення.
 */
export function wrapLayers(
  message: string,
  chain: Roster,
  rpFor: (entry: RosterEntry) => string | undefined = () => undefined,
  onLayer?: (trace: LayerTrace) => void,
): string {
  let current = message;
  for (const entry of [...chain].reverse()) {
    const rp = rpFor(entry);
    if (rp !== undefined) current += rp;
    current = encryptLayer(current, entry.publicKey);
    onLayer?.({ layer: entry.name, rpAdded: rp !== undefined, length: current.length });
  }
  return current;
}
