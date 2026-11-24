import { formBallot, randomRp, wrapLayers } from "./ballot.ts";
import { ROUNDS, RP_LENGTH, type Candidate, type Roster } from "./types.ts";

/**
 * Дії нечесних учасників для негативних сценаріїв і аналізу.
 * Усе, що тут використовується, доступне кожному: відкриті ключі зі спільного списку
 * та набори, які учасник легально отримує під час протоколу.
 */

/** Сфабрикований бюлетень: усі раунди шифрування відкритими ключами, але без жодного RP. */
export function fabricateBallot(evp: string, roster: Roster): string {
  let ballot = evp;
  for (let round = 0; round < ROUNDS; round += 1) ballot = wrapLayers(ballot, roster);
  return ballot;
}

/** Підробка бюлетеня власника `owner` для решти ланцюжка: замість справжнього RP — випадковий. */
export function forgeWithWrongRp(evp: string, chain: Roster, owner: string): string {
  return wrapLayers(evp, chain, (entry) => (entry.name === owner ? randomRp() : undefined));
}

/**
 * Довжина шифротексту залежить від того, перед яким шаром дописано RP, тобто від позиції власника.
 * Тому бюлетень конкретного виборця знаходиться за довжиною, попри перемішування.
 */
export function findByLength(ballots: readonly string[], length: number): number {
  return ballots.findIndex((ballot) => ballot.length === length);
}

/**
 * Після зняття RP решта шарів детермінована: учасник може сам зашифрувати бюлетень
 * кожного кандидата ключами решти ланцюжка й порахувати збіги в отриманому наборі.
 */
export function peekTally(ballots: readonly string[], chain: Roster, candidates: readonly Candidate[]): Map<number, number> {
  const tally = new Map<number, number>();
  for (const candidate of candidates) {
    const sample = wrapLayers(formBallot(candidate, candidates), chain);
    tally.set(candidate.id, ballots.filter((ballot) => ballot === sample).length);
  }
  return tally;
}

/**
 * Довжина бюлетеня (у символах) після всіх раундів шифрування для виборця на позиції `position`
 * (0 — перший у списку) серед `voters` учасників: кожен шар подвоює довжину.
 */
export function ballotLength(voters: number, position: number, evpLength: number): number {
  let length = evpLength;
  for (let round = 0; round < ROUNDS; round += 1) {
    for (let layer = voters - 1; layer >= 0; layer -= 1) {
      if (layer === position) length += RP_LENGTH;
      length *= 2;
    }
  }
  return length;
}
