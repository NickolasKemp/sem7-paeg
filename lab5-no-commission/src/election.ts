import { createHash } from "node:crypto";

import { countVotes, formBallot, type LayerTrace } from "./ballot.ts";
import { ROUNDS, type Candidate, type Failure, type IncomingSet, type Publication, type Roster, type SignedSet } from "./types.ts";
import { Voter } from "./voter.ts";

/**
 * Хід протоколу між виборцями. Тут немає жодної довіреної сторони:
 * функції лише передають дані від одного виборця до іншого в порядку спільного списку,
 * усі перевірки виконують самі виборці.
 */

/** Передача набору: збір бюлетенів першим виборцем або передача від одного виборця наступному. */
export type Hop =
  | { readonly kind: "collect"; readonly to: string }
  | { readonly kind: "pass"; readonly round: number; readonly from: string; readonly to: string };

/** Втручання в канал або дії нечесного відправника; undefined — набір не передано. */
export type Tamper = (hop: Hop, set: IncomingSet) => IncomingSet | undefined;

export type StepRecord = {
  readonly round: number;
  readonly voter: string;
  readonly received: number;
  readonly verifiedSender: string | undefined;
  readonly output: SignedSet;
};

export type MixOutcome =
  | { readonly status: "completed"; readonly steps: readonly StepRecord[]; readonly final: SignedSet }
  | {
      readonly status: "aborted";
      readonly steps: readonly StepRecord[];
      readonly voter: string;
      readonly round: number;
      readonly failure: Failure;
    };

/**
 * Крок 1: учасники домовляються про впорядкований список (порядок реєстрації),
 * кожен генерує ключі й оголошує відкритий ключ, кожен складає власну копію списку.
 */
export function registerVoters(names: readonly string[]): Voter[] {
  const voters = names.map((name) => new Voter(name));
  const announcements = voters.map(({ name, publicKey }) => ({ name, publicKey }));
  for (const voter of voters) voter.acceptRoster(announcements.map((entry) => ({ ...entry })));
  return voters;
}

/** Відбиток копії списку: однаковий у всіх виборців означає однакові учасників, порядок і ключі. */
export function rosterFingerprint(roster: Roster): string {
  const text = roster.map(({ name, publicKey }) => `${name}:${publicKey.e}:${publicKey.n}`).join(";");
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

/** Крок 2: кожен виборець формує EVP і шифрує його; результат — набір, який отримує перший виборець. */
export function castBallots(
  voters: readonly Voter[],
  choices: readonly Candidate[],
  candidates: readonly Candidate[],
  onLayer?: (voter: string, trace: LayerTrace & { readonly round: number }) => void,
): string[] {
  return voters.map((voter, index) => {
    const choice = choices[index];
    if (choice === undefined) throw new Error(`Немає вибору для ${voter.name}`);
    return voter.castBallot(formBallot(choice, candidates), (trace) => onLayer?.(voter.name, trace));
  });
}

/** Кроки 3–4: ROUNDS раундів розшифрування, у кожному — усі виборці в порядку списку. */
export function mix(
  voters: readonly Voter[],
  ballots: readonly string[],
  options: { readonly tamper?: Tamper; readonly onStep?: (step: StepRecord) => void } = {},
): MixOutcome {
  const deliver = (hop: Hop, set: IncomingSet) => (options.tamper ? options.tamper(hop, set) : set);
  const first = voters[0];
  if (first === undefined) throw new Error("Немає учасників");

  const steps: StepRecord[] = [];
  let incoming = deliver({ kind: "collect", to: first.name }, { kind: "collected", ballots });
  let final: SignedSet | undefined;

  for (let round = 0; round < ROUNDS; round += 1) {
    for (const [index, voter] of voters.entries()) {
      if (incoming === undefined) {
        const failure = { reason: "NOT_RECEIVED", detail: "попередній учасник не передав набір — протокол зупинено" } as const;
        return { status: "aborted", steps, voter: voter.name, round, failure };
      }

      const result = voter.processSet(incoming, round);
      if (!result.ok) {
        return { status: "aborted", steps, voter: voter.name, round, failure: { reason: result.reason, detail: result.detail } };
      }

      const step = { round, voter: voter.name, received: incoming.ballots.length, verifiedSender: result.verifiedSender, output: result.output };
      steps.push(step);
      options.onStep?.(step);

      const next = voters[index + 1] ?? (round + 1 < ROUNDS ? first : undefined);
      if (next === undefined) {
        final = result.output;
        break;
      }
      incoming = deliver({ kind: "pass", round, from: voter.name, to: next.name }, result.output);
    }
  }

  if (final === undefined) throw new Error("Протокол завершився без остаточного набору");
  return { status: "completed", steps, final };
}

/** Крок 5: останній виборець публікує відкриті бюлетені й оголошує свій підрахунок. */
export function publish(final: SignedSet, candidates: readonly Candidate[]): Publication {
  return { set: final, announced: countVotes(final.ballots, candidates) };
}
