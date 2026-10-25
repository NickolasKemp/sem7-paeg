/**
 * Поділ ID кандидата на два цілі множники.
 *
 * Множник «приховує» вибір, якщо він ділить ID щонайменше двох кандидатів:
 * побачивши такий множник, ВК не може однозначно сказати, за кого голос.
 */

export type Split = readonly [first: bigint, second: bigint];

/** Усі впорядковані розклади id = a · b з нетривіальними множниками (a, b > 1). */
export function factorPairs(id: bigint): Split[] {
  const pairs: Split[] = [];
  for (let a = 2n; a * 2n <= id; a += 1n) {
    if (id % a === 0n && id / a > 1n) pairs.push([a, id / a]);
  }
  return pairs;
}

/** Кількість ID кандидатів, частиною яких може бути множник. */
export function candidatesSharing(factor: bigint, ids: readonly bigint[]): number {
  return ids.filter((id) => id % factor === 0n).length;
}

/** Розклади, у яких обидва множники не видають кандидата. */
export function hidingSplits(id: bigint, ids: readonly bigint[]): Split[] {
  return factorPairs(id).filter((pair) => pair.every((factor) => candidatesSharing(factor, ids) >= 2));
}
