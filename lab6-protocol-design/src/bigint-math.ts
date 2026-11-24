import { randomBytes } from "node:crypto";

/**
 * Базова цілочисельна арифметика, на якій тримається RSA:
 * модульне піднесення до степеня, розширений алгоритм Евкліда,
 * тест простоти та генерація простих чисел.
 */

/** Швидке модульне піднесення до степеня: base^exp mod modulus. */
export function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new RangeError("Модуль має бути додатним");
  if (modulus === 1n) return 0n;

  let result = 1n;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exp;

  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** Результат розширеного алгоритму Евкліда: gcd = a*x + b*y. */
export type ExtendedGcd = { gcd: bigint; x: bigint; y: bigint };

/**
 * Розширений алгоритм Евкліда в ітеративній формі
 * (r0 = a, r1 = b; x0 = 1, x1 = 0; y0 = 0, y1 = 1).
 */
export function extendedGcd(a: bigint, b: bigint): ExtendedGcd {
  let [r0, r1] = [a, b];
  let [x0, x1] = [1n, 0n];
  let [y0, y1] = [0n, 1n];

  while (r1 !== 0n) {
    const q = r0 / r1; // ціла частина від ділення
    [r0, r1] = [r1, r0 - q * r1];
    [x0, x1] = [x1, x0 - q * x1];
    [y0, y1] = [y1, y0 - q * y1];
  }

  return { gcd: r0, x: x0, y: y0 };
}

export function gcd(a: bigint, b: bigint): bigint {
  return extendedGcd(a, b).gcd;
}

/**
 * Число, обернене до `a` за модулем `m`: (a * inverse) mod m === 1.
 * Якщо коефіцієнт x від'ємний — додаємо модуль, доки не стане додатним.
 */
export function modInverse(a: bigint, m: bigint): bigint {
  const { gcd: g, x } = extendedGcd(a, m);
  if (g !== 1n) throw new Error(`Оберненого не існує: НСД(${a}, ${m}) = ${g}`);
  return ((x % m) + m) % m;
}

/** Криптографічно стійке випадкове ціле в діапазоні [min, max]. */
export function randomBigInt(min: bigint, max: bigint): bigint {
  const range = max - min + 1n;
  const bits = range.toString(2).length;
  const bytes = Math.ceil(bits / 8);

  while (true) {
    const candidate = bytesToBigInt(randomBytes(bytes)) >> BigInt(bytes * 8 - bits);
    if (candidate < range) return min + candidate;
  }
}

const SMALL_PRIMES = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n,
  73n, 79n, 83n, 89n, 97n,
];

/** Імовірнісний тест Міллера — Рабіна. */
export function isProbablePrime(n: bigint, rounds = 24): boolean {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }

  // n - 1 = 2^s * d, де d непарне
  let d = n - 1n;
  let s = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    s += 1n;
  }

  witness: for (let i = 0; i < rounds; i += 1) {
    const a = randomBigInt(2n, n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;

    for (let r = 1n; r < s; r += 1n) {
      x = (x * x) % n;
      if (x === n - 1n) continue witness;
    }
    return false;
  }
  return true;
}

/** Генерація випадкового простого числа заданої довжини у бітах. */
export function generatePrime(bits: number): bigint {
  if (bits < 8) throw new RangeError("Занадто мала довжина простого числа");
  const min = 1n << BigInt(bits - 1);
  const max = (1n << BigInt(bits)) - 1n;

  while (true) {
    const candidate = randomBigInt(min, max) | 1n; // гарантовано непарне
    if (isProbablePrime(candidate)) return candidate;
  }
}

/** Кількість значущих бітів числа. */
export function bitLength(value: bigint): number {
  return value <= 0n ? 0 : value.toString(2).length;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) result = (result << 8n) | BigInt(byte);
  return result;
}

export function bigIntToBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new RangeError("Очікується невід'ємне число");
  if (value === 0n) return new Uint8Array([0]);

  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return new Uint8Array(out);
}
