import {
  bigIntToBytes,
  bitLength,
  bytesToBigInt,
  gcd,
  generatePrime,
  modInverse,
  modPow,
} from "./bigint-math.ts";

/**
 * Навчальна реалізація RSA: генерація ключів, блокове шифрування,
 * хеш квадратичної згортки та ЕЦП (підпис + перевірка).
 *
 * Реалізація навмисно «шкільна»: без OAEP/PSS-доповнень, щоб формули
 * збігалися з методичними вказівками до лабораторної роботи.
 */

export type PublicKey = { readonly e: bigint; readonly n: bigint };
export type PrivateKey = { readonly d: bigint; readonly n: bigint };

export type KeyPair = {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
  /** Секретні параметри: показуємо лише для наочності в звіті. */
  readonly parameters: { readonly p: bigint; readonly q: bigint; readonly phi: bigint };
};

const DEFAULT_PUBLIC_EXPONENT = 65537n;

/**
 * Генерація пари ключів RSA.
 * p, q — різні прості; n = p*q; φ(n) = (p-1)(q-1);
 * e — непарне, 1 < e < φ(n), НСД(e, φ(n)) = 1; d = e⁻¹ mod φ(n).
 */
export function generateKeyPair(bits = 512): KeyPair {
  if (bits < 64) throw new RangeError("Для блокового шифрування потрібно щонайменше 64 біти");

  const halfBits = Math.floor(bits / 2);
  let p = generatePrime(halfBits);
  let q = generatePrime(bits - halfBits);
  while (p === q) q = generatePrime(bits - halfBits);

  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  const e = gcd(DEFAULT_PUBLIC_EXPONENT, phi) === 1n
    ? DEFAULT_PUBLIC_EXPONENT
    : findCoprimeExponent(phi);
  const d = modInverse(e, phi); // розширений алгоритм Евкліда

  return { publicKey: { e, n }, privateKey: { d, n }, parameters: { p, q, phi } };
}

function findCoprimeExponent(phi: bigint): bigint {
  for (let candidate = 3n; candidate < phi; candidate += 2n) {
    if (gcd(candidate, phi) === 1n) return candidate;
  }
  throw new Error("Не вдалося підібрати відкритий показник e");
}

/** Скільки байтів відкритого тексту вміщується в один блок для модуля n. */
export function blockSize(n: bigint): number {
  // -1 біт, щоб число завжди було меншим за n; -1 байт під маркер 0x01
  const size = Math.floor((bitLength(n) - 1) / 8) - 1;
  if (size < 1) throw new RangeError("Модуль RSA замалий для блокового шифрування");
  return size;
}

/**
 * Шифрування рядка відкритим ключем: c = m^e mod n для кожного блоку.
 * Перед блоком ставиться маркер 0x01, щоб не втратити провідні нулі.
 */
export function encrypt(message: string, key: PublicKey): bigint[] {
  const bytes = new TextEncoder().encode(message);
  const size = blockSize(key.n);
  const blocks: bigint[] = [];

  for (let offset = 0; offset < bytes.length; offset += size) {
    const chunk = bytes.subarray(offset, offset + size);
    const marked = new Uint8Array(chunk.length + 1);
    marked[0] = 0x01;
    marked.set(chunk, 1);
    blocks.push(modPow(bytesToBigInt(marked), key.e, key.n));
  }
  return blocks;
}

/** Розшифрування закритим ключем: m = c^d mod n. */
export function decrypt(blocks: readonly bigint[], key: PrivateKey): string {
  const chunks: Uint8Array[] = [];

  for (const block of blocks) {
    const marked = bigIntToBytes(modPow(block, key.d, key.n));
    if (marked[0] !== 0x01) throw new Error("Пошкоджений блок шифротексту");
    chunks.push(marked.subarray(1));
  }

  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Хеш квадратичної згортки: Hᵢ = (Hᵢ₋₁ + Mᵢ)² mod n, H₀ = 0,
 * де Mᵢ — числове представлення символу повідомлення.
 */
export function hashMessage(message: string, n: bigint): bigint {
  const bytes = new TextEncoder().encode(message);
  let h = 0n;
  for (const byte of bytes) h = ((h + BigInt(byte)) ** 2n) % n;
  return h;
}

/** Формування ЕЦП закритим ключем: ЕЦП = H^d mod n. */
export function sign(message: string, key: PrivateKey): bigint {
  return modPow(hashMessage(message, key.n), key.d, key.n);
}

/** Перевірка ЕЦП: порівнюємо H і H_c = ЕЦП^e mod n. */
export function verify(message: string, signature: bigint, key: PublicKey): boolean {
  const expected = hashMessage(message, key.n);
  const recovered = modPow(signature, key.e, key.n);
  return expected === recovered;
}

/** Компактне представлення великого числа для логів і скріншотів. */
export function short(value: bigint, head = 12, tail = 6): string {
  const hex = value.toString(16);
  if (hex.length <= head + tail + 3) return `0x${hex}`;
  return `0x${hex.slice(0, head)}…${hex.slice(-tail)} (${bitLength(value)} біт)`;
}
