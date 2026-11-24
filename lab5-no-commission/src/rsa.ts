import { bitLength, gcd, generatePrime, modInverse, modPow } from "./bigint-math.ts";

/**
 * Навчальна реалізація RSA: генерація ключів, посимвольне шифрування шару,
 * хеш квадратичної згортки та ЕЦП.
 *
 * Символ — одна кодова одиниця рядка JavaScript (UTF-16, 0…65535).
 * Модуль n має 32 біти, тому шифротекст символу займає рівно два символи,
 * і результат шару — знову рядок, який наступний шар шифрує так само.
 */

export type PublicKey = { readonly e: bigint; readonly n: bigint };
export type PrivateKey = { readonly d: bigint; readonly n: bigint };

export type KeyPair = {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
  /** Секретні параметри: показуємо лише для наочності в звіті. */
  readonly parameters: { readonly p: bigint; readonly q: bigint; readonly phi: bigint };
};

const SYMBOL_BITS = 16n;
const SYMBOL_COUNT = 1n << SYMBOL_BITS;
const SYMBOL_MASK = SYMBOL_COUNT - 1n;
const KEY_BITS = 32;
const DEFAULT_PUBLIC_EXPONENT = 65537n;

/**
 * Генерація пари ключів RSA.
 * p, q — різні 16-бітні прості; n = p*q; φ(n) = (p-1)(q-1);
 * e — непарне, 1 < e < φ(n), НСД(e, φ(n)) = 1; d = e⁻¹ mod φ(n).
 */
export function generateKeyPair(): KeyPair {
  const halfBits = KEY_BITS / 2;
  const p = generatePrime(halfBits);
  let q = generatePrime(halfBits);
  while (p === q) q = generatePrime(halfBits);

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

/** Число 0 ≤ c < 2³² записуємо двома символами: старші та молодші 16 біт. */
function packValue(value: bigint): string {
  return String.fromCharCode(Number(value >> SYMBOL_BITS), Number(value & SYMBOL_MASK));
}

function unpackValues(cipher: string): bigint[] {
  const values: bigint[] = [];
  for (let index = 0; index < cipher.length; index += 2) {
    values.push((BigInt(cipher.charCodeAt(index)) << SYMBOL_BITS) | BigInt(cipher.charCodeAt(index + 1)));
  }
  return values;
}

/**
 * Посимвольне шифрування з незалежними символами: cᵢ = mᵢ^e mod n.
 * Однакові символи дають однакові шифротексти, тому RSA(X || RP) = RSA(X) || RSA(RP) —
 * випадковий рядок RP нічого не приховує. Використовується лише для демонстрації цієї вади.
 */
export function encryptSymbolwise(text: string, key: PublicKey): string {
  let cipher = "";
  for (let index = 0; index < text.length; index += 1) {
    cipher += packValue(modPow(BigInt(text.charCodeAt(index)), key.e, key.n));
  }
  return cipher;
}

/**
 * Один шар посимвольного RSA зі зворотним зчепленням символів:
 * cᵢ = ((mᵢ + cᵢ₊₁) mod n)^e mod n, де за останнім символом стоїть c = 0.
 * Кожен символ шифрується окремо, але залежить від усіх символів праворуч,
 * тому дописаний у кінець RP змінює весь шифротекст шару.
 */
export function encryptLayer(text: string, key: PublicKey): string {
  const values = new Array<bigint>(text.length);
  let next = 0n;
  for (let index = text.length - 1; index >= 0; index -= 1) {
    next = modPow((BigInt(text.charCodeAt(index)) + next) % key.n, key.e, key.n);
    values[index] = next;
  }
  return values.map(packValue).join("");
}

/**
 * Зняття шару закритим ключем: mᵢ = (cᵢ^d − cᵢ₊₁) mod n.
 * Повертає undefined, якщо шар зашифровано не цим ключем
 * (непарна довжина, значення поза модулем або символ поза алфавітом).
 */
export function decryptLayer(cipher: string, key: PrivateKey): string | undefined {
  if (cipher.length % 2 !== 0) return undefined;
  const values = unpackValues(cipher);

  let text = "";
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]!;
    if (value >= key.n) return undefined;
    const next = values[index + 1] ?? 0n;
    const symbol = (modPow(value, key.d, key.n) - next % key.n + key.n) % key.n;
    if (symbol >= SYMBOL_COUNT) return undefined;
    text += String.fromCharCode(Number(symbol));
  }
  return text;
}

/**
 * Хеш квадратичної згортки: Hᵢ = (Hᵢ₋₁ + Mᵢ)² mod n, H₀ = 0,
 * де Mᵢ — код i-го символу повідомлення.
 */
export function hashMessage(message: string, n: bigint): bigint {
  let h = 0n;
  for (let index = 0; index < message.length; index += 1) {
    h = ((h + BigInt(message.charCodeAt(index))) ** 2n) % n;
  }
  return h;
}

/** Формування ЕЦП закритим ключем: ЕЦП = H^d mod n. */
export function sign(message: string, key: PrivateKey): bigint {
  return modPow(hashMessage(message, key.n), key.d, key.n);
}

/** Перевірка ЕЦП: порівнюємо H і H_c = ЕЦП^e mod n. */
export function verify(message: string, signature: bigint, key: PublicKey): boolean {
  return hashMessage(message, key.n) === modPow(signature, key.e, key.n);
}

/** Компактне представлення числа для логів і скріншотів. */
export function short(value: bigint): string {
  return `0x${value.toString(16)} (${bitLength(value)} біт)`;
}
