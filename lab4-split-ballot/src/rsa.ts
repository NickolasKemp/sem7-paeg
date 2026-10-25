import { bitLength, gcd, generatePrime, modInverse, modPow } from "./bigint-math.ts";

/**
 * Навчальна реалізація RSA: генерація ключів, шифрування числа,
 * мультиплікативна гомоморфність, хеш квадратичної згортки та ЕЦП.
 *
 * Шифрування — «шкільне» RSA без доповнень: саме воно зберігає
 * властивість RSA(a) · RSA(b) = RSA(a · b) mod n, на якій тримається протокол.
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
  if (bits < 64) throw new RangeError("Модуль RSA має бути щонайменше 64 біти");

  const halfBits = Math.floor(bits / 2);
  const p = generatePrime(halfBits);
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

/** Шифрування числа відкритим ключем: c = m^e mod n. */
export function encrypt(message: bigint, key: PublicKey): bigint {
  if (message <= 0n || message >= key.n) throw new RangeError("Повідомлення має бути в діапазоні 0 < m < n");
  return modPow(message, key.e, key.n);
}

/** Розшифрування закритим ключем: m = c^d mod n. */
export function decrypt(cipher: bigint, key: PrivateKey): bigint {
  return modPow(cipher, key.d, key.n);
}

/**
 * Об'єднання шифротекстів без розшифрування:
 * (m₁^e · m₂^e) mod n = (m₁ · m₂)^e mod n, тобто RSA(m₁) · RSA(m₂) = RSA(m₁ · m₂).
 */
export function multiplyCiphers(first: bigint, second: bigint, key: PublicKey): bigint {
  return (first * second) % key.n;
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
  return hashMessage(message, key.n) === modPow(signature, key.e, key.n);
}

/** Компактне представлення великого числа для логів і скріншотів. */
export function short(value: bigint, head = 12, tail = 6): string {
  const hex = value.toString(16);
  if (hex.length <= head + tail + 3) return `0x${hex}`;
  return `0x${hex.slice(0, head)}…${hex.slice(-tail)} (${bitLength(value)} біт)`;
}
