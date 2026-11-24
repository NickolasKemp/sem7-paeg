import { gcd, modInverse, modPow, randomBigInt } from "./bigint-math.ts";
import type { PrivateKey, PublicKey } from "./rsa.ts";

/**
 * Сліпий підпис RSA:
 *   маскування       H' = H·rᵉ mod n        (виборець)
 *   сліпий підпис    S' = (H')ᵈ mod n       (ВК, не бачить H)
 *   зняття маски     S  = S'·r⁻¹ mod n      (виборець)
 *   перевірка        H_c = Sᵉ mod n, H_c = H
 */

/** Випадковий множник маскування r: 1 < r < n, НСД(r, n) = 1. */
export function randomBlindingFactor(n: bigint): bigint {
  while (true) {
    const r = randomBigInt(2n, n - 2n);
    if (gcd(r, n) === 1n) return r;
  }
}

export function blind(hash: bigint, r: bigint, key: PublicKey): bigint {
  return (hash * modPow(r, key.e, key.n)) % key.n;
}

export function signBlinded(blinded: bigint, key: PrivateKey): bigint {
  return modPow(blinded, key.d, key.n);
}

/** r⁻¹ знаходиться розширеним алгоритмом Евкліда. */
export function unblind(blindSignature: bigint, r: bigint, key: PublicKey): bigint {
  return (blindSignature * modInverse(r, key.n)) % key.n;
}
