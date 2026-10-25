import { encrypt, type PublicKey } from "./rsa.ts";

/**
 * Дії нечесної ВК. RSA без доповнень детермінований, а відкритий ключ ЦВК
 * доступний усім, тому малий множник можна «розшифрувати» перебором.
 */
export function decodeByDictionary(cipher: bigint, key: PublicKey, maxValue: bigint): bigint | undefined {
  for (let value = 1n; value <= maxValue; value += 1n) {
    if (encrypt(value, key) === cipher) return value;
  }
  return undefined;
}
