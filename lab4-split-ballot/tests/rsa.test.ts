import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { decodeByDictionary } from "../src/attacks.ts";
import { decrypt, encrypt, generateKeyPair, multiplyCiphers, sign, verify } from "../src/rsa.ts";

const keys = generateKeyPair(256);

describe("RSA", () => {
  test("відтворює таблицю з методичних вказівок для ключів (7, 33) і (3, 33)", () => {
    const publicKey = { e: 7n, n: 33n };
    const privateKey = { d: 3n, n: 33n };
    const expected: readonly (readonly [bigint, bigint, bigint, bigint])[] = [
      [1n, 24n, 1n, 18n],
      [2n, 12n, 29n, 12n],
      [3n, 8n, 9n, 2n],
      [4n, 6n, 16n, 30n],
    ];
    for (const [a, b, ca, cb] of expected) {
      assert.equal(encrypt(a, publicKey), ca);
      assert.equal(encrypt(b, publicKey), cb);
      assert.equal(multiplyCiphers(ca, cb, publicKey), 18n);
      assert.equal(decrypt(18n, privateKey), 24n);
    }
  });

  test("RSA(a) · RSA(b) mod n розшифровується в a · b для згенерованого ключа", () => {
    const combined = multiplyCiphers(encrypt(4n, keys.publicKey), encrypt(9n, keys.publicKey), keys.publicKey);
    assert.equal(decrypt(combined, keys.privateKey), 36n);
  });

  test("ЕЦП перевіряється ключем підписувача і не перевіряється після зміни тексту", () => {
    const signature = sign("повідомлення", keys.privateKey);
    assert.equal(verify("повідомлення", signature, keys.publicKey), true);
    assert.equal(verify("повідомлення!", signature, keys.publicKey), false);
    assert.equal(verify("повідомлення", signature, generateKeyPair(256).publicKey), false);
  });

  test("малий множник підбирається перебором за відкритим ключем", () => {
    assert.equal(decodeByDictionary(encrypt(12n, keys.publicKey), keys.publicKey, 36n), 12n);
    assert.equal(decodeByDictionary(encrypt(97n, keys.publicKey), keys.publicKey, 36n), undefined);
  });
});
