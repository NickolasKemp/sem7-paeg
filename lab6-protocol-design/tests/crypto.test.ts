import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { decodeByDictionary } from "../src/attacks.ts";
import { blind, randomBlindingFactor, signBlinded, unblind } from "../src/blind-signature.ts";
import { decrypt, encrypt, generateKeyPair, hashMessage, multiplyCiphers, sign, verify } from "../src/rsa.ts";

const keys = generateKeyPair(256);

describe("RSA і сліпий підпис", () => {
  test("RSA(a) · RSA(b) mod n розшифровується в a · b", () => {
    const combined = multiplyCiphers(encrypt(4n, keys.publicKey), encrypt(9n, keys.publicKey), keys.publicKey);
    assert.equal(decrypt(combined, keys.privateKey), 36n);
  });

  test("ЕЦП не перевіряється після зміни тексту або чужим ключем", () => {
    const signature = sign("повідомлення", keys.privateKey);
    assert.equal(verify("повідомлення", signature, keys.publicKey), true);
    assert.equal(verify("повідомлення!", signature, keys.publicKey), false);
    assert.equal(verify("повідомлення", signature, generateKeyPair(256).publicKey), false);
  });

  test("знятий сліпий підпис збігається зі звичайним ЕЦП того самого тексту", () => {
    const hash = hashMessage("мандат", keys.publicKey.n);
    const r = randomBlindingFactor(keys.publicKey.n);
    const blinded = blind(hash, r, keys.publicKey);
    assert.notEqual(blinded, hash);
    assert.equal(unblind(signBlinded(blinded, keys.privateKey), r, keys.publicKey), sign("мандат", keys.privateKey));
  });

  test("перебір знаходить малі значення, але не випадкову частину", () => {
    assert.equal(decodeByDictionary(encrypt(101n, keys.publicKey), keys.publicKey, 103n), 101n);
    assert.equal(decodeByDictionary(encrypt(randomBlindingFactor(keys.publicKey.n), keys.publicKey), keys.publicKey, 103n), undefined);
  });
});
