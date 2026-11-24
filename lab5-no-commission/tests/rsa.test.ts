import assert from "node:assert/strict";
import { test } from "node:test";

import { decryptLayer, encryptLayer, encryptSymbolwise, generateKeyPair, sign, verify } from "../src/rsa.ts";

const keys = generateKeyPair();
const other = generateKeyPair();

test("e·d ≡ 1 mod φ(n) для згенерованої пари ключів", () => {
  const { publicKey, privateKey, parameters } = keys;
  assert.equal((publicKey.e * privateKey.d) % parameters.phi, 1n);
  assert.equal(parameters.p * parameters.q, publicKey.n);
});

test("шар подвоює довжину і знімається лише власним закритим ключем", () => {
  const text = "Олена Петренко";
  const cipher = encryptLayer(text, keys.publicKey);
  assert.equal(cipher.length, text.length * 2);
  assert.equal(decryptLayer(cipher, keys.privateKey), text);
  assert.notEqual(decryptLayer(cipher, other.privateKey), text);
});

test("багатошарове шифрування: результат шару — вхідні дані наступного", () => {
  const chain = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  let cipher = "EVP";
  for (const pair of [...chain].reverse()) cipher = encryptLayer(cipher, pair.publicKey);
  for (const pair of chain) cipher = decryptLayer(cipher, pair.privateKey) ?? "";
  assert.equal(cipher, "EVP");
});

test("без зчеплення RP не приховує повідомлення, зі зчепленням — змінює весь шар", () => {
  const evp = "Іван Коваленко";
  const [first, second] = [encryptSymbolwise(`${evp}RP01`, keys.publicKey), encryptSymbolwise(`${evp}RP02`, keys.publicKey)];
  assert.equal(first.slice(0, evp.length * 2), second.slice(0, evp.length * 2));

  const [chainedFirst, chainedSecond] = [encryptLayer(`${evp}RP01`, keys.publicKey), encryptLayer(`${evp}RP02`, keys.publicKey)];
  assert.notEqual(chainedFirst.slice(0, 2), chainedSecond.slice(0, 2));
});

test("ЕЦП перевіряється ключем підписувача і не переноситься на змінений текст", () => {
  const signature = sign("набір бюлетенів", keys.privateKey);
  assert.ok(verify("набір бюлетенів", signature, keys.publicKey));
  assert.ok(!verify("набір бюлетенів!", signature, keys.publicKey));
  assert.ok(!verify("набір бюлетенів", signature, other.publicKey));
});
