import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { bitLength, extendedGcd, gcd, isProbablePrime, modInverse, modPow } from "../src/bigint-math.ts";
import { blind, randomBlindingFactor, signBlinded, unblind } from "../src/blind-signature.ts";
import { decrypt, encrypt, generateKeyPair, hashMessage, verify } from "../src/rsa.ts";

const BITS = 256;

describe("арифметика", () => {
  test("розширений алгоритм Евкліда дає коефіцієнти рівності a*x + b*y = НСД(a, b)", () => {
    const { gcd: g, x, y } = extendedGcd(240n, 46n);
    assert.equal(g, 2n);
    assert.equal(240n * x + 46n * y, g);
  });

  test("обернене за модулем задовольняє (a * a⁻¹) mod m = 1", () => {
    assert.equal((17n * modInverse(17n, 3120n)) % 3120n, 1n);
  });

  test("modInverse відмовляє, якщо числа не взаємно прості", () => {
    assert.throws(() => modInverse(6n, 9n));
  });

  test("тест простоти відрізняє прості від складених", () => {
    assert.equal(isProbablePrime(2n ** 61n - 1n), true);
    assert.equal(isProbablePrime(2n ** 61n - 3n), false);
  });

  test("modPow збігається з наївним піднесенням до степеня", () => {
    assert.equal(modPow(7n, 13n, 101n), 7n ** 13n % 101n);
  });
});

describe("RSA", () => {
  test("ключі узгоджені: e*d ≡ 1 mod φ(n)", () => {
    const { publicKey, privateKey, parameters } = generateKeyPair(BITS);
    assert.equal((publicKey.e * privateKey.d) % parameters.phi, 1n);
    assert.equal(parameters.p * parameters.q, publicKey.n);
    assert.equal(bitLength(publicKey.n), BITS);
  });

  test("шифрування та розшифрування повертають вихідний текст", () => {
    const { publicKey, privateKey } = generateKeyPair(BITS);
    const message = '{"ballot":"{\\"id\\":\\"ab12\\",\\"candidateId\\":\\"К2\\"}","signature":"ff"}';
    assert.equal(decrypt(encrypt(message, publicKey), privateKey), message);
  });

  test("хеш квадратичної згортки чутливий до зміни одного символу", () => {
    const { publicKey } = generateKeyPair(BITS);
    assert.notEqual(hashMessage("К1", publicKey.n), hashMessage("К2", publicKey.n));
  });
});

describe("сліпий підпис RSA", () => {
  const keys = generateKeyPair(BITS);
  const message = '{"id":"0a1b2c3d4e5f6a7b","candidateId":"К1"}';
  const hash = hashMessage(message, keys.publicKey.n);

  test("множник маскування взаємно простий з n", () => {
    assert.equal(gcd(randomBlindingFactor(keys.publicKey.n), keys.publicKey.n), 1n);
  });

  test("замаскований хеш не збігається з початковим", () => {
    const r = randomBlindingFactor(keys.publicKey.n);
    assert.notEqual(blind(hash, r, keys.publicKey), hash);
  });

  test("після зняття маскування отримано дійсний підпис початкового повідомлення", () => {
    const r = randomBlindingFactor(keys.publicKey.n);
    const blindSignature = signBlinded(blind(hash, r, keys.publicKey), keys.privateKey);
    const signature = unblind(blindSignature, r, keys.publicKey);

    assert.equal(signature, modPow(hash, keys.privateKey.d, keys.publicKey.n));
    assert.equal(verify(message, signature, keys.publicKey), true);
  });

  test("підпис не переноситься на змінене повідомлення", () => {
    const r = randomBlindingFactor(keys.publicKey.n);
    const signature = unblind(signBlinded(blind(hash, r, keys.publicKey), keys.privateKey), r, keys.publicKey);
    assert.equal(verify(message.replace("К1", "К2"), signature, keys.publicKey), false);
  });

  test("без правильного r маскування не знімається", () => {
    const r = randomBlindingFactor(keys.publicKey.n);
    const blindSignature = signBlinded(blind(hash, r, keys.publicKey), keys.privateKey);
    const wrong = unblind(blindSignature, randomBlindingFactor(keys.publicKey.n), keys.publicKey);
    assert.equal(verify(message, wrong, keys.publicKey), false);
  });
});
