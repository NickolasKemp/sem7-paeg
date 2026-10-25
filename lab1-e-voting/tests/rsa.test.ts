import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { extendedGcd, gcd, isProbablePrime, modInverse, modPow } from "../src/bigint-math.ts";
import { decrypt, encrypt, generateKeyPair, hashMessage, sign, verify } from "../src/rsa.ts";

const BITS = 256;

describe("арифметика", () => {
  test("розширений алгоритм Евкліда дає коефіцієнти рівності a*x + b*y = НСД(a, b)", () => {
    const { gcd: g, x, y } = extendedGcd(240n, 46n);
    assert.equal(g, 2n);
    assert.equal(240n * x + 46n * y, g);
  });

  test("обернене за модулем задовольняє (a * a⁻¹) mod m = 1", () => {
    const inverse = modInverse(17n, 3120n);
    assert.equal((17n * inverse) % 3120n, 1n);
  });

  test("modInverse відмовляє, якщо числа не взаємно прості", () => {
    assert.throws(() => modInverse(6n, 9n));
  });

  test("тест простоти відрізняє прості від складених", () => {
    assert.equal(isProbablePrime(2n ** 61n - 1n), true); // просте Мерсенна
    assert.equal(isProbablePrime(2n ** 61n - 3n), false);
  });

  test("modPow збігається з наївним піднесенням до степеня", () => {
    assert.equal(modPow(7n, 13n, 101n), 7n ** 13n % 101n);
  });
});

describe("RSA", () => {
  test("ключі узгоджені: e*d ≡ 1 mod φ(n), НСД(e, φ(n)) = 1", () => {
    const { publicKey, privateKey, parameters } = generateKeyPair(BITS);
    assert.equal(gcd(publicKey.e, parameters.phi), 1n);
    assert.equal((publicKey.e * privateKey.d) % parameters.phi, 1n);
    assert.equal(parameters.p * parameters.q, publicKey.n);
  });

  test("шифрування та розшифрування повертають вихідний текст (у т.ч. кирилицю)", () => {
    const { publicKey, privateKey } = generateKeyPair(BITS);
    const message = '{"voterName":"Шевченко Олена","candidateId":"К2"}';
    assert.equal(decrypt(encrypt(message, publicKey), privateKey), message);
  });

  test("шифротекст не збігається з відкритим текстом", () => {
    const { publicKey } = generateKeyPair(BITS);
    const blocks = encrypt("К1", publicKey);
    assert.ok(blocks.every((block) => block > 255n));
  });

  test("хеш квадратичної згортки чутливий до зміни одного символу", () => {
    const { publicKey } = generateKeyPair(BITS);
    assert.notEqual(hashMessage("К1", publicKey.n), hashMessage("К2", publicKey.n));
  });

  test("ЕЦП перевіряється відкритим ключем автора", () => {
    const { publicKey, privateKey } = generateKeyPair(BITS);
    const message = "бюлетень за К1";
    assert.equal(verify(message, sign(message, privateKey), publicKey), true);
  });

  test("ЕЦП не проходить перевірку після зміни повідомлення", () => {
    const { publicKey, privateKey } = generateKeyPair(BITS);
    const signature = sign("бюлетень за К1", privateKey);
    assert.equal(verify("бюлетень за К2", signature, publicKey), false);
  });

  test("ЕЦП не проходить перевірку чужим відкритим ключем", () => {
    const author = generateKeyPair(BITS);
    const stranger = generateKeyPair(BITS);
    const message = "бюлетень за К1";
    assert.equal(verify(message, sign(message, author.privateKey), stranger.publicKey), false);
  });
});
