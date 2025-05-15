import { AESHandler, AESCore } from '../src/index';
import { TestsUtils, AESTestUtils } from '../utils';

const password = 'yourpassword123';
const salt = TestsUtils.getConstantSaltBytes();
const key = TestsUtils.deriveKeyFromPassword(password, salt);
const keyUint8Array = new Uint8Array(key);

describe('AESHandler', () => {
  let handler: AESHandler;

  beforeEach(() => {
    handler = new AESHandler(keyUint8Array);
  });

  it('should initialize AESHandler correctly', () => {
    expect(handler).toBeDefined();
    // Internals are private, but you can check the handler instance exists
  });

  it('should correctly encrypt and decrypt using AES CTR mode', () => {
    const originalText = 'This is a secret test!';
    const plaintext = TestsUtils.stringToUint8Array(originalText);

    // Encrypt returns { ciphertext, nonce }
    const { cipherText, nonce } = handler.encrypt(plaintext);

    // New handler for decryption with the same key
    const decryptHandler = new AESHandler(keyUint8Array);

    // Decrypt cipherText with nonce
    const decrypted = decryptHandler.decrypt(cipherText, nonce);

    const decryptedText = TestsUtils.uint8ArrayToString(decrypted);

    expect(decrypted).toEqual(plaintext);
    expect(decryptedText).toBe(originalText);
    expect(cipherText).not.toEqual(plaintext);
  });

  it('should encrypt and decrypt plaintext of arbitrary length (non-block size)', () => {
    const originalText = 'Short!';
    const plaintext = TestsUtils.stringToUint8Array(originalText);

    const { cipherText, nonce } = handler.encrypt(plaintext);

    const decryptHandler = new AESHandler(keyUint8Array);
    const decrypted = decryptHandler.decrypt(cipherText, nonce);

    const decryptedText = TestsUtils.uint8ArrayToString(decrypted);

    expect(decrypted).toEqual(plaintext);
    expect(decryptedText).toBe(originalText);
  });

  it('should use different nonces for each encryption', () => {
    const plaintext = TestsUtils.stringToUint8Array('Block1');
    const { cipherText: ct1, nonce: nonce1 } = handler.encrypt(plaintext);
    const { cipherText: ct2, nonce: nonce2 } = handler.encrypt(plaintext);
    // TESTOING LOGS
    // console.log('nonce1:', nonce1);
    // console.log('nonce2:', nonce2);
    // console.log('ct1:', ct1);
    // console.log('ct2:', ct2);
    expect(nonce1).not.toEqual(nonce2);
    expect(ct1).not.toEqual(ct2);
  });

  it('should correctly encrypt and decrypt a plaintext', () => {
    const plaintextStr = 'Hello AES CTR!';
    const plaintext = TestsUtils.stringToUint8Array(plaintextStr);

    // Encrypt the plaintext
    const { cipherText, nonce } = handler.encrypt(plaintext);

    // Decrypt with the same nonce and default initial counter
    const decrypted = handler.decrypt(cipherText, nonce);

    // Convert decrypted Uint8Array back to string
    const decryptedStr = TestsUtils.uint8ArrayToString(decrypted);

    expect(decryptedStr).toEqual(plaintextStr);
  });
  it('should correctly add, apply and return a passed nonce', () => {
    const originalText = 'generated nonce test';
    const generatedNonce = TestsUtils.generateNonce();
    const plaintext = TestsUtils.stringToUint8Array(originalText);
    const aesCustomNonceHandler = new AESHandler(keyUint8Array, generatedNonce);

    const { cipherText, nonce } = handler.encrypt(plaintext);
    expect(nonce).not.toEqual(generatedNonce);

    const decrypted = aesCustomNonceHandler.decrypt(cipherText, nonce);
    const decryptedText = TestsUtils.uint8ArrayToString(decrypted);
    expect(decryptedText).toBe(originalText);
  });
  it('should handle unicode plaintext', () => {
    const unicodeStr = '🚀🔥💧 中文テスト 🌟';
    const plaintext = TestsUtils.stringToUint8Array(unicodeStr);
    const { cipherText, nonce } = handler.encrypt(plaintext);
    const decrypted = handler.decrypt(cipherText, nonce);
    const decryptedStr = TestsUtils.uint8ArrayToString(decrypted);
    expect(decryptedStr).toBe(unicodeStr);
  });
});

describe('AESCore', () => {
  let aesCore: AESCore;

  beforeEach(() => {
    aesCore = new AESCore(keyUint8Array);
  });
  it('should throw if no key is provided', () => {
    expect(() => new AESCore(null)).toThrow();
  });

  it('should expand keys correctly on initialization', () => {
    const encKeys = aesCore.getEncryptionRoundKeys();
    const decKeys = aesCore.getDecryptionRoundKeys();

    expect(encKeys.length).toBeGreaterThan(0);
    expect(decKeys.length).toBeGreaterThan(0);
    encKeys.forEach((row) => {
      expect(
        AESTestUtils.isFlatArrayOfNumbers(row) || AESTestUtils.is4x4Matrix(row),
      ).toBe(true);
    });

    decKeys.forEach((row) => {
      expect(
        AESTestUtils.isFlatArrayOfNumbers(row) || AESTestUtils.is4x4Matrix(row),
      ).toBe(true);
    });
  });
});

describe('AESCounter', () => {});

describe('AESEncryptDecrypt', () => {});

describe('AESUtils', () => {});
