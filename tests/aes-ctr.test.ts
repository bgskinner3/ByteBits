import {
  AESHandler,
  AESCore,
  AESCounterCTR,
  AESError,
  AESEncryptDecrypt,
  AESSharedValues,
  KEY_SIZE_ROUNDS,
  AESUtils,
} from '../src/index';
import { TestsUtils, AESTestUtils } from '../utils';
import { ObjectUtils } from '../utils/common';

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

    console.log(cipherText, nonce, '\n\n\n\n');
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

describe('AESCounter', () => {
  const nonce = new Uint8Array(12).fill(1); // 12-byte valid nonce

  it('should initialize with a number and nonce correctly', () => {
    const counter = new AESCounterCTR(5, nonce);
    expect(counter._counter.length).toBe(16);
    expect(counter.getNonce()).toEqual(nonce);
    expect(counter.getValue(counter._counter)).toBe(5);
  });

  it('should initialize with Uint8Array and preserve value', () => {
    const counterBytes = new Uint8Array(16);
    counterBytes.set(nonce, 0);
    counterBytes.set([0, 0, 0, 10], 12); // value = 10

    const counter = new AESCounterCTR(counterBytes, nonce);
    expect(counter._counter).toEqual(counterBytes);
    expect(counter.getValue(counter._counter)).toBe(10);
  });

  it('should increment correctly with carry-over', () => {
    const counter = new AESCounterCTR(255, nonce);
    counter.increment();
    expect(counter.getValue(counter._counter)).toBe(256);

    // Overflow test
    const bigVal = 0xffffffff;
    counter.setValue(bigVal);
    expect(counter.getValue(counter._counter)).toBe(bigVal);
    counter.increment();
    expect(counter.getValue(counter._counter)).toBe(0); // should roll over
  });

  it('should throw with invalid nonce length', () => {
    const badNonce = new Uint8Array(8);
    expect(() => new AESCounterCTR(0, badNonce)).toThrow(AESError);
  });

  it('should clone correctly and preserve internal state', () => {
    const original = new AESCounterCTR(123, nonce);
    const clone = original.clone();

    expect(clone._counter).not.toBe(original._counter); // different references
    expect(clone._counter).toEqual(original._counter);
    expect(clone.getNonce()).toEqual(original.getNonce());

    // Ensure mutations on clone don't affect original
    clone.increment();
    expect(clone.getValue(clone._counter)).toBe(124);
    expect(original.getValue(original._counter)).toBe(123);
  });

  it('should set value correctly via setValue()', () => {
    const counter = new AESCounterCTR(0, nonce);
    counter.setValue(65535);
    expect(counter.getValue(counter._counter)).toBe(65535);
  });

  it('should set value via setBytes()', () => {
    const bytes = new Uint8Array(16);
    bytes.set(nonce, 0);
    bytes.set([0, 0, 0, 42], 12); // Set value to 42

    const counter = new AESCounterCTR(0, nonce);
    counter.setBytes(bytes);
    expect(counter._counter).toEqual(bytes);
    expect(counter.getValue(counter._counter)).toBe(42);
  });

  it('getValue() should return correct numeric value from last 4 bytes', () => {
    const val = 123456789;
    const counter = new AESCounterCTR(val, nonce);
    expect(counter.getValue(counter._counter)).toBe(val);
  });
  it('should default initialValue to 1 if falsy and not 0', () => {
    const counter = new AESCounterCTR(null, nonce);
    expect(counter.getValue(counter._counter)).toBe(1);
  });
  test('should call AESUtils.generateNonce if nonce not provided', () => {
    const mockNonce = new Uint8Array(12).fill(1);

    const spy = jest
      .spyOn(AESUtils, 'generateNonce')
      .mockReturnValue(mockNonce);

    const counter = new AESCounterCTR(1);

    expect(spy).toHaveBeenCalled();
    expect(counter.getNonce()).toEqual(mockNonce);

    spy.mockRestore(); // always restore the spy after test
  });
});

describe('AESEncryptDecrypt', () => {
  let aesEncryptDecrypt: AESEncryptDecrypt;
  // let handler: AESHandler;
  // let aesCore: AESCore;

  beforeEach(() => {
    aesEncryptDecrypt = new AESEncryptDecrypt();
    // handler = new AESHandler(keyUint8Array);
    // aesCore = new AESCore(keyUint8Array);
  });
  it('should process block with decryption path', () => {
    const dummyInput = new Uint8Array(16); // all zero block
    const dummyRoundKeys = [
      [0x0, 0x0, 0x0, 0x0], // initial key
      [0x0, 0x0, 0x0, 0x0], // at least one round
    ];

    const result = aesEncryptDecrypt['processBlockAES'](
      dummyInput,
      dummyRoundKeys,
      AESSharedValues.aesInverseSBox,
      false, // triggers the decryptionTransformationBoxes
    );

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(16);
  });
});

describe('AESUtils GET NUMBER OF ROUNDS && INFER KEY SIZE', () => {
  /**
    ///==================
    GET NUMBER OF ROUNDS
    ///==================
     */
  it('returns correct rounds for key size %i', () => {
    ObjectUtils.keys(KEY_SIZE_ROUNDS).forEach((keySizeStr) => {
      const keySize = Number(
        keySizeStr,
      ) as keyof typeof AESSharedValues.keySizeRounds;
      const expectedRounds = KEY_SIZE_ROUNDS[keySize];
      expect(AESUtils.getNumberOfRounds(keySize)).toBe(expectedRounds);
    });
  });
  it('throws AESError for invalid key sizes', () => {
    // Try some invalid key sizes, e.g. 8, 20, 33
    const invalidKeySizes = [8, 20, 33, 0, 100];
    invalidKeySizes.forEach((invalidSize) => {
      expect(() =>
        AESUtils.getNumberOfRounds(
          invalidSize as keyof typeof AESSharedValues.keySizeRounds,
        ),
      ).toThrow(AESError);
    });
  });
  /**
///==================
inferKeySize
///==================
 */
  it('should return 16 for key length 16', () => {
    const key = new Uint8Array(16);
    expect(AESUtils.inferKeySize(key)).toBe(16);
  });

  it('should return 24 for key length 24', () => {
    const key = new Uint8Array(24);
    expect(AESUtils.inferKeySize(key)).toBe(24);
  });

  it('should return 32 for key length 32', () => {
    const key = new Uint8Array(32);
    expect(AESUtils.inferKeySize(key)).toBe(32);
  });

  it('should throw AESError for invalid key length', () => {
    const large = new Uint8Array(20);
    const small = new Uint8Array(10);
    expect(() => AESUtils.inferKeySize(large)).toThrow(AESError);
    expect(() => AESUtils.inferKeySize(small)).toThrow(AESError);
  });
});
describe('AESUtils VALIDATE AND WRAP UNIT 8 ARRAY', () => {
  /**
     ///==================
       validateAndWrapUnit8Array
       ///==================
     */
  it('should return the same Uint8Array instance if copy is false or undefined', () => {
    const arr = new Uint8Array([1, 2, 3]);
    expect(AESUtils.validateAndWrapUnit8Array(arr)).toBe(arr);
    expect(AESUtils.validateAndWrapUnit8Array(arr, false)).toBe(arr);
  });

  it('should return a copy if copy is true', () => {
    const arr = new Uint8Array([1, 2, 3]);
    const result = AESUtils.validateAndWrapUnit8Array(arr, true);
    expect(result).not.toBe(arr); // different instance
    expect(result).toEqual(arr); // same content
  });

  it('should convert a valid array of numbers to Uint8Array', () => {
    const arr = [10, 20, 30];
    const result = AESUtils.validateAndWrapUnit8Array(arr);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(Array.from(result)).toEqual(arr);
  });

  it('should throw AESError for invalid array contents', () => {
    const invalidArr = [10, '20', 30]; // contains string
    expect(() =>
      AESUtils.validateAndWrapUnit8Array(invalidArr as unknown),
    ).toThrow(AESError);
  });

  it('should throw AESError for totally invalid input', () => {
    const invalidInput = { a: 1 };
    expect(() =>
      AESUtils.validateAndWrapUnit8Array(invalidInput as unknown),
    ).toThrow(AESError);
  });
});
