import {
  KaloCore,
  KaloEncodingUtils,
  KaloStructureUtils,
  KaloError,
  TestableKaloCore,
} from '../../src';
import { pbkdf2Sync } from 'crypto';

jest.mock('../../src/custom-algos/kalo/utils', () => ({
  KaloEncodingUtils: {
    hexToBytes: jest.fn(),
  },
  KaloStructureUtils: {
    concatUint8Arrays: jest.fn(),
    generateSaltAndNonce: jest.fn(),
  },
  KaloError: {
    MissingEnvVars: jest.fn(() => new Error('Missing env vars')),
    InvalidHexParts: jest.fn(
      (msg?: string) => new Error(msg || 'Invalid hex parts'),
    ),
    InvalidPassword: jest.fn(() => new Error('Missing env vars')),
  },
  // KaloError: class KaloError extends Error {
  //     constructor(opts?: { message?: string }) {
  //       super(opts?.message || 'KaloError');
  //       this.name = 'KaloError';
  //     }
  //     static MissingEnvVars() {
  //       return KaloError.MissingEnvVars()
  //     }
  //     static InvalidHexParts(msg?: string) {
  //       return KaloError.InvalidHexParts(msg)
  //     }
  //   },
  KaloValidationUtils: {
    isValidHex: jest.fn((hex: string) => /^[0-9a-fA-F]+$/.test(hex)), // or jest.fn(() => true) for simplest mock
    validateSaltAndNonceUint8Arrays: jest.fn(() => true), // if you call it in tests
    validateSaltNonceLengths: jest.fn(), // if you want to mock this
  },
}));
jest.mock('crypto', () => ({
  pbkdf2Sync: jest.fn(),
}));

describe('KaloCore', () => {
  const mockSaltHex = '2084482373de';
  const mockNonceHex = 'c4c16b009783';
  const saltBytes = new Uint8Array(6).fill(1);
  const nonceBytes = new Uint8Array(6).fill(2);
  const derivedKey = new Uint8Array(32).fill(5);
  beforeAll(() => {
    // Mock env vars for testing
    process.env.KALO_SALT = mockSaltHex; // 6 hex chars
    process.env.KALO_NONCE = mockNonceHex; // 6 hex chars
  });

  beforeEach(() => {
    jest.resetAllMocks();
    process.env.KALO_SALT = mockSaltHex;
    process.env.KALO_NONCE = mockNonceHex;

    (KaloEncodingUtils.hexToBytes as jest.Mock).mockImplementation((hex) => {
      if (hex === mockSaltHex) return saltBytes;
      if (hex === mockNonceHex) return nonceBytes;
      return new Uint8Array();
    });

    (KaloStructureUtils.concatUint8Arrays as jest.Mock).mockImplementation(
      (a: Uint8Array, b: Uint8Array) => {
        // Return concatenation for testing
        const result = new Uint8Array(a.length + b.length);
        result.set(a);
        result.set(b, a.length);
        return result;
      },
    );

    (KaloStructureUtils.generateSaltAndNonce as jest.Mock).mockReturnValue({
      salt: saltBytes,
      nonce: nonceBytes,
    });

    (pbkdf2Sync as jest.Mock).mockReturnValue(Buffer.from(derivedKey));
  });
  it('throws if env vars are missing', () => {
    delete process.env.KALO_SALT;
    expect(() => KaloCore.forEncryption('pass')).toThrow(
      KaloError.MissingEnvVars(),
    );

    process.env.KALO_SALT = mockSaltHex;
    delete process.env.KALO_NONCE;
    expect(() => KaloCore.forEncryption('pass')).toThrow(
      KaloError.MissingEnvVars(),
    );
  });
  it('throws InvalidHexParts for invalid hex env vars', () => {
    process.env.KALO_SALT = 'zzzzzzzzzzzz';
    expect(() => KaloCore.forEncryption('pass')).toThrow(
      KaloError.InvalidHexParts(),
    );
  });
  it('throws InvalidHexParts if env hex length is incorrect', () => {
    process.env.KALO_SALT = '1234'; // too short
    expect(() => KaloCore.forEncryption('pass')).toThrow(
      KaloError.InvalidHexParts(),
    );
  });
  it('validates isValidHex correctly', () => {
    expect(KaloCore.isValidHex('abcdef123456', 6)).toBe(true);
    expect(KaloCore.isValidHex('abc', 6)).toBe(false);
    expect(KaloCore.isValidHex('zzzzzzzzzzzz', 6)).toBe(false);
  });
  it('throws if decoded salt or nonce length is not 6 bytes', () => {
    (KaloEncodingUtils.hexToBytes as jest.Mock).mockImplementation(
      () => new Uint8Array(5),
    ); // invalid length
    expect(() => KaloCore.forEncryption('pass')).toThrow(
      KaloError.InvalidHexParts(),
    );
  });
  it('throws if remainderPair lengths are invalid', () => {
    expect(() =>
      KaloCore.forDecryption('pass', {
        salt: new Uint8Array(5),
        nonce: new Uint8Array(5),
      }),
    ).toThrow(KaloError.InvalidHexParts());
  });

  it('creates instance successfully for encryption', () => {
    const instance = KaloCore.forEncryption('password123');
    expect(instance).toBeInstanceOf(KaloCore);

    const keyMaterial = instance.getKeyMaterial();
    expect(keyMaterial.key).toEqual(derivedKey);
    expect(keyMaterial.fullNonce.length).toBe(12);
    expect(keyMaterial.nonceRemainder).toEqual(nonceBytes);
    expect(keyMaterial.saltRemainder).toEqual(saltBytes);
  });

  it('throws error if invlaid password', () => {
    expect(() => new KaloCore({})).toThrow(KaloError.InvalidPassword());
  });
  it('throws if salt length !== 12', () => {
    const instance = new TestableKaloCore({
      password: 'pass',
      remainderPair: undefined,
    });
    const badSalt = new Uint8Array(10); // length not 12

    expect(() => instance.callDeriveKey('pass', badSalt)).toThrow(
      KaloError.InvalidHexParts(),
    );
  });
  it('returns passed remainderPair if lengths are valid', () => {
    const instance = new TestableKaloCore({
      password: 'pass',
      remainderPair: undefined,
    });
    const salt = new Uint8Array(6).fill(1);
    const nonce = new Uint8Array(6).fill(2);

    const pair = instance.callGetSaltNoncePair({ salt, nonce });

    expect(pair.salt).toEqual(salt);
    expect(pair.nonce).toEqual(nonce);
  });

  it('throws error if remainderPair has invalid lengths', () => {
    const instance = new TestableKaloCore({
      password: 'pass',
      remainderPair: undefined,
    });
    const badSalt = new Uint8Array(5); // too short
    const badNonce = new Uint8Array(6);

    expect(() =>
      instance.callGetSaltNoncePair({ salt: badSalt, nonce: badNonce }),
    ).toThrow(KaloError.InvalidHexParts());
  });
});
