import type { TAESBuffer, TByte, TRoundKey, Maybe } from './types';
import { AESSharedValues } from './aes-shared-values';
/** @internal */
export class AESUtils {
  static getNumberOfRounds = (
    keySize: Maybe<keyof typeof AESSharedValues.keySizeRounds>,
  ): number => {
    if (!keySize || !(keySize in AESSharedValues.keySizeRounds))
      throw new AESError({
        message:
          'Invalid key size (must be 16, 24, or 32 bytes) for AES encryption.',
        statusCode: 400,
        customErrorCode: 'AES_KEY_SIZE_INVALID',
        name: 'AES Encryption Error',
      });

    return AESSharedValues.keySizeRounds[keySize];
  };

  public static validateAndWrapUnit8Array = <T extends TByte[] | Uint8Array>(
    arg: T | unknown,
    copy?: boolean,
  ): Uint8Array => {
    if (this.isUint8Array(arg)) {
      return copy ? arg.slice() : arg;
    }

    if (!this.checkInts(arg)) {
      throw new AESError({
        message: `Array contains invalid value: ${arg}`,
        statusCode: 400,
        customErrorCode: 'AES_KEY_SIZE_INVALID',
        name: 'AES Encryption Error',
      });
    }

    return new Uint8Array(arg);
  };
  /* istanbul ignore next */
  public static generateNonce(): Uint8Array {
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce); // secure random bytes
    return nonce;
  }
  /* istanbul ignore next */
  public static convertToInt32 = (bytes: number[] | Uint8Array) => {
    // Preallocate the array
    // *Bitwise faster than division for integers
    const result = new Array(bytes.length >>> 2);
    // NEW IDEA: In-place result index
    // eliminates the overhead of array resizing.
    let j = 0;
    for (let i = 0; i < bytes.length; i += 4) {
      result[j++] =
        (bytes[i] << 24) |
        (bytes[i + 1] << 16) |
        (bytes[i + 2] << 8) |
        bytes[i + 3];
    }
    return result;
  };
  /* istanbul ignore next */
  public static roundConstant(roundConstantPointer: number): number {
    return AESSharedValues.roundConstants[roundConstantPointer];
  }

  public static initializeEncryptionBoxes({
    rounds,
    encryptionRoundKeys,
    decryptionRoundKeys,
  }: {
    rounds: number;
    encryptionRoundKeys: TRoundKey[];
    decryptionRoundKeys: TRoundKey[];
  }) {
    for (let i = 0; i <= rounds; i++) {
      encryptionRoundKeys.push([0, 0, 0, 0]);
      decryptionRoundKeys.push([0, 0, 0, 0]);
    }
  }
  /* istanbul ignore next */
  public static toSingedInteger = (value: number): number => {
    return parseInt(value.toString(), 10);
  };
  /* istanbul ignore next */
  static checkInt = (value: unknown): boolean => {
    return typeof value === 'number' && value === value;
  };
  /* istanbul ignore next */
  static checkByteArray<T extends number[]>(arr: T): arr is T {
    return arr.every(
      (value) =>
        typeof value === 'number' &&
        value >= 0 &&
        value <= 255 &&
        Number.isInteger(value),
    );
  }
  /* istanbul ignore next */
  static isUint8Array(arg: unknown): arg is Uint8Array {
    return arg instanceof Uint8Array;
  }
  /* istanbul ignore next */
  static isValidByteArray<T extends number[]>(arg: unknown): arg is T {
    return Array.isArray(arg) && this.checkByteArray(arg);
  }
  /* istanbul ignore next */
  static checkInts<T extends number[]>(arrayIsh: unknown): arrayIsh is T {
    if (!Array.isArray(arrayIsh)) return false;
    return this.checkByteArray(arrayIsh);
  }

  static inferKeySize<T extends TAESBuffer>(key: T): 16 | 24 | 32 {
    const length = key.length;
    if (length !== 16 && length !== 24 && length !== 32) {
      throw new AESError({
        message: 'Key length must be 16, 24, or 32',
        customErrorCode: 'AES_KEY_INVALID',
        statusCode: 400,
      });
    }

    return length;
  }
  /* istanbul ignore next */
  static validateInputLength(input: Uint8Array | TByte[]) {
    if (input.length !== 16) {
      throw new AESError({
        message: 'Invalid text size (must be 16 bytes',
        customErrorCode: 'AES_TEXT_INVALID',
        statusCode: 400,
      });
    }
  }
  /* istanbul ignore next */
  static isNumber(value: unknown): value is number {
    return typeof value === 'number';
  }
  /* istanbul ignore next */
  static isInteger(value: unknown): value is number {
    return Number.isInteger(value);
  }
  /* istanbul ignore next */
  static validateCounterValue(value: number | string): asserts value is number {
    if (!this.isNumber(value) || !this.isInteger(value)) {
      throw new AESError({
        message: 'Counter value must be an integer.',
        customErrorCode: 'AES_INVALID_COUNTER_VALUE',
        statusCode: 400,
      });
    }

    if (value > Number.MAX_SAFE_INTEGER) {
      throw new AESError({
        message:
          'The provided number exceeds the safe integer range. Please provide a value less than or equal to Number.MAX_SAFE_INTEGER.',
        customErrorCode: 'AES_INVALID_COUNTER_VALUE',
        statusCode: 400,
      });
    }
  }
}
/* istanbul ignore next */
export class AESError extends Error {
  statusCode: number;
  customErrorCode: string;
  static defaultStatusCode = 400;

  constructor({
    message,
    statusCode = AESError.defaultStatusCode,
    customErrorCode = 'UNKNOWN_ERROR',
    name = 'AESError',
  }: {
    message: string;
    statusCode?: number;
    customErrorCode?: string;
    name?: string;
  }) {
    super(message);
    this.statusCode = statusCode;
    this.customErrorCode = customErrorCode;
    this.name = name;

    // This ensures the stack trace is correctly set in V8-based environments (Node.js)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}
