import { TAESBuffer, TByte } from './types';
import { AESError } from './aes-shared-resources';

/**
 * class should be responsible for validating inputs, ensuring the correct sizes, for the key, nonce etc.
 * Vlaididng the integrity of teh process as well as validating types
 *
 * for Example:
 * Given COUNTER (CTR), here we check and validate if necessary the nonce has been provided and validate that the nonce
 * is strcitly unique
 */
export class AESValidation {
  static checkInt = (value: unknown): boolean => {
    return typeof value === 'number' && value === value;
  };

  static checkByteArray<T extends number[]>(arr: T): arr is T {
    return arr.every(
      (value) =>
        typeof value === 'number' &&
        value >= 0 &&
        value <= 255 &&
        Number.isInteger(value),
    );
  }

  static isUint8Array(arg: unknown): arg is Uint8Array {
    return arg instanceof Uint8Array;
  }
  static isValidByteArray<T extends number[]>(arg: unknown): arg is T {
    return Array.isArray(arg) && this.checkByteArray(arg);
  }

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
  static validateInputLength(input: Uint8Array | TByte[]) {
    if (input.length !== 16) {
      throw new AESError({
        message: 'Invalid text size (must be 16 bytes',
        customErrorCode: 'AES_TEXT_INVALID',
        statusCode: 400,
      });
    }
  }
  static isNumber(value: unknown): value is number {
    return typeof value === 'number';
  }
  static isInteger(value: unknown): value is number {
    return Number.isInteger(value);
  }

  static validateCounterValue(value: number | string): asserts value is number {
    if (!AESValidation.isNumber(value) || !AESValidation.isInteger(value)) {
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
