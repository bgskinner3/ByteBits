import { TAESBuffer } from './types';
import { AESError } from './aes-shared-resources';

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
  static isValidTextLength(text: Uint8Array) {
    if (text.length !== 16) {
      throw new AESError({
        message: 'Invalid text size (must be 16 bytes',
        customErrorCode: 'AES_TEXT_INVALID',
        statusCode: 400,
      });
    }
  }
}
