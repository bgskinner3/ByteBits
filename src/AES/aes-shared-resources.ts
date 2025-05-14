import { TKeySizeRounds, TByte, TRoundKey, TAESBuffer } from './types';
import { AESValidation } from './aes-validation';
import {
  KEY_SIZE_ROUNDS,
  AES_ROUND_CONSTANTS,
  AES_S_BOX,
  AES_INVERSE_S_BOX,
  AES_NUMBER_OF_COLUMNS,
  AES_ENCRYPT_TRANSFORMATION_1,
  AES_ENCRYPT_TRANSFORMATION_2,
  AES_ENCRYPT_TRANSFORMATION_3,
  AES_ENCRYPT_TRANSFORMATION_4,
  AES_DECRYPT_TRANSFORMATION_5,
  AES_DECRYPT_TRANSFORMATION_6,
  AES_DECRYPT_TRANSFORMATION_7,
  AES_DECRYPT_TRANSFORMATION_8,
  DECRYPTION_KEY_EXPANSION_TABLE_1,
  DECRYPTION_KEY_EXPANSION_TABLE_2,
  DECRYPTION_KEY_EXPANSION_TABLE_3,
  DECRYPTION_KEY_EXPANSION_TABLE_4,
} from './constants';

/**
 * This class encapsulates shared constants, resources, and utility functions used
 * in AES encryption and decryption processes. It provides access to key schedules,
 * transformation matrices, round constants, and utility methods for handling AES operations.
 */
export class AESSharedResources {
  private static keySizeRounds: TKeySizeRounds = KEY_SIZE_ROUNDS;
  public static roundConstants = AES_ROUND_CONSTANTS;
  public static aesSBox = AES_S_BOX;
  public static aesInverseSBox = AES_INVERSE_S_BOX;
  public static numberOfColumns = AES_NUMBER_OF_COLUMNS; // Known as Nb

  public static aesEncryptTransformation1 = AES_ENCRYPT_TRANSFORMATION_1;
  public static aesEncryptTransformation2 = AES_ENCRYPT_TRANSFORMATION_2;
  public static aesEncryptTransformation3 = AES_ENCRYPT_TRANSFORMATION_3;
  public static aesEncryptTransformation4 = AES_ENCRYPT_TRANSFORMATION_4;

  public static aesDecryptTransformation5 = AES_DECRYPT_TRANSFORMATION_5;
  public static aesDecryptTransformation6 = AES_DECRYPT_TRANSFORMATION_6;
  public static aesDecryptTransformation7 = AES_DECRYPT_TRANSFORMATION_7;
  public static aesDecryptTransformation8 = AES_DECRYPT_TRANSFORMATION_8;

  public static decryptionKeyExpansionTable1 = DECRYPTION_KEY_EXPANSION_TABLE_1;
  public static decryptionKeyExpansionTable2 = DECRYPTION_KEY_EXPANSION_TABLE_2;
  public static decryptionKeyExpansionTable3 = DECRYPTION_KEY_EXPANSION_TABLE_3;
  public static decryptionKeyExpansionTable4 = DECRYPTION_KEY_EXPANSION_TABLE_4;

  static getNumberOfRounds = (
    keySize: keyof typeof KEY_SIZE_ROUNDS,
  ): number => {
    if (!this.keySizeRounds[keySize])
      throw new AESError({
        message:
          'Invalid key size (must be 16, 24, or 32 bytes) for AES encryption.',
        statusCode: 400,
        customErrorCode: 'AES_KEY_SIZE_INVALID',
        name: 'AES Encryption Error',
      });

    return this.keySizeRounds[keySize];
  };

  public static validateAndWrapUnit8Array = <T extends TByte[] | Uint8Array>(
    arg: T | unknown,
    copy?: boolean,
  ): Uint8Array => {
    if (AESValidation.isUint8Array(arg)) {
      return copy ? arg.slice() : arg;
    }

    if (!AESValidation.checkInts(arg)) {
      throw new AESError({
        message: `Array contains invalid value: ${arg}`,
        statusCode: 400,
        customErrorCode: 'AES_KEY_SIZE_INVALID',
        name: 'AES Encryption Error',
      });
    }

    return new Uint8Array(arg);
  };

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

  public static roundConstant(roundConstantPointer: number): number {
    return this.roundConstants[roundConstantPointer];
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

  //   public static copyArray = (
  //     sourceArray: TAESBuffer,
  //     targetArray: Uint8Array,
  //     targetStart?: number,
  //     sourceStart?: number,
  //     sourceEnd?: number,
  //   ) => {
  //     if (sourceStart != null || sourceEnd != null) {
  //       sourceArray = sourceArray.slice(sourceStart, sourceEnd)
  //     }
  //     targetArray.set(sourceArray, targetStart)
  //   }

  public static copyArray = (
    sourceArray: TAESBuffer,
    targetArray: Uint8Array,
    targetStart = 0,
    sourceStart = 0,
    sourceEnd = sourceArray.length,
  ): void => {
    let slice: TAESBuffer;
    // TODO: CHECK IF AESBUFFER IS COMING IN ONLY AS UNIT8ARRAY
    if (sourceArray instanceof Uint8Array) {
      // Use subarray for Uint8Array (more efficient than slice)
      slice = sourceArray.subarray(sourceStart, sourceEnd);
    } else {
      // For regular arrays, use slice
      slice = sourceArray.slice(sourceStart, sourceEnd);
    }

    targetArray.set(slice, targetStart);
  };
  public static toSingedInteger = (value: number): number => {
    return parseInt(value.toString(), 10);
  };
}
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
