/* eslint-disable @typescript-eslint/no-explicit-any */
import { TKeySizeRounds, TByte, TRoundKey } from './types';
import { AESError } from './aes-error';
import { AESValidation } from './aes-validation';
import {
  KEY_SIZE_ROUNDS,
  AES_ROUND_CONSTANTS,
  AES_S_BOX,
  AES_INVERSE_S_BOX,
  AES_ENCRYPT_TRANSFORMATION_1,
  AES_ENCRYPT_TRANSFORMATION_2,
  AES_ENCRYPT_TRANSFORMATION_3,
  AES_ENCRYPT_TRANSFORMATION_4,
  AES_DECRYPT_TRANSFORMATION_1,
  AES_DECRYPT_TRANSFORMATION_2,
  AES_DECRYPT_TRANSFORMATION_3,
  AES_DECRYPT_TRANSFORMATION_4,
  DECRYPTION_KEY_EXPANSION_TABLE_1,
  DECRYPTION_KEY_EXPANSION_TABLE_2,
  DECRYPTION_KEY_EXPANSION_TABLE_3,
  DECRYPTION_KEY_EXPANSION_TABLE_4,
} from './constants';

export class AESEncryptionUtils {
  private static keySizeRounds: TKeySizeRounds = KEY_SIZE_ROUNDS;
  public static roundConstants = AES_ROUND_CONSTANTS;
  public static aesSBox = AES_S_BOX;
  public static aesInverseSBox = AES_INVERSE_S_BOX;

  public static aesEncryptTransformation1 = AES_ENCRYPT_TRANSFORMATION_1;
  public static aesEncryptTransformation2 = AES_ENCRYPT_TRANSFORMATION_2;
  public static aesEncryptTransformation3 = AES_ENCRYPT_TRANSFORMATION_3;
  public static aesEncryptTransformation4 = AES_ENCRYPT_TRANSFORMATION_4;

  public static aesDecryptTransformation1 = AES_DECRYPT_TRANSFORMATION_1;
  public static aesDecryptTransformation2 = AES_DECRYPT_TRANSFORMATION_2;
  public static aesDecryptTransformation3 = AES_DECRYPT_TRANSFORMATION_3;
  public static aesDecryptTransformation4 = AES_DECRYPT_TRANSFORMATION_4;

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

  public static convertToInt32 = (bytes: number[] | Uint8Array): number[] => {
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
}
