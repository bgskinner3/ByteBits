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
import type { TKeySizeRounds } from './types';
/** @internal */
export class AESSharedValues {
  static keySizeRounds: TKeySizeRounds = KEY_SIZE_ROUNDS;
  static roundConstants = AES_ROUND_CONSTANTS;
  static aesSBox = AES_S_BOX;
  static aesInverseSBox = AES_INVERSE_S_BOX;
  static numberOfColumns = AES_NUMBER_OF_COLUMNS; // Known as Nb

  static aesEncryptTransformation1 = AES_ENCRYPT_TRANSFORMATION_1;
  static aesEncryptTransformation2 = AES_ENCRYPT_TRANSFORMATION_2;
  static aesEncryptTransformation3 = AES_ENCRYPT_TRANSFORMATION_3;
  static aesEncryptTransformation4 = AES_ENCRYPT_TRANSFORMATION_4;

  static aesDecryptTransformation5 = AES_DECRYPT_TRANSFORMATION_5;
  static aesDecryptTransformation6 = AES_DECRYPT_TRANSFORMATION_6;
  static aesDecryptTransformation7 = AES_DECRYPT_TRANSFORMATION_7;
  static aesDecryptTransformation8 = AES_DECRYPT_TRANSFORMATION_8;

  static decryptionKeyExpansionTable1 = DECRYPTION_KEY_EXPANSION_TABLE_1;
  static decryptionKeyExpansionTable2 = DECRYPTION_KEY_EXPANSION_TABLE_2;
  static decryptionKeyExpansionTable3 = DECRYPTION_KEY_EXPANSION_TABLE_3;
  static decryptionKeyExpansionTable4 = DECRYPTION_KEY_EXPANSION_TABLE_4;

  static encryptionTransformationBoxes = [
    this.aesEncryptTransformation1,
    this.aesEncryptTransformation2,
    this.aesEncryptTransformation3,
    this.aesEncryptTransformation4,
  ];
  static decryptionTransformationBoxes = [
    this.aesDecryptTransformation5,
    this.aesDecryptTransformation6,
    this.aesDecryptTransformation7,
    this.aesDecryptTransformation8,
  ];
}
