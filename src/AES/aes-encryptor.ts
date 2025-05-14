import { TAESBuffer, TRoundKey } from './types';
import { AESError } from './aes-error';
import { AESEncryptionUtils } from './aes-encryptor-utils';
import { AESValidation } from './aes-validation';

class AESEncryption {
  private readonly KEY: TAESBuffer;
  private readonly rounds: number;
  private _expandedKey: TRoundKey[];
  private _encryptionRoundKeys: TRoundKey[] = [];
  private _decryptionRoundKeys: TRoundKey[] = [];

  constructor(key: TAESBuffer) {
    if (!key) {
      throw new AESError({
        message: 'AES requires key!',
        customErrorCode: 'AES_KEY_MISSING',
        name: 'AES Encryption Error',
      });
    }
    this.KEY = AESEncryptionUtils.validateAndWrapUnit8Array(key, true);
    const keySize = AESValidation.inferKeySize(this.KEY);
    this.rounds = AESEncryptionUtils.getNumberOfRounds(keySize);

    AESEncryptionUtils.initializeEncryptionBoxes({
      rounds: this.rounds,
      encryptionRoundKeys: this._encryptionRoundKeys,
      decryptionRoundKeys: this._decryptionRoundKeys,
    });

    // Initialize the expanded key array but do not expand yet
    this._expandedKey = [];
    // this._expandedKey = new Uint32Array(roundKeyCount);
  }

  private expandKey(): void {
    const keyLength = this.KEY.length;
    const roundKeyCount = (this.rounds + 1) * 4;
    // Bitwise shift (>>> 2): faster than division for integers
    const numWordsKey = keyLength >>> 2; // keyLength / 4

    // Convert the key into 32-bit integers (words)
    const tempKey = AESEncryptionUtils.convertToInt32(this.KEY);

    // Populate initial round keys
    for (let i = 0; i < this.rounds; i++) {
      this._expandedKey[i] = [
        (tempKey[i] >> 24) & 0xff, // MSB
        (tempKey[i] >> 16) & 0xff,
        (tempKey[i] >> 8) & 0xff,
        tempKey[i] & 0xff, // LSB
      ];
    }

    // Key expansion (fips-197 section 5.2)
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    for (let t = numWordsKey, rc = 1; t < roundKeyCount; t++) {
      const prev = this._expandedKey[t - 1];
      const tmp = [...prev];

      if (t % numWordsKey === 0) {
        this.rotateWord(tmp);
        this.substituteWord(tmp);
        this.coefficientAddition(tmp, AESEncryptionUtils.roundConstant(rc++));
      } else if (numWordsKey > 6 && t % numWordsKey === 4) {
        this.substituteWord(tmp);
      }

      const from = this._expandedKey[t - numWordsKey];
      this._expandedKey[t] = [
        from[0] ^ tmp[0],
        from[1] ^ tmp[1],
        from[2] ^ tmp[2],
        from[3] ^ tmp[3],
      ];
    }
  }

  // Rotate word for key expansion (rotWord)
  private rotateWord(w: number[]): void {
    const tmp = w[0];
    for (let i = 0; i < 3; i++) {
      w[i] = w[i + 1];
    }
    w[3] = tmp;
  }
  // Substitute bytes in key expansion (subWord)
  private substituteWord(w: number[]): void {
    for (let i = 0; i < 4; i++) {
      w[i] =
        AESEncryptionUtils.aesSBox[16 * ((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
    }
  }
  // XOR with round constant in key expansion (coefAdd)
  private coefficientAddition(w: number[], roundConstant: number): void {
    w[0] ^= roundConstant;
  }
}
