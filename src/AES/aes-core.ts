import { TAESBuffer, TRoundKey } from './types';
import { AESError, AESSharedResources } from './aes-shared-resources';
import { AESValidation } from './aes-validation';

/**
 * AESEncryption class
 * This class encapsulates the core AES encryption and decryption logic, including key expansion,
 * block transformations, and encryption/decryption operations.
 * ----
 * AES-specific notation (based on FIPS-197):
 *
 * - 📐 Nk: Number of 32-bit words in the key (4/6/8 for AES-128/192/256)
 * - 📊 Nr: Number of rounds (Nk + 6 → 10/12/14 for AES-128/192/256)
 * - 🔒 w[]: Key schedule consisting of Nb * (Nr + 1) 32-bit words
 * - Nb: Number of columns in the state (always 4 for AES)
 *
 * Key expansion reference: FIPS-197 Section 5.2 — "Key Expansion"
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 */
export class AESCore {
  private KEY: Uint8Array;
  private rounds: number; // 📊  Nr in FIPS-197
  // ***** KNOWN AS    _Ke
  private _encryptionRoundKeys: TRoundKey[] = []; //  🔒 w[] — Key schedule (expanded key words)
  // ***** KNOWN AS  _decryptionRoundKeys
  private _decryptionRoundKeys: TRoundKey[] = []; //  🔒 w[] — Key schedule (expanded key words)

  constructor(key: TAESBuffer) {
    if (!key) {
      throw new AESError({
        message: 'AES requires key!',
        customErrorCode: 'AES_KEY_MISSING',
        name: 'AES Encryption Error',
      });
    }
    this.KEY = AESSharedResources.validateAndWrapUnit8Array(key, true);
    const keySize = AESValidation.inferKeySize(this.KEY);
    this.rounds = AESSharedResources.getNumberOfRounds(keySize); // Nr = Nk + 6

    AESSharedResources.initializeEncryptionBoxes({
      rounds: this.rounds,
      encryptionRoundKeys: this._encryptionRoundKeys,
      decryptionRoundKeys: this._decryptionRoundKeys,
    });

    this.expandKey();
  }

  private expandKey(): void {
    const keyLength = this.KEY.length;
    const roundKeyCount =
      AESSharedResources.numberOfColumns * (this.rounds + 1); // 🔒(FIPS-197) w[] length
    const numWordsKey = keyLength >>> 2; // 📐 (FIPS-197) Nk — number
    const tempKey = AESSharedResources.convertToInt32(this.KEY); // 📐 Input key interpreted as array of Nk 32-bit words

    for (let i = 0, idx = 0; i < numWordsKey; i++) {
      idx = i >> 2;
      this._encryptionRoundKeys[idx][i % 4] = tempKey[i];
      this._decryptionRoundKeys[this.rounds - idx][i % 4] = tempKey[i];
    }

    // Key expansion (fips-197 section 5.2)
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    for (let t = numWordsKey, rc = 1; t < roundKeyCount; t++) {
      const prev: number = tempKey[t - 1]; // @note temp ← w[t - 1] (the previous word)
      const tmp: number[] = [prev]; // corresponds to `temp` in FIPS-197

      if (t % numWordsKey === 0) {
        this.rotateWord(tmp);
        this.substituteWord(tmp);
        this.coefficientAddition(tmp, AESSharedResources.roundConstant(rc++));
      } else if (numWordsKey > 6 && t % numWordsKey === 4) {
        this.substituteWord(tmp); // For AES-256 only: If Nk > 6 and t mod Nk === 4, temp ← SubWord(temp)
      }

      const from = tempKey[t - numWordsKey]; //  w[t] = w[t - Nk] ⊕ temp
      tempKey[t] = [
        from[0] ^ tmp[0],
        from[1] ^ tmp[1],
        from[2] ^ tmp[2],
        from[3] ^ tmp[3],
      ];
    }
    for (let t = 0; t < roundKeyCount; t++) {
      const row = Math.floor(t / 4);
      const col = t % 4;

      // Populate encryption round keys
      this._encryptionRoundKeys[row][col] = tempKey[t];

      // Populate decryption round keys (in reverse order)
      this._decryptionRoundKeys[this.rounds - row][col] = tempKey[t];
    }
    // inverse-cipher-ify the decryption round key (fips-197 section 5.3)
    for (let r = 1; r < this.rounds; r++) {
      for (let c = 0; c < 4; c++) {
        const tt = this._decryptionRoundKeys[r][c];
        this._decryptionRoundKeys[r][c] =
          AESSharedResources.decryptionKeyExpansionTable1[(tt >> 24) & 0xff] ^
          AESSharedResources.decryptionKeyExpansionTable2[(tt >> 16) & 0xff] ^
          AESSharedResources.decryptionKeyExpansionTable3[(tt >> 8) & 0xff] ^
          AESSharedResources.decryptionKeyExpansionTable4[tt & 0xff];
      }
    }
  }

  /**
   * @note AES RotWord function — left-rotate 4-byte word
   */
  private rotateWord(w: number[]): void {
    const tmp = w[0];
    for (let i = 0; i < 3; i++) {
      w[i] = w[i + 1];
    }
    w[3] = tmp;
  }

  /**
   * @note AES SubWord function — apply AES S-Box to each byte in the word
   */
  private substituteWord(w: number[]): void {
    for (let i = 0; i < 4; i++) {
      w[i] =
        AESSharedResources.aesSBox[16 * ((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
    }
  }

  /**
   * @note XOR first byte with the round constant
   */
  private coefficientAddition(w: number[], roundConstant: number): void {
    w[0] ^= roundConstant;
  }
}
