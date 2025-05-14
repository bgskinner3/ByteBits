import { AESCounterCTR } from './aes-counter';
import { AESEncryptDecrypt } from './aes-encrypt-decrypt';
import { TAESBuffer } from './types';
import { AESCore } from './aes-core';

export class AESHandler {
  private _counter: AESCounterCTR;
  private _remainingCounter: null | Uint8Array;
  private _remainingCounterIndex: number;
  private _aes: AESCore;
  private _encryptDecrypt: AESEncryptDecrypt;

  constructor(aes: AESCore, counter: AESCounterCTR | number) {
    // Initialize AES instance and counter
    this._aes = aes;
    this._counter =
      counter instanceof AESCounterCTR ? counter : new AESCounterCTR(counter);
    this._remainingCounter = null;
    this._remainingCounterIndex = 16;
    this._encryptDecrypt = new AESEncryptDecrypt();
  }

  /**
   * Encrypts the given plaintext using AES CTR mode.
   * @param {TAESBuffer} plaintext - The data to encrypt.
   * @returns {Uint8Array} - The encrypted ciphertext.
   */
  public encrypt(plaintext: TAESBuffer): Uint8Array {
    return this._encryptDecrypt.AESEncryptCTR({
      plaintext,
      state: {
        _counter: this._counter,
        _remainingCounter: this._remainingCounter,
        _remainingCounterIndex: this._remainingCounterIndex,
      },
    });
  }

  /**
   * Decrypts the given cipherText using AES.
   * @param {TAESBuffer} cipherText - The data to decrypt.
   * @param {number[][]} roundKeys - The round keys for AES decryption.
   * @returns {Uint8Array} - The decrypted plaintext.
   */
  public decrypt(
    cipherText: Uint8Array,
    roundKeys: number[][] = [],
  ): Uint8Array {
    return this._encryptDecrypt.decryptBlockAES(cipherText, roundKeys);
  }
}
