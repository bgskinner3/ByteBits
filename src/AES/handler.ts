import { AESCore } from './aes-core';
import { AESUtils } from './aes-utils';
import { AESCounterCTR } from './aes-counter';
import { AESEncryptDecrypt } from './aes-encrypt-decrypt';
import { TAESBuffer } from './types';

export class AESHandler {
  private _aes: AESCore;
  private _encryptDecrypt: AESEncryptDecrypt;
  private _nonce: Uint8Array | null; // 12-byte nonce
  private _counter: AESCounterCTR | null;
  private _remainingCounter: null | Uint8Array = null;
  private _remainingCounterIndex: number = 16;
  private _initialCounterValue: number;

  /**
   * @param key The AES key as Uint8Array
   * @param nonce Optional 12-byte nonce. If not provided, will generate a random one on encrypt.
   * @param initialCounterValue Optional initial counter number (default 1)
   */
  constructor(key: Uint8Array, nonce?: Uint8Array, initialCounterValue = 1) {
    this._aes = new AESCore(key);
    this._encryptDecrypt = new AESEncryptDecrypt();
    this._initialCounterValue = initialCounterValue;

    if (nonce) {
      this._nonce = new Uint8Array(12);
      this._counter = new AESCounterCTR(initialCounterValue, this._nonce);
    } else {
      this._nonce = null;

      this._counter = null;
    }
  }

  /**
   * Encrypts the plaintext with AES CTR mode.
   * Generates nonce if not set.
   * @param plaintext
   * @returns Object containing ciphertext and nonce (for storage/transfer)
   *
   * @note nonce, is needed for decryption
   * with regard to method i.e kalo-skribi must be used and tacked on to phrase in accoradnce to
   * sharding and wrapping method
   */
  public encrypt(plaintext: TAESBuffer): {
    cipherText: Uint8Array;
    nonce: Uint8Array;
  } {
    // Generate fresh nonce and reset counter + internal state
    this._nonce = AESUtils.generateNonce();
    this._counter = new AESCounterCTR(this._initialCounterValue, this._nonce);
    this._remainingCounter = null;
    this._remainingCounterIndex = 16;

    const cipherText = this._encryptDecrypt.AESEncryptCTR({
      plaintext,
      state: {
        _counter: this._counter,
        _remainingCounter: this._remainingCounter,
        _remainingCounterIndex: this._remainingCounterIndex,
        _aes: this._aes,
      },
    });

    return { cipherText, nonce: this._nonce };
  }

  /**
   * Decrypts ciphertext with given nonce and initial counter.
   * Initializes counter with nonce and initialCounterValue.
   * @param cipherText
   * @param nonce
   * @param initialCounterValue Optional initial counter number (default 1)
   */
  public decrypt(
    cipherText: Uint8Array,
    nonce: Uint8Array,
    initialCounterValue = 1,
  ): Uint8Array {
    const counter = new AESCounterCTR(initialCounterValue, nonce);

    return this._encryptDecrypt.AESEncryptCTR({
      plaintext: cipherText,
      state: {
        _counter: counter,
        _aes: this._aes,
        _remainingCounter: null,
        _remainingCounterIndex: 16,
      },
    });
  }
}
