import { AESCore } from './aes-core';
import { AESError } from './aes-utils';
import { AESCounterCTR } from './aes-counter';
import { AESEncryptDecrypt } from './aes-encrypt-decrypt';
import { TAESBuffer } from './types';

/**
 * @example
 * ```typescript
 * import { AESHandler } from './aes-handler';
 *
 * const key = crypto.getRandomValues(new Uint8Array(16)); // 128-bit key
 * const handler = new AESHandler(key);
 *
 * const data = new TextEncoder().encode("Hello, World!");
 * const { cipherText, nonce } = handler.encrypt(data);
 *
 * const decrypted = handler.decrypt(cipherText, nonce);
 * console.log(new TextDecoder().decode(decrypted)); // "Hello, World!"
 * ```
 *
 * AESHandler
 *
 *  Handles nonce generation, counter initialization, and state management for performing
 * secure encryption/decryption operations using AES.
 *
 *  @remarks
 * - AES CTR mode is a stream cipher, and the same nonce + counter combination must never be reused.
 * - The `encrypt` method generates a fresh 12-byte nonce automatically.
 * - The `decrypt` method requires the exact same nonce used during encryption.
 * - You can customize the initial counter value (default is `1`).
 *
 * This handler is base encoding and decoding method for kalo-skribi architecture
 * @note
 * Additional branch's will be added to meet critra if needed
 */
export class KaloAESHandler {
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
  constructor(key: Uint8Array, nonce: Uint8Array, initialCounterValue = 1) {
    this._aes = new AESCore(key);
    this._encryptDecrypt = new AESEncryptDecrypt();
    this._initialCounterValue = initialCounterValue;

    if (nonce) {
      if (nonce.length !== 12) {
        throw new AESError({
          message: 'Nonce must be 12 bytes',
          customErrorCode: 'AES_NONCE_MISSING',
          name: 'AES Encryption Error',
        });
      }
      this._nonce = nonce;
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
  public encrypt(plaintext: TAESBuffer): Uint8Array {
    if (!this._nonce) throw new Error('Nonce not set');
    this._counter = new AESCounterCTR(this._initialCounterValue, this._nonce);
    this._remainingCounter = null;
    this._remainingCounterIndex = 16;

    return this._encryptDecrypt.AESEncryptCTR({
      plaintext,
      state: {
        _counter: this._counter,
        _remainingCounter: this._remainingCounter,
        _remainingCounterIndex: this._remainingCounterIndex,
        _aes: this._aes,
      },
    });
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
