// import { AESCounterCTR } from './aes-counter';
// import { AESEncryptDecrypt } from './aes-encrypt-decrypt';
// import { TAESBuffer } from './types';
// import { AESCore } from './aes-core';

// export class AESHandler {
//   private _counter: AESCounterCTR;
//   private _remainingCounter: null | Uint8Array;
//   private _remainingCounterIndex: number;
//   private _aes: AESCore;
//   private _encryptDecrypt: AESEncryptDecrypt;

//   constructor(aes: AESCore, counter: AESCounterCTR | number) {
//     // Initialize AES instance and counter
//     this._aes = aes;
//     this._counter =
//       counter instanceof AESCounterCTR ? counter : new AESCounterCTR(counter);
//     this._remainingCounter = null;
//     this._remainingCounterIndex = 16;
//     this._encryptDecrypt = new AESEncryptDecrypt();
//   }

//   /**
//    * Encrypts the given plaintext using AES CTR mode.
//    * @param {TAESBuffer} plaintext - The data to encrypt.
//    * @returns {Uint8Array} - The encrypted ciphertext.
//    */
//   public encrypt(plaintext: TAESBuffer): Uint8Array {
//     return this._encryptDecrypt.AESEncryptCTR({
//       plaintext,
//       state: {
//         _counter: this._counter,
//         _remainingCounter: this._remainingCounter,
//         _remainingCounterIndex: this._remainingCounterIndex,
//         _aes: this._aes
//       },
//     });
//   }

//   /**
//    * Decrypts the given cipherText using AES.
//    * @param {TAESBuffer} cipherText - The data to decrypt.
//    * @param {number[][]} roundKeys - The round keys for AES decryption.
//    * @returns {Uint8Array} - The decrypted plaintext.
//    */
//   public decrypt(
//     cipherText: Uint8Array,
//   ): Uint8Array {
//     const decryptedRoundKeys = this._aes.getDecryptionRoundKeys()
//     return this._encryptDecrypt.decryptBlockAES(cipherText, decryptedRoundKeys);
//   }
// }

import { AESCore } from './aes-core';
import { AESUtils, AESError } from './aes-utils';
import { AESCounterCTR } from './aes-counter';
import { AESEncryptDecrypt } from './aes-encrypt-decrypt';
import { TAESBuffer } from './types';

export class AESHandler {
    private _aes: AESCore;
    private _encryptDecrypt: AESEncryptDecrypt;
    private _nonce: Uint8Array | null // 12-byte nonce
    private _counter: AESCounterCTR | null
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
            this._nonce = null
      
            this._counter = null;
        }
    }

    /**
     * Encrypts the plaintext with AES CTR mode.
     * Generates nonce if not set.
     * @param plaintext
     * @returns Object containing ciphertext and nonce (for storage/transfer)
     */
    public encrypt(plaintext: TAESBuffer): { cipherText: Uint8Array; nonce: Uint8Array } {
        if (!this._nonce || !this._counter) {
            this._nonce = AESUtils.generateNonce();
            this._counter = new AESCounterCTR(this._initialCounterValue, this._nonce);
        }
   

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
        initialCounterValue = 1
    ): Uint8Array {
        if (nonce.length !== 12 || !nonce) {

            throw new AESError({
                message: 'Nonce must be 12 bytes',
                customErrorCode: 'AES_NONCE_INVALID',
                statusCode: 400,
            });
        }
        // Setup counter with provided nonce & initial counter
        this._counter = new AESCounterCTR(initialCounterValue, nonce);
        this._remainingCounter = null;
        this._remainingCounterIndex = 16;

        // Decrypt by "encrypting" cipherText using CTR mode
        return this._encryptDecrypt.AESEncryptCTR({
            plaintext: cipherText,
            state: {
                _counter: this._counter,
                _remainingCounter: this._remainingCounter,
                _remainingCounterIndex: this._remainingCounterIndex,
                _aes: this._aes,
            },
        });
    }
}
