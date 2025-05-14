import { AESCounterCTR } from './aes-counter';
import { AESEncryptDecrypt } from './aes-encrypt-decrypt';
import { TAESBuffer } from './types';
import { AESSharedResources } from './aes-shared-resources';
import { AESCore } from './aes-core';

export class AESHandler {
  private _counter: AESCounterCTR;
  private _remainingCounter: null | Uint8Array;
  private _remainingCounterIndex: number;
  private _aes: AESCore;

  constructor(aes: AESCore, counter: AESCounterCTR) {
    // Initialize AES instance and counter
    this._aes = aes;
    this._counter =
      counter instanceof AESCounterCTR ? counter : new AESCounterCTR(counter);
    this._remainingCounter = null;
    this._remainingCounterIndex = 16;
  }

  // private process(data: TAESBuffer) {
  //     // Logic for processing the data (encryption or decryption)
  //     // Assuming AESEncryptDecrypt handles both encrypt and decrypt
  //     return  AESEncryptDecrypt(this._aes, data, this)
  //   }
  //   encrypt(plaintext: TAESBuffer) {
  //     return this.process(plaintext)
  //   }

  //   decrypt(ciphertext: TAESBuffer) {
  //     return this.process(ciphertext)
  //   }
}
