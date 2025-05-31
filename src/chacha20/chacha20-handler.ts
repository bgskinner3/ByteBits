import { ChaCha20Core } from './chacha20-core';
import { CHA_CHA_PROCESS_BLOCK_SIZE } from './constants';
import { ChaCha20Error, ChaCha20Utils } from './utils';
export class ChaCha20Handler {
  private core: ChaCha20Core;
  private keyStream: Uint8Array = new Uint8Array(64);
  private keyStreamIndex = 64;
  private readonly processBlockSize = CHA_CHA_PROCESS_BLOCK_SIZE;

  constructor(key: string, nonce: Uint8Array, counter = 0) {
    if (!key) {
      throw new ChaCha20Error({ message: 'a valid hex key must be applied' });
    }
    const chaCha20Key = ChaCha20Utils.generateKeyFromHex(key);
    this.core = new ChaCha20Core(chaCha20Key, nonce, counter);
  }
  private refillKeyStream() {
    this.keyStream = this.core.generateBlock();
    this.keyStreamIndex = 0;
  }

  processCipher(data: Uint8Array): Uint8Array {
    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw new ChaCha20Error({
        message: 'Input must be a non-empty Uint8Array',
      });
    }
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      if (this.keyStreamIndex === this.processBlockSize) {
        this.refillKeyStream();
      }
      output[i] = data[i] ^ this.keyStream[this.keyStreamIndex++];
    }
    return output;
  }
}

// import type { ChaCha20Core } from "./chacha20-core";
// import { CHA_CHA_PROCESS_BLOCK_SIZE } from "./constants";
// export class ChaCha20Cipher {
//     private readonly core: ChaCha20Core;
//     private readonly processBlockSize = CHA_CHA_PROCESS_BLOCK_SIZE

//     constructor(core: ChaCha20Core) {
//         this.core = core;
//     }

//     process(input: Uint8Array): Uint8Array {
//         const output = new Uint8Array(input.length);

//         const blockSize = this.processBlockSize;

//         for (let offset = 0; offset < input.length; offset += blockSize) {
//             // Generate the next 64-byte keystream block
//             const keyStream = this.core.generateBlock();

//             // XOR
//             const blockLength = Math.min(blockSize, input.length - offset);
//             for (let i = 0; i < blockLength; i++) {
//                 output[offset + i] = input[offset + i] ^ keyStream[i];
//             }
//         }

//         return output;
//     }
// }
