import type { AESCounterCTR } from './aes-counter';
import { TAESBuffer } from './types';
import { AESSharedValues } from './aes-shared-values';
import { AESUtils } from './aes-utils';

type TAESEncryptCTR = {
  plaintext: TAESBuffer;
  state: {
    _counter: AESCounterCTR;
    _remainingCounter: null | Uint8Array;
    _remainingCounterIndex: number;
  };
};

export class AESEncryptDecrypt {
  private roundState: number[] = new Array(4).fill(0);
  private encryptionTransformationBoxes =
    AESSharedValues.encryptionTransformationBoxes;
  private decryptionTransformationBoxes =
    AESSharedValues.decryptionTransformationBoxes;

  /**
   * Since CTR is symmetrical
   *   ***that is The same operation is used for both encryption and decryption.***
   * We consolidate the block process into one method, with the only difference being the
   * 1. transformation Boxes
   * 2. sBox
   */
  private processBlockAES(
    input: Uint8Array,
    roundKeys: number[][] = [],
    sBox: number[],
    isEncryption: boolean,
  ): Uint8Array {
    AESUtils.validateInputLength(input);
    const transformations = isEncryption
      ? this.encryptionTransformationBoxes
      : this.decryptionTransformationBoxes;
    const rounds = roundKeys.length - 1;
    let tempKey = AESUtils.convertToInt32(input);

    // Initial round key XOR
    for (let i = 0; i < 4; i++) {
      tempKey[i] ^= roundKeys[0][i];
    }

    // Apply the round transformations
    for (let r = 1; r < rounds; r++) {
      for (let i = 0; i < 4; i++) {
        this.roundState[i] =
          transformations[0][(tempKey[i] >> 24) & 0xff] ^
          transformations[1][(tempKey[(i + 1) % 4] >> 16) & 0xff] ^
          transformations[2][(tempKey[(i + 2) % 4] >> 8) & 0xff] ^
          transformations[3][tempKey[(i + 3) % 4] & 0xff] ^
          roundKeys[r][i];
      }
      tempKey = this.roundState.slice();
    }

    // Final round
    const result = new Uint8Array(16);
    for (let i = 0, tt = 0; i < 4; i++) {
      tt = roundKeys[rounds][i];
      result[4 * i] = (sBox[(tempKey[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
      result[4 * i + 1] =
        (sBox[(tempKey[(i + 1) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
      result[4 * i + 2] =
        (sBox[(tempKey[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff;
      result[4 * i + 3] = (sBox[tempKey[(i + 3) % 4] & 0xff] ^ tt) & 0xff;
    }

    return result;
  }
  private encryptBlockAES(
    plaintext: Uint8Array,
    roundKeys: number[][] = [],
  ): Uint8Array {
    return this.processBlockAES(
      plaintext,
      roundKeys,
      AESSharedValues.aesSBox,
      true, // Encrypting
    );
  }
  public decryptBlockAES(
    cipherText: Uint8Array,
    roundKeys: number[][] = [],
  ): Uint8Array {
    return this.processBlockAES(
      cipherText,
      roundKeys,
      AESSharedValues.aesInverseSBox,
      false, // Decrypting
    );
  }
  public AESEncryptCTR({ plaintext, state }: TAESEncryptCTR) {
    const encrypted = AESUtils.validateAndWrapUnit8Array(plaintext, true);
    for (let i = 0; i < encrypted.length; i++) {
      if (state._remainingCounterIndex === 16) {
        state._remainingCounter = this.encryptBlockAES(state._counter._counter);
        state._remainingCounterIndex = 0;
        state._counter.increment();
      }
      encrypted[i] ^= state._remainingCounter![state._remainingCounterIndex++];
    }
    return encrypted;
  }
}
