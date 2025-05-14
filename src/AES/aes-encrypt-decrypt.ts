import { AESSharedResources, AESError } from './aes-shared-resources';
import { AESValidation } from './aes-validation';
import type { AESCounterCTR } from './aes-counter';
import { TAESBuffer } from './types';

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
  private encryptionTransformationBoxes = [
    AESSharedResources.aesEncryptTransformation1,
    AESSharedResources.aesEncryptTransformation2,
    AESSharedResources.aesEncryptTransformation3,
    AESSharedResources.aesEncryptTransformation4,
  ];
  private decryptionTransformationBoxes = [
    AESSharedResources.aesEncryptTransformation1,
    AESSharedResources.aesEncryptTransformation2,
    AESSharedResources.aesEncryptTransformation3,
    AESSharedResources.aesEncryptTransformation4,
  ];

  private processBlockAES(
    input: Uint8Array,
    roundKeys: number[][] = [],

    sBox: number[], // S-Box or Inverse S-Box
    isEncryption: boolean, // Flag to decide if encrypting or decrypting
  ): Uint8Array {
    AESValidation.validateInputLength(input);
    const transformations = isEncryption
      ? this.encryptionTransformationBoxes
      : this.decryptionTransformationBoxes;
    const rounds = roundKeys.length - 1;
    let tempKey = AESSharedResources.convertToInt32(input);

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
    // For encryption, use the appropriate transformations and S-box
    return this.processBlockAES(
      plaintext,
      roundKeys,
      AESSharedResources.aesSBox,
      true, // Encrypting
    );
  }
  public decryptBlockAES(
    cipherText: Uint8Array,
    roundKeys: number[][] = [],
  ): Uint8Array {
    // For decryption, use the inverse transformations and inverse S-box
    return this.processBlockAES(
      cipherText,
      roundKeys,
      AESSharedResources.aesInverseSBox,
      false, // Decrypting
    );
  }
  public AESEncryptCTR({ plaintext, state }: TAESEncryptCTR) {
    const encrypted = AESSharedResources.validateAndWrapUnit8Array(
      plaintext,
      true,
    );
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
