import { TwoFishCore } from './two-fish-core';
import { TwoFishBlockUtils, TwoFishUtils, TwoFishError } from './utils';
import { TwoFishSharedValues } from './two-fish-shared-values';
import { TEncryptDecryptBlockProps } from './types';

export class TwoFishEncryptDecrypt {
  private readonly core: TwoFishCore;
  private ROUND_SUB_KEYS = TwoFishSharedValues.subKeyRounds;
  private ROUNDS = TwoFishSharedValues.totalRounds;
  public BLOCK_SIZE = 16;
  constructor(core: TwoFishCore) {
    this.core = core;
  }
  protected outputBlock({
    outputBuffer,
    outputOffset,
    word0,
    word1,
    word2,
    word3,
  }: {
    outputBuffer: Uint8Array;
    outputOffset: number;
    word0: number;
    word1: number;
    word2: number;
    word3: number;
  }) {
    TwoFishUtils.writeUint32LE(outputBuffer, outputOffset, word0);
    TwoFishUtils.writeUint32LE(outputBuffer, outputOffset + 4, word1);
    TwoFishUtils.writeUint32LE(outputBuffer, outputOffset + 8, word2);
    TwoFishUtils.writeUint32LE(outputBuffer, outputOffset + 12, word3);
  }

  protected encryptBlock({
    plain,
    inputOffSet,
    cipher,
    outputOffset,
  }: TEncryptDecryptBlockProps) {
    if (cipher.length < outputOffset + this.BLOCK_SIZE) {
      throw new TwoFishError({
        message: 'Insufficient space to write ciphertext block.',
        customErrorCode: 'INVALID_BLOCK_SIZE',
        name: 'TWOFISH Encryption Error',
      });
    }

    let state0 =
      TwoFishUtils.readUint32LE(plain, inputOffSet) ^ this.core.s_Keys[0];
    inputOffSet += 4;

    let state1 =
      TwoFishUtils.readUint32LE(plain, inputOffSet) ^ this.core.s_Keys[1];
    inputOffSet += 4;

    let state2 =
      TwoFishUtils.readUint32LE(plain, inputOffSet) ^ this.core.s_Keys[2];
    inputOffSet += 4;

    let state3 =
      TwoFishUtils.readUint32LE(plain, inputOffSet) ^ this.core.s_Keys[3];
    inputOffSet += 4;

    let t0: number, t1: number;
    let k = this.ROUND_SUB_KEYS;

    for (let round = 0; round < this.ROUNDS; round += 2) {
      t0 = this.sBoxTransform(state0);
      t1 = this.sBoxTransform(state1);

      state2 ^= t0 + t1 + this.core.s_Keys[k++];
      state2 = TwoFishBlockUtils.rotateRight(state2, 1);

      state3 = TwoFishBlockUtils.rotateLeft(state3, 1);
      state3 ^= t0 + 2 * t1 + this.core.s_Keys[k++];

      t0 = this.sBoxTransform(state2);
      t1 = this.sBoxTransform(state3);

      state0 ^= t0 + t1 + this.core.s_Keys[k++];
      state0 = TwoFishBlockUtils.rotateRight(state0, 1);

      state1 = TwoFishBlockUtils.rotateLeft(state1, 1);
      state1 ^= t0 + 2 * t1 + this.core.s_Keys[k++];
    }
    const word0: number = state0 ^ this.core.s_Keys[4];
    const word1: number = state1 ^ this.core.s_Keys[5];
    const word2: number = state2 ^ this.core.s_Keys[6];
    const word3: number = state3 ^ this.core.s_Keys[7];

    this.outputBlock({
      outputBuffer: cipher,
      outputOffset,
      word0,
      word1,
      word2,
      word3,
    });
  }
  protected decryptBlock(
    // cipher: Uint8Array,
    // io: number,
    // plain: Uint8Array,
    // oo: number,
    { plain, inputOffSet, cipher, outputOffset }: TEncryptDecryptBlockProps,
  ) {
    if (cipher.length < inputOffSet + 16) {
      throw new TwoFishError({
        message: 'Incomplete ciphertext block.',
        customErrorCode: 'INVALID_BLOCK_SIZE',
        name: 'TWOFISH DECRYPTION Error',
      });
    }
    if (plain.length < outputOffset + 16) {
      throw new TwoFishError({
        message: 'Insufficient space to write plaintext block.',
        customErrorCode: 'INVALID_BLOCK_SIZE',
        name: 'TWOFISH DECRYPTION Error',
      });
    }

    let state0 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet) ^ this.core.s_Keys[4];
    inputOffSet += 4;
    let state1 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet) ^ this.core.s_Keys[5];
    inputOffSet += 4;
    let state2 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet) ^ this.core.s_Keys[6];
    inputOffSet += 4;
    let state3 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet) ^ this.core.s_Keys[7];
    inputOffSet += 4;

    let t0: number, t1: number;
    let k = this.ROUND_SUB_KEYS + this.ROUNDS * 2 - 1;

    for (let round = this.ROUNDS - 1; round >= 0; round -= 2) {
      // First round (r)
      t0 = this.sBoxTransform(state2);
      t1 = this.sBoxTransform(state3);

      state1 = TwoFishBlockUtils.rotateRight(
        state1 ^ (t0 + 2 * t1 + this.core.s_Keys[k--]),
        1,
      );

      state0 = TwoFishBlockUtils.rotateLeft(state0, 1);
      state0 ^= t0 + t1 + this.core.s_Keys[k--];

      // Second round (r - 1)
      t0 = this.sBoxTransform(state0);
      t1 = this.sBoxTransform(state1);

      state3 = TwoFishBlockUtils.rotateRight(
        state3 ^ (t0 + 2 * t1 + this.core.s_Keys[k--]),
        1,
      );

      state2 = TwoFishBlockUtils.rotateLeft(state2, 1);
      state2 ^= t0 + t1 + this.core.s_Keys[k--];
    }
    const word0: number = state0 ^ this.core.s_Keys[0];
    const word1: number = state1 ^ this.core.s_Keys[1];
    const word2: number = state2 ^ this.core.s_Keys[2];
    const word3: number = state3 ^ this.core.s_Keys[3];
    this.outputBlock({
      outputBuffer: plain,
      outputOffset,
      word0,
      word1,
      word2,
      word3,
    });
  }
  private sBoxTransform = (x: number) => {
    const mask = 0x1fe;
    const base = 0x200;
    return (
      this.core.s_Box[(x << 1) & mask] ^
      this.core.s_Box[((x >>> 7) & mask) + 1] ^
      this.core.s_Box[base + ((x >>> 15) & mask)] ^
      this.core.s_Box[base + ((x >>> 23) & mask) + 1]
    );
  };
  public encrypt(buffer: Uint8Array): Uint8Array {
    const blockSize = this.BLOCK_SIZE; // 16 bytes

    // Step 1: Pad input using your utility
    const paddedBuffer = TwoFishBlockUtils.pkcs7Pad(buffer);

    // Step 2: Allocate output buffer same size as padded input
    const cipher = new Uint8Array(paddedBuffer.length);

    // Step 3: Calculate number of 16-byte blocks
    const blockCount = paddedBuffer.length / blockSize;

    let outputOffset = 0;
    for (let i = 0; i < blockCount; i++) {
      const inputOffset = i * blockSize;

      // Step 4: Encrypt block in-place into cipher buffer
      this.encryptBlock({
        plain: paddedBuffer,
        inputOffSet: inputOffset,
        cipher,
        outputOffset,
      });

      outputOffset += blockSize;
    }

    // Step 5: Return encrypted buffer
    return cipher;
  }
  public decrypt(buffer: Uint8Array): Uint8Array {
    const blockSize = this.BLOCK_SIZE; // 16 bytes

    if (buffer.length % blockSize !== 0) {
      throw new TwoFishError({
        message: 'Invalid ciphertext length, must be multiple of block size.',
        customErrorCode: 'INVALID_CIPHER_LENGTH',
        name: 'TWOFISH Decryption Error',
      });
    }
    const plain = new Uint8Array(buffer.length);
    const blockCount = buffer.length / blockSize;
    for (let i = 0; i < blockCount; i++) {
      const inputOffSet = i * blockSize;
      const outputOffset = i * blockSize;

      this.decryptBlock({ plain, inputOffSet, cipher: buffer, outputOffset });
    }

    return TwoFishBlockUtils.pkcs7UnPad(plain);
  }
}
