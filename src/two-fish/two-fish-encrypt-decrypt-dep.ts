import { TwoFishCore } from './two-fish-core';
import { TwoFishError } from './utils';
import { TwoFishUtils } from './utils/two-fish-utils';
import { TwoFishSharedValues } from './two-fish-shared-values';

type TEncryptDecryptBlockProps = {
  plain: Uint8Array;
  inputOffSet: number;
  cipher: Uint8Array;
  outputOffset: number;
};

export class TwoFishEncryptDecryptd {
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
    let state1 =
      TwoFishUtils.readUint32LE(plain, inputOffSet + 4) ^ this.core.s_Keys[1];
    let state2 =
      TwoFishUtils.readUint32LE(plain, inputOffSet + 8) ^ this.core.s_Keys[2];
    let state3 =
      TwoFishUtils.readUint32LE(plain, inputOffSet + 12) ^ this.core.s_Keys[3];

    let t0: number, t1: number;
    let k = this.ROUND_SUB_KEYS;

    for (let round = 0; round < this.ROUNDS; round += 2) {
      t0 = this.sBoxTransform(state0);
      t1 = this.sBoxTransform(state1);

      state2 ^= t0 + t1 + this.core.s_Keys[k++];
      state2 = this.rotateRight(state2, 1);

      state3 = this.rotateLeft(state3, 1);
      state3 ^= t0 + 2 * t1 + this.core.s_Keys[k++];

      t0 = this.sBoxTransform(state2);
      t1 = this.sBoxTransform(state3);

      state0 ^= t0 + t1 + this.core.s_Keys[k++];
      state0 = this.rotateRight(state0, 1);

      state1 = this.rotateLeft(state1, 1);
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

  protected decryptBlock({
    plain,
    inputOffSet,
    cipher,
    outputOffset,
  }: TEncryptDecryptBlockProps) {
    if (cipher.length < inputOffSet + 16 || plain.length < outputOffset + 16) {
      const isCipherTestError = cipher.length < inputOffSet + 16;
      throw new TwoFishError({
        message: isCipherTestError
          ? 'Incomplete ciphertext block.'
          : 'Insufficient space to write plaintext block.',
        customErrorCode: isCipherTestError
          ? 'INCOMPLETE_CIPHERTEXT'
          : 'INSUFFICIENT_PLAINTEXT_SPACE',
      });
    }

    let state0 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet) ^ this.core.s_Keys[4];
    let state1 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet + 4) ^ this.core.s_Keys[5];
    let state2 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet + 8) ^ this.core.s_Keys[6];
    let state3 =
      TwoFishUtils.readUint32LE(cipher, inputOffSet + 12) ^ this.core.s_Keys[7];

    let t0: number, t1: number;
    let k = this.ROUND_SUB_KEYS + 2 * this.ROUNDS - 1;

    for (let round = 0; round < this.ROUNDS; round += 2) {
      t0 = this.sBoxTransform(state0);
      t1 = this.sBoxTransform(state1);

      state2 ^= t0 + t1 + this.core.s_Keys[k--];
      state2 = this.rotateRight(state2, 1);

      state3 = this.rotateLeft(state3, 1);
      state3 ^= t0 + 2 * t1 + this.core.s_Keys[k--];

      t0 = this.sBoxTransform(state2);
      t1 = this.sBoxTransform(state3);

      state0 ^= t0 + t1 + this.core.s_Keys[k--];
      state0 = this.rotateRight(state0, 1);

      state1 = this.rotateLeft(state1, 1);
      state1 ^= t0 + 2 * t1 + this.core.s_Keys[k--];
    }

    // this.outputBlock(
    //     {
    //         outputBuffer: plain,
    //         outputOffset,
    //         word0: state0 ^ this.core.s_Keys[0], word1: state1 ^ this.core.s_Keys[1], word2: state2 ^ this.core.s_Keys[2], word3: state3 ^ this.core.s_Keys[3],
    //     }

    // )
  }

  public encrypt(buffer: Uint8Array): Uint8Array {
    // const blockSize = 16; // Define the block size (16 bytes for TwoFish)

    // // Calculate padding length
    // const paddingLength = blockSize - (buffer.length % blockSize);

    // // If padding is needed, apply PKCS#7 padding
    // const paddedBuffer =
    //   paddingLength === blockSize
    //     ? buffer
    //     : new Uint8Array(buffer.length + paddingLength);

    // // Copy the original buffer into the padded buffer
    // paddedBuffer.set(buffer);

    // // Fill the padding area with the padding length value
    // for (let i = buffer.length; i < paddedBuffer.length; i++) {
    //   paddedBuffer[i] = paddingLength;
    // }
    // const cipher: Uint8Array = new Uint8Array(paddedBuffer.length);

    // let oo = 0; // Output index

    // const blockCount = Math.ceil(buffer.length / blockSize);

    // for (let i = 0; i < blockCount; i++) {
    //   // Get the current block (8 bytes)
    //   const blockStart = i * blockSize;
    //   const blockEnd = Math.min((i + 1) * blockSize, buffer.length);
    //   const block = buffer.slice(blockStart, blockEnd);

    //   // Encrypt the block using encryptBlock
    //   this.encryptBlock({plain: block, inputOffSet: 0, cipher, outputOffset: oo});

    //   // Update the output index (16 bytes per block)
    //   oo += 16;
    // }
    // return cipher;
    const blockSize = 16;

    // Calculate padding length (always 1 to 16)
    const paddingLength = blockSize - (buffer.length % blockSize);

    // Create padded buffer
    const paddedBuffer = new Uint8Array(buffer.length + paddingLength);

    // Copy original data
    paddedBuffer.set(buffer);

    // Fill padding bytes with paddingLength value
    for (let i = buffer.length; i < paddedBuffer.length; i++) {
      paddedBuffer[i] = paddingLength;
    }

    const cipher = new Uint8Array(paddedBuffer.length);
    let oo = 0; // output offset

    const blockCount = paddedBuffer.length / blockSize;

    for (let i = 0; i < blockCount; i++) {
      const blockStart = i * blockSize;
      // Instead of slicing, you can pass the paddedBuffer directly with offset
      this.encryptBlock({
        plain: paddedBuffer,
        inputOffSet: blockStart,
        cipher,
        outputOffset: oo,
      });
      oo += blockSize;
    }

    return cipher;
  }
  // public encrypt(buffer: Uint8Array): Uint8Array {
  //     const padded = this.pad(buffer); // Ensure full 16-byte blocks
  //     const cipher = new Uint8Array(padded.length);
  //     const blockSize = this.BLOCK_SIZE;

  //     for (let i = 0; i < padded.length; i += blockSize) {
  //         this.encryptBlock({
  //             plain: padded,
  //             inputOffSet: i,
  //             cipher,
  //             outputOffset: i,
  //         });
  //     }
  //     console.log({ cipher })
  //     return cipher;
  // }
  public decrypt(buffer: Uint8Array): Uint8Array {
    const blockSize = this.BLOCK_SIZE;

    if (buffer.length % blockSize !== 0) {
      throw new Error('Invalid ciphertext length');
    }

    const plain = new Uint8Array(buffer.length);

    for (let i = 0; i < buffer.length; i += blockSize) {
      this.decryptBlock({
        cipher: buffer,
        inputOffSet: i,
        plain: plain,
        outputOffset: i,
      });
    }

    return this.unpad(plain);
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
  /**
   * BLOCK PROCESSING HELPERS
   */
  private rotateRight = (val: number, bits: number) =>
    ((val >>> bits) | (val << (32 - bits))) >>> 0;
  private rotateLeft = (val: number, bits: number) =>
    ((val << bits) | (val >>> (32 - bits))) >>> 0;

  private pad(data: Uint8Array): Uint8Array {
    // const padding = this.BLOCK_SIZE - (data.length % this.BLOCK_SIZE);
    // const result = new Uint8Array(data.length + padding);
    // result.set(data, 0);
    // result.fill(padding, data.length); // Fill remaining bytes with `padding` value
    // return result;
    const padding = this.BLOCK_SIZE - (data.length % this.BLOCK_SIZE);
    console.log('Padding to add:', padding);
    const result = new Uint8Array(data.length + padding);
    result.set(data, 0);
    result.fill(padding, data.length);
    console.log('Padded data tail:', result.slice(-padding));
    return result;
  }
  private unpad(data: Uint8Array): Uint8Array {
    const padding = data[data.length - 1];
    console.log('Padding byte:', padding);
    console.log('Data tail bytes:', data.slice(data.length - padding));
    if (padding < 1 || padding > 16) {
      throw new Error('Invalid padding.');
    }

    return data.subarray(0, data.length - padding);
  }
}
