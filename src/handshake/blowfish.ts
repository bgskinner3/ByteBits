import { BlowfishSharedVar } from './blowfish-shared';

export class Blowfish {
  // maximum possible key length
  public static MAXKEYLENGTH = 56;
  // size of the single boxes
  private PBOX_ENTRIES = 18;
  private SBOX_ENTRIES = 256;

  // encryption boxes
  private pboxes: Uint32Array;
  private sboxes1: Uint32Array;
  private sboxes2: Uint32Array;
  private sboxes3: Uint32Array;
  private sboxes4: Uint32Array;

  constructor(bkey: Uint8Array) {
    this.pboxes = new Uint32Array();
    this.sboxes1 = new Uint32Array();
    this.sboxes2 = new Uint32Array();
    this.sboxes3 = new Uint32Array();
    this.sboxes4 = new Uint32Array();
    // Call the initialization method from the Blowfish class
    this.BlowfishInt(bkey);
  }

  public BlowfishInt(bfkey: Uint8Array) {
    let nI;
    this.pboxes = new Uint32Array(this.PBOX_ENTRIES);

    for (nI = 0; nI < this.PBOX_ENTRIES; nI++) {
      this.pboxes[nI] = BlowfishSharedVar.pbox_init[nI];
    }

    this.sboxes1 = new Uint32Array(this.SBOX_ENTRIES);
    this.sboxes2 = new Uint32Array(this.SBOX_ENTRIES);
    this.sboxes3 = new Uint32Array(this.SBOX_ENTRIES);
    this.sboxes4 = new Uint32Array(this.SBOX_ENTRIES);
    for (nI = 0; nI < this.SBOX_ENTRIES; nI++) {
      this.sboxes1[nI] = BlowfishSharedVar.sbox_init_1[nI];
      this.sboxes2[nI] = BlowfishSharedVar.sbox_init_2[nI];
      this.sboxes3[nI] = BlowfishSharedVar.sbox_init_3[nI];
      this.sboxes4[nI] = BlowfishSharedVar.sbox_init_4[nI];
    }

    const nLen = bfkey.length;
    if (nLen === 0) {
      return;
    }
    let nKeyPos = 0;
    let nBuild = 0;
    let nJ;
    for (nI = 0; nI < this.PBOX_ENTRIES; nI++) {
      for (nJ = 0; nJ < 4; nJ++) {
        nBuild = (nBuild << 8) | (bfkey[nKeyPos] & 0x0ff);
        if (++nKeyPos === nLen) {
          nKeyPos = 0;
        }
      }
      // xor the key over the p-boxes
      this.pboxes[nI] ^= nBuild;
    }
    const fillBoxes = (boxes: Uint32Array, lZero: bigint, entries: number) => {
      for (nI = 0; nI < entries; nI += 2) {
        lZero = this.encryptBlock(lZero);
        boxes[nI] = Number(lZero >> BigInt(32));
        boxes[nI + 1] = Number(lZero & BigInt(0x0ffffffff));
      }
      return lZero;
    };
    // encrypt all boxes with the all zero string
    // this intializes the boxes and provides tool
    // for decryption based on seed
    let lZero = BigInt(0);
    lZero = fillBoxes(this.pboxes, lZero, this.PBOX_ENTRIES);

    for (let i = 1; i <= 4; i++) {
      const box = `sboxes${i}` as 'sboxes1' | 'sboxes2' | 'sboxes3' | 'sboxes4';
      lZero = fillBoxes(this[box], lZero, this.SBOX_ENTRIES);
    }
  }

  private encryptionMath32BitInt(halve: bigint) {
    // we get the index for each box as a bigInt
    // the convert back to number to get the value
    const sboxes1Index = Number(halve >> BigInt(24));
    const sboxes2Index = Number((halve >> BigInt(16)) & BigInt(0x0ff));
    const sboxes3Index = Number((halve >> BigInt(8)) & BigInt(0x0ff));
    const sboxes4Index = Number(halve & BigInt(0x0ff));

    const bigIntBoxes1 = this.sboxes1[sboxes1Index];
    const bigIntBoxes2 = this.sboxes2[sboxes2Index];
    const bigIntBoxes3 = this.sboxes3[sboxes3Index];
    const bigIntBoxes4 = this.sboxes4[sboxes4Index];

    // each calc is borken down to ensure that the value
    // remains as a 32-bit integer
    const addBoxOneAndTwo = (bigIntBoxes1 + bigIntBoxes2) >>> 0;
    const bitwiseXORBox3 = (addBoxOneAndTwo ^ bigIntBoxes3) | 0;
    const addBox4 = (bitwiseXORBox3 + bigIntBoxes4) >>> 0;

    return BigInt(addBox4);
  }
  // encrypt a 64bit block
  protected encryptBlock(lPlainblock: bigint) {
    // split the block in two 32 bit halves
    // lPlainblock is passed as a 64 bit-int
    let nLeft: bigint = lPlainblock >> BigInt(32);
    let nRight: bigint = lPlainblock & BigInt(0x0ffffffff);

    // encrypt the block, gain more speed by unrooling the loop
    // (we avoid swaping by using nLeft and nRight alternating
    //  at odd an even loop nubers)

    for (let num = 0; num < 16; num++) {
      if (num % 2 !== 0) {
        nRight = nRight ^ BigInt(this.pboxes[num]);
        nLeft ^= this.encryptionMath32BitInt(nRight);
      } else {
        nLeft = nLeft ^ BigInt(this.pboxes[num]);
        nRight ^= this.encryptionMath32BitInt(nLeft);
      }
    }

    // swap, finalize and reassemble to return the block
    const nSwap: bigint = nRight;
    nRight = BigInt((Number(nLeft) ^ this.pboxes[16]) >>> 0);
    nLeft = BigInt((Number(nSwap) ^ this.pboxes[17]) >>> 0);

    return (
      (BigInt(nLeft) << BigInt(32)) | (BigInt(nRight) & BigInt(0xffffffff))
    );
  }
  // decrypt a 64bit block
  protected decryptBlock(lCipherblock: bigint) {
    // split the block in two 32 bit halves
    let nLeft: bigint = lCipherblock >> BigInt(32);
    let nRight: bigint = lCipherblock & BigInt(0x0ffffffff);

    for (let num = 17; num >= 2; num--) {
      if (num % 2 === 0) {
        nRight = nRight ^ BigInt(this.pboxes[num]);
        nLeft ^= this.encryptionMath32BitInt(nRight);
      } else {
        nLeft = nLeft ^ BigInt(this.pboxes[num]);
        nRight ^= this.encryptionMath32BitInt(nLeft);
      }
    }

    // swap, finalize and reassemble to return the block
    const nSwap: bigint = nRight;
    nRight = BigInt((Number(nLeft) ^ this.pboxes[1]) >>> 0);
    nLeft = BigInt((Number(nSwap) ^ this.pboxes[0]) >>> 0);

    return (
      (BigInt(nLeft) << BigInt(32)) | (BigInt(nRight) & BigInt(0xffffffff))
    );
  }

  protected byteArrayToLong(buffer: Uint8Array, nStartIndex: number) {
    // iterate over the loop to build out the bigInt from the byteArray

    let result = BigInt(0);
    for (let i = 0; i < 8; i++) {
      const shiftAmount = BigInt((7 - i) * 8);
      result =
        result |
        ((BigInt(buffer[nStartIndex + i]) & BigInt(0x0ff)) << shiftAmount);
    }
    return result;
  }
  protected longToByteArray(
    lValue: bigint,
    buffer: Uint8Array,
    nStartIndex: number,
  ): void {
    /**
     * shiftAmount accounts for the amount of bits we need to shift to the left
     */
    for (let i = 0; i < 8; i++) {
      const shiftAmount = BigInt(56 - i * 8);
      buffer[nStartIndex + i] = Number((lValue >> shiftAmount) & BigInt(0xff));
    }
  }
  /**
   * decrypts an int buffer (should be aligned to an
   * @param buffer buffer to decrypt
   */
  public decrypt(buffer: Uint8Array): void {
    const nLen = buffer.length;
    let lTemp: bigint;

    for (let nI = 0; nI < nLen; nI += 8) {
      // decrypt a temporary 64bit block
      lTemp = this.byteArrayToLong(buffer, nI);

      lTemp = this.decryptBlock(lTemp);

      this.longToByteArray(lTemp, buffer, nI);
    }
  }
  /**
   * encrypts an int buffer (should be aligned to an
   * 2 int border) to another int buffer (of the same size or bigger)
   * @param inbuffer int[] buffer with plaintext data
   * @param outbuffer int[] buffer to get the ciphertext data
   */
  public encrypt(buffer: Uint8Array): void {
    const nLen = buffer.length;
    let lTemp: bigint;

    for (let nI = 0; nI < nLen; nI += 8) {
      // decrypt a temporary 64bit block
      lTemp = this.byteArrayToLong(buffer, nI);

      lTemp = this.encryptBlock(lTemp);

      this.longToByteArray(lTemp, buffer, nI);
    }
  }
}
