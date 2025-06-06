import { TwoFishSharedValues } from '../two-fish-shared-values';
import { TwoFishError } from './twofish-error';
type TGetSubKeyWordType = {
  numKeyBlocks64: number;
  keyWord0: number;
  keyWord1: number;
  keyWord2: number;
  keyWord3: number;
  subByte0: number;
  subByte1: number;
  subByte2: number;
  subByte3: number;
  subKeyWord: Uint32Array;
};

/** @internal */
export class TwoFishUtils {
  private static P0 = TwoFishSharedValues.P0;
  private static P1 = TwoFishSharedValues.P1;
  private static MDS0 = TwoFishSharedValues.MDS0;
  private static MDS1 = TwoFishSharedValues.MDS1;
  private static MDS2 = TwoFishSharedValues.MDS2;
  private static MDS3 = TwoFishSharedValues.MDS3;

  private static substitutionFunctions = {
    b0: (x: number) => x & 0xff,
    b1: (x: number) => (x >>> 8) & 0xff,
    b2: (x: number) => (x >>> 16) & 0xff,
    b3: (x: number) => (x >>> 24) & 0xff,
  };

  static substitutionMixer(
    input: number,
    box: 'b0' | 'b1' | 'b2' | 'b3',
  ): number {
    const substitutionFunc = this.substitutionFunctions[box];
    if (!substitutionFunc) {
      throw new Error(`Invalid box name: ${box}`);
    }
    return substitutionFunc(input);
  }
  static get permutationMapsForKey() {
    return [
      [this.P0, this.P0, this.P1, this.P1],
      [this.P0, this.P1, this.P0, this.P1],
      [this.P1, this.P1, this.P0, this.P0],
      [this.P1, this.P0, this.P0, this.P1],
    ];
  }

  static getSubKeyWord({
    numKeyBlocks64,
    keyWord0,
    keyWord1,
    keyWord2,
    keyWord3,
    subByte0,
    subByte1,
    subByte2,
    subByte3,
    subKeyWord,
  }: TGetSubKeyWordType) {
    const step = numKeyBlocks64 & 3;

    // Define arrays for key and permutation sets per step index
    const keys = [keyWord0, keyWord1, keyWord2, keyWord3];
    const P_maps = this.permutationMapsForKey;
    // Apply transformations in descending order from 3 down to step (exclusive)
    for (let i = 3; i > step; i--) {
      subByte0 = P_maps[i][0][subByte0] ^ this.substitutionMixer(keys[i], 'b0');
      subByte1 = P_maps[i][1][subByte1] ^ this.substitutionMixer(keys[i], 'b1');
      subByte2 = P_maps[i][2][subByte2] ^ this.substitutionMixer(keys[i], 'b2');
      subByte3 = P_maps[i][3][subByte3] ^ this.substitutionMixer(keys[i], 'b3');
    }

    // Final step: set SUB_KEY_WORD with step 0 (k0)
    subKeyWord[0] =
      this.MDS0[this.P0[subByte0] ^ this.substitutionMixer(keyWord0, 'b0')];
    subKeyWord[1] =
      this.MDS1[this.P0[subByte1] ^ this.substitutionMixer(keyWord0, 'b1')];
    subKeyWord[2] =
      this.MDS2[this.P1[subByte2] ^ this.substitutionMixer(keyWord0, 'b2')];
    subKeyWord[3] =
      this.MDS3[this.P1[subByte3] ^ this.substitutionMixer(keyWord0, 'b3')];
  }
  static charToSigned8BitInt(char: string): number {
    // Get the UTF-16 code unit (integer) for the character
    const charCode = char.charCodeAt(0);

    // Truncate to the least significant 8 bits (0-255)
    let result = charCode & 0xff;

    // Convert from unsigned to signed 8-bit range (-128 to 127)
    // If the value is > 127, subtract 256 to get negative equivalent
    if (result > 127) {
      result -= 256;
    }

    return result;
  }

  /**
   * Tested ✅
   *
   * Truncate the key if longer than MAX_KEY_LENGTH,
   * then pad it to make length a multiple of 8 bytes.
   * @param key Uint8Array input key
   * @returns new Uint8Array truncated and padded
   */
  static truncateAndPadKey(key: Uint8Array): Uint8Array {
    const maxLength = TwoFishSharedValues.maxPasswordLength; // 32 bytes
    const minLength = 8;
    // Step 1: truncate if longer than maxLength
    const truncated = key.length > maxLength ? key.slice(0, maxLength) : key;

    // Step 2: compute padding length to nearest multiple of 8, minimum 8 bytes
    const length = truncated.length;
    const mod = length % 8;

    // Determine final padded length
    let paddedLength;
    if (length === 0) {
      paddedLength = minLength; // pad empty key to 8 bytes
    } else if (mod === 0) {
      paddedLength = length; // already multiple of 8
    } else {
      paddedLength = length + (8 - mod); // pad up to next multiple of 8
    }

    // Step 3: If padding needed, pad with zeros
    if (paddedLength !== length) {
      const paddedKey = new Uint8Array(paddedLength);
      paddedKey.set(truncated);
      return paddedKey;
    }

    // Step 4: No padding needed, return truncated
    return truncated;
  }
  /**
   * Performs a single step of the Reed-Solomon MDS matrix transformation
   * on a 32-bit input value, using the specified Galois field polynomial.
   *
   * https://people.computing.clemson.edu/~jmarty/papers/IntroToGaloisFieldsAndRSCoding.pdf
   */
  static reedSolomonTransformStep(val: number): number {
    // Extract most significant byte
    const topByte = (val >>> 24) & 0xff;

    // Multiply topByte by 2 in GF(256) with feedback polynomial
    const gfMult2 =
      ((topByte << 1) ^
        ((topByte & 0x80) !== 0 ? TwoFishSharedValues.reedSolGalField : 0)) &
      0xff;

    // Multiply topByte by 3 in GF(256) = gfMult2 XOR (topByte >>> 1) with polynomial adjustments
    const gfMult3 =
      (topByte >>> 1) ^
      ((topByte & 0x01) !== 0 ? TwoFishSharedValues.reedSolGalField >>> 1 : 0) ^
      gfMult2;

    // Rotate val left by 8 bits and XOR with the GF multiples in the right positions
    return (
      (val << 8) ^ (gfMult3 << 24) ^ (gfMult2 << 16) ^ (gfMult3 << 8) ^ topByte
    );
  }
  /**
   * Reads a 32-bit unsigned integer from a Uint8Array starting at the given offset,
   * interpreting the bytes in little-endian order (least significant byte first)
   */
  static readUint32LE(bytes: Uint8Array, offset: number): number {
    return (
      bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)
    );
  }
  static writeUint32LE(buffer: Uint8Array, offset: number, value: number) {
    buffer[offset] = value & 0xff;
    buffer[offset + 1] = (value >>> 8) & 0xff;
    buffer[offset + 2] = (value >>> 16) & 0xff;
    buffer[offset + 3] = (value >>> 24) & 0xff;
  }
  static pkcs7Pad(data: Uint8Array, blockSize = 16): Uint8Array {
    const padding = blockSize - (data.length % blockSize);
    const result = new Uint8Array(data.length + padding);
    result.set(data, 0);
    result.fill(padding, data.length);
    return result;
  }

  static pkcs7UnPad(data: Uint8Array): Uint8Array {
    const padding = data[data.length - 1];
    if (padding < 1 || padding > 16) {
      const isTooLarge = padding > 16;
      throw new TwoFishError({
        message: 'Invalid PKCS#7 padding length',
        customErrorCode: isTooLarge
          ? 'tOO_MUCH_PADDING'
          : 'INSUFFICIENT_PADDING',
      });
    }
    // Validate padding bytes
    for (let i = data.length - padding; i < data.length; i++) {
      if (data[i] !== padding) {
        throw new TwoFishError({
          message: 'Invalid PKCS#7 padding bytes',
          customErrorCode: 'INVALID_PADDING_BYTES',
        });
      }
    }
    return data.subarray(0, data.length - padding);
  }

  static rotateRight = (val: number, bits: number) =>
    ((val >>> bits) | (val << (32 - bits))) >>> 0;
  static rotateLeft = (val: number, bits: number) =>
    ((val << bits) | (val >>> (32 - bits))) >>> 0;
}
