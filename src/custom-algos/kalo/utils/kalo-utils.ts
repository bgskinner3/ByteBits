import { randomBytes } from 'crypto';
import type { TFourBitKey, TAllChars, TLookUpObjectKeys } from '../types';
import { kaloMapper } from '../kalo-mapper';
import { FOUR_BIT_KEYS } from '../constants';
import { KaloError } from './error';
export class KaloEncodingUtils {
  static hexToBytes(hex: string): Uint8Array {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
  }
  static stringToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }
  static uint8ArrayToString(arr: Uint8Array): string {
    return new TextDecoder().decode(arr);
  }
  /**
   * Converts a single character to a Unicode tag string like "U0041" for 'A'
   * *This is used for fast lookup in our mapper
   */
  static toUnicodeTag(char: string): string {
    if (!char || char.length !== 1) {
      throw new Error('Input must be a single character');
    }

    const codePoint = char.codePointAt(0)!;
    return 'U' + codePoint.toString(16).toUpperCase().padStart(4, '0');
  }
  /**
   * Converts a Uint8Array into a bit string representation
   * @example
   * ```ts
   * const bytes = new Uint8Array([5, 10]);
   * 5 in binary: 00000101
   * 10 in binary: 00001010
   * const bits = KaloEncodingUtils.uint8ArrayToBits(bytes);
   * console.log(bits); // "0000010100001010"
   * ```
   */
  static uint8ArrayToBits(arr: Uint8Array): string {
    return Array.from(arr)
      .map((byte) => byte.toString(2).padStart(8, '0')) // convert each byte to 8-bit binary string
      .join('');
  }
  /**
   * Filters and converts a string into an array of Unicode tags
   * @example
   * Suppose 'A' maps to 'U0041' and 'B' maps to 'U0042' in kaloMapper
   * KaloEncodingUtils.getUniCodeChars('ABZ');
   * Returns ['U0041', 'U0042'] if 'Z' (U005A) is not in kaloMapper
   */
  static getUniCodeChars(text: string): TLookUpObjectKeys[] {
    return text
      .split('')
      .map(this.toUnicodeTag)
      .filter((tag): tag is TLookUpObjectKeys => tag in kaloMapper.encryptMap);
  }

  /**
   * Converts a UTF-8 string to its binary bit string representation
   * @example
   *  'A' -> 01000001
   * KaloEncodingUtils.stringToBinary('A'); // "01000001"
   */
  static stringToBinary(input: string): string {
    return input
      .split('')
      .map((char) => char.charCodeAt(0).toString(2).padStart(8, '0'))
      .join('');
  }
  /**
   * Converts a binary string (e.g., "01000001") into a Uint8Array of bytes.
   *
   * @example
   * Convert binary string for "A" and "B"
   * const bytes = KaloEncodingUtils.binaryToUint8Array('0100000101000010');
   * bytes => Uint8Array [65, 66]
   */
  static binaryToUint8Array(bitString: string): Uint8Array {
    const byteCount = Math.floor(bitString.length / 8);
    const result = new Uint8Array(byteCount);

    for (let i = 0; i < byteCount; i++) {
      const byteBits = bitString.slice(i * 8, i * 8 + 8);
      result[i] = parseInt(byteBits, 2);
    }

    return result;
  }
}

export class KaloParsingUtils {
  static sanitizeText = (text: string) =>
    text.toLowerCase().replace(/[^A-Za-z]/g, '');
  static sanitizeSpaces = (text: string) => text.replace(/\s+/g, '');
  static getNonceAndSaltFromText(encryptedText: string): {
    partialNonce: Uint8Array;
    partialSalt: Uint8Array;
  } {
    const sanitizedText = this.sanitizeSpaces(encryptedText);

    const bits = KaloStructureUtils.mapEncryptedTextToBits(sanitizedText);

    const allChunks = KaloStructureUtils.splitIntoChunks(bits);

    const combinedKeyChunks = allChunks.slice(-24);
    const combinedKeyBits = combinedKeyChunks.join('');
    const combinedBytes = KaloEncodingUtils.binaryToUint8Array(combinedKeyBits);
    const partialNonce = combinedBytes.slice(0, 6);
    const partialSalt = combinedBytes.slice(6, 12);

    const isValid = KaloValidationUtils.validateSaltAndNonceUint8Arrays(
      partialNonce,
      partialSalt,
    );

    if (!isValid) {
      throw new KaloError({
        message: 'chars and bits arrays must have equal length',
      });
    }

    return { partialNonce, partialSalt };
  }
}

export class KaloStructureUtils {
  static concatUint8Arrays(prefix: Uint8Array, suffix: Uint8Array): Uint8Array {
    return new Uint8Array([...prefix, ...suffix]);
  }
  static generateSaltAndNonce = () => {
    const bytes = randomBytes(12); // 12 random bytes
    const salt = bytes.subarray(0, 6); // First 6 bytes for salt
    const nonce = bytes.subarray(6, 12); // Last 6 bytes for nonce
    return { salt: new Uint8Array(salt), nonce: new Uint8Array(nonce) };
  };
  static splitIntoChunks = (bitString: string): TFourBitKey[] => {
    const chunks: TFourBitKey[] = [];
    for (let i = 0; i < bitString.length; i += 4) {
      chunks.push(bitString.slice(i, i + 4) as TFourBitKey);
    }
    return chunks;
  };
  /**
   * Returns an array of padding chunks (4-bit keys), currently fixed to the first FOUR_BIT_KEYS entry.

   */
  static randomPaddingChunks = (paddingChunks: number) =>
    Array.from({ length: paddingChunks }, () => {
      const randIndex = Math.floor(Math.random() * FOUR_BIT_KEYS.length);
      return FOUR_BIT_KEYS[randIndex];
    });

  /**
   * Zips together an array of chars and an array of bits into an object
   * with keys 'char0', 'char1', ..., mapping to objects { char, bit }.
   * Throws if arrays differ in length.
   */
  static zipToCharBitPairs<K extends string>({
    chars,
    bits,
  }: {
    chars: TLookUpObjectKeys[];
    bits: TFourBitKey[];
  }): Record<K, { char: TLookUpObjectKeys; bit: TFourBitKey }> {
    if (chars.length !== bits.length) {
      throw new Error('chars and bits arrays must have equal length');
    }

    const result = {} as Record<
      K,
      { char: TLookUpObjectKeys; bit: TFourBitKey }
    >;

    for (let i = 0; i < chars.length; i++) {
      const key = `char${i}` as K;
      result[key] = { char: chars[i], bit: bits[i] };
    }

    return result;
  }
  /**
   * TODO: ADD EXAMPLE
   */
  static mapEncryptedTextToBits(sanitizedText: string): string {
    return Array.from(sanitizedText)
      .filter(
        (char) =>
          char in kaloMapper.decryptMap &&
          !(char in kaloMapper.paddedDecryptMap),
      )
      .map((char) => kaloMapper.decryptMap[char as TAllChars])
      .join('');
  }
}

export class KaloValidationUtils {
  static validateSaltAndNonceUint8Arrays(
    a: Uint8Array,
    b: Uint8Array,
  ): boolean {
    if (a.length !== 6 || b.length !== 6) return false;

    // Return true if at least one byte differs
    return a.some((value, index) => value !== b[index]);
  }
  public static isValidHex(hex: string, expectedBytes?: number): boolean {
    if (!hex) return false;
    hex = hex.trim(); // Trim whitespace just in case
    if (expectedBytes !== undefined && hex.length !== expectedBytes * 2) {
      console.log(`Expected length ${expectedBytes * 2} but got ${hex.length}`);
      return false;
    }
    const valid = /^[0-9a-fA-F]+$/.test(hex);
    if (!valid) console.log(`Invalid hex characters found in: ${hex}`);
    return valid;
    return true;
  }
  public static validateSaltNonceLengths(
    salt: Uint8Array,
    nonce: Uint8Array,
    context: string,
  ) {
    if (salt.length !== 6 || nonce.length !== 6) {
      throw KaloError.InvalidHexParts(
        `${context} must be 6 bytes each. Got ${salt.length} and ${nonce.length}`,
      );
    }
  }
}
export class ObjectUtils {
  /**
   * Returns the keys of an object while protecting key inference.
   *
   * @template Obj - The object type
   * @param {Obj} obj - The object to extract keys from
   */
  static keys<Obj extends object>(obj: Obj) {
    return Object.keys(obj) as (keyof Obj)[];
  }
  /**
   * Returns the key-value pairs of an object while protecting type inference.
   *
   * @template T - The object type
   * @param {T} obj - The object to extract key-value pairs from
   */
  static entries<T extends Record<string, unknown>>(
    obj: T,
  ): [keyof T, T[keyof T]][] {
    return obj ? (Object.entries(obj) as [keyof T, T[keyof T]][]) : [];
  }
}
