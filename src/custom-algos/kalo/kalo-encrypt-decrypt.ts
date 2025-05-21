import {
  KaloStructureUtils,
  KaloEncodingUtils,
  KaloError,
  KaloParsingUtils,
  ObjectUtils,
} from './utils';
import type {
  TFourBitKey,
  TKaloEncrypt,
  TKaloDecrypt,
  TAllChars,
} from './types';
import { kaloMapper } from './kalo-mapper';

export class KaloEncryptDecrypt {
  /**
   * Converts nonce and salt Uint8Arrays + encrypted text Uint8Array
   * into their respective bit string representations.
   */
  private convertEncryptedTextAndKeys({
    remainders,
    encodedEncryptText,
  }: {
    remainders: TKaloEncrypt['state']['remainders'];
    encodedEncryptText: Uint8Array;
  }) {
    const { nonceRemainder, saltRemainder } = remainders;
    /**
     * nonce will be the first 6 bits while salt will be the last
     */
    const combined = KaloStructureUtils.concatUint8Arrays(
      nonceRemainder,
      saltRemainder,
    );

    return {
      combinedKeysBinary: KaloEncodingUtils.uint8ArrayToBits(combined),
      encryptionTextBinary:
        KaloEncodingUtils.uint8ArrayToBits(encodedEncryptText),
    };
  }
  /**
   * Splits combined keys and encrypted text bit strings into 4-bit chunks,
   * pads with random chunks to fill the displayText length,
   * and returns a combined chunks array.
   *
   * Throws if displayText length too short.
   */
  private getChunksArray({
    encryptionTextBinary,
    combinedKeysBinary,
    sanitizedText,
  }: {
    encryptionTextBinary: string;
    combinedKeysBinary: string;
    sanitizedText: string;
  }): Record<'baseBytes' | 'paddingBytes', TFourBitKey[]> {
    const totalFixedLength = sanitizedText.length;

    const keyChunksCount = Math.ceil(combinedKeysBinary.length / 4);
    const encChunksCount = Math.ceil(encryptionTextBinary.length / 4);
    const paddingChunksCount =
      totalFixedLength - keyChunksCount - encChunksCount;

    if (paddingChunksCount < 0) {
      throw new KaloError({
        message: 'Display text not long enough for encrypted payload.',
      });
    }

    const randomPadding =
      KaloStructureUtils.randomPaddingChunks(paddingChunksCount);
    const encryptionChunks =
      KaloStructureUtils.splitIntoChunks(encryptionTextBinary);
    const combinedChunks =
      KaloStructureUtils.splitIntoChunks(combinedKeysBinary);

    return {
      baseBytes: [...encryptionChunks, ...combinedChunks],
      paddingBytes: randomPadding,
    };
  }

  /**
   * Build the final encrypted string by replacing characters in displayText
   * that have a matching unicode tag in encryptedLib.
   *
   * Unmatched characters are kept as is.
   *
   */
  private buildEncryptedString({
    encryptedLib,
    displayText,
    baseLength,
  }: {
    encryptedLib: ReturnType<typeof KaloStructureUtils.zipToCharBitPairs>;
    displayText: string;
    baseLength: number;
  }): string {
    const flatLib = ObjectUtils.keys(encryptedLib);
    let result = '';
    let libIndex = 0;
    for (const char of displayText) {
      const unicodeTag = KaloEncodingUtils.toUnicodeTag(char);
      const flatLibKey = flatLib[libIndex];
      const libEntry = encryptedLib[flatLibKey];
      if (libEntry.char === unicodeTag) {
        const currentMap =
          libIndex < baseLength
            ? kaloMapper.encryptMap
            : kaloMapper.paddedEncryptMap;
        result += currentMap[libEntry.char][libEntry.bit];
        libIndex++;
      } else {
        result += char;
      }
    }
    return result;
  }

  public kaloEncryptString({
    encryptText,
    displayText,
    state,
  }: TKaloEncrypt): string {
    const { remainders, aesHandler } = state;
    const sanitizedText = KaloParsingUtils.sanitizeText(displayText);
    // Convert encryptText to Uint8Array and encrypt using AES CTR
    const encryptionTextArray =
      KaloEncodingUtils.stringToUint8Array(encryptText);
    const encodedEncryptText = aesHandler.encrypt(encryptionTextArray);

    // Get bit string versions of nonce+salt and encrypted data
    const { combinedKeysBinary, encryptionTextBinary } =
      this.convertEncryptedTextAndKeys({ encodedEncryptText, remainders });

    /**
     * 4 bit chuncks for encoded text and padding before mapping
     *
     */
    const { baseBytes, paddingBytes } = this.getChunksArray({
      combinedKeysBinary,
      encryptionTextBinary,
      sanitizedText,
    });

    // Map cleaned display text to unicode tags from the mapper lib
    const displayTextKeys = KaloEncodingUtils.getUniCodeChars(sanitizedText);

    // Pair unicode chars with their corresponding 4-bit chunks
    const encryptedLib = KaloStructureUtils.zipToCharBitPairs({
      chars: displayTextKeys,
      bits: [...baseBytes, ...paddingBytes],
    });
    return this.buildEncryptedString({
      encryptedLib,
      displayText,
      baseLength: baseBytes.length,
    });
  }

  private stripAndCleanDecryptionText(encryptedText: string): Uint8Array {
    const cleanedBits = Array.from(encryptedText)
      .filter(
        (char) =>
          char in kaloMapper.decryptMap &&
          !(char in kaloMapper.paddedDecryptMap),
      )
      .map((char) => kaloMapper.decryptMap[char as TAllChars])
      .join('');

    const allChunks = KaloStructureUtils.splitIntoChunks(cleanedBits);

    const encryptedTextSanitized = allChunks.slice(0, -24);

    const combinedSanitizedBits = encryptedTextSanitized.join('');
    return KaloEncodingUtils.binaryToUint8Array(combinedSanitizedBits);
  }

  public kaloDecryptString({ encryptedText, state }: TKaloDecrypt) {
    const { aesHandler, nonce } = state;
    const sanitizedText = KaloParsingUtils.sanitizeSpaces(encryptedText);
    const parsedEncryption = this.stripAndCleanDecryptionText(sanitizedText);

    const encodedEncryptText = aesHandler.decrypt(parsedEncryption, nonce);

    const result = KaloEncodingUtils.uint8ArrayToString(encodedEncryptText);

    return result;
  }
}
