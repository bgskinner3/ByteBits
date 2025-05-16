import { TwoFishError } from './twofish-error';

export class TwoFishBlockUtils {
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
