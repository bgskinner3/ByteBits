import { ChaCha20Error } from './error';

export class ChaCha20Utils {
  static writeUint32LE(
    buffer: Uint8Array,
    offset: number,
    value: number,
  ): void {
    buffer[offset] = value & 0xff;
    buffer[offset + 1] = (value >>> 8) & 0xff;
    buffer[offset + 2] = (value >>> 16) & 0xff;
    buffer[offset + 3] = (value >>> 24) & 0xff;
  }
  static readUint32LE(bytes: Uint8Array, offset: number): number {
    return (
      (bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24)) >>>
      0
    ); // >>> 0 ensures unsigned
  }
  static rotateLeft(value: number, bits: number): number {
    return ((value << bits) | (value >>> (32 - bits))) >>> 0;
  }
  static generateKeyFromHex(hex: string): Uint8Array {
    if (hex.length % 2 !== 0)
      throw new ChaCha20Error({
        message: 'Invalid hex string length',
      });
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) {
      arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return arr;
  }
}
