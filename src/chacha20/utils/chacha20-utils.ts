


export class ChaCha20ParsingUtils {
    static readUint32LE(bytes: Uint8Array, offset: number): number {
        return (
            bytes[offset] |
            (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24)
        ) >>> 0; // >>> 0 ensures unsigned
    }

}


export class ChaCha20EncodingUtils {
    static writeUint32LE(buffer: Uint8Array, offset: number, value: number): void {
        buffer[offset] = value & 0xff;
        buffer[offset + 1] = (value >>> 8) & 0xff;
        buffer[offset + 2] = (value >>> 16) & 0xff;
        buffer[offset + 3] = (value >>> 24) & 0xff;
    }

    static rotateLeft(value: number, bits: number): number {
        return ((value << bits) | (value >>> (32 - bits))) >>> 0;
      }
}