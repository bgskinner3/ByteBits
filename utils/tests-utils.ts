import { createHash, randomBytes } from 'crypto';

export class TestsUtils {
  static deriveKeyFromPassword(
    password: string,
    salt: Buffer,
    iterations: number = 1000,
    keyLength: number = 32,
  ): Buffer {
    let key = Buffer.from(password + salt.toString('hex'), 'utf8'); // Combine password with salt

    for (let i = 0; i < iterations; i++) {
      key = createHash('sha256').update(Uint8Array.from(key)).digest();
    }

    // Truncate or pad to the desired length
    return key.slice(0, keyLength);
  }
  static getRandomSaltBytes = () => randomBytes(16);
  static getConstantSaltBytes = () => Buffer.from('randomsalt123', 'utf8');
  static deriveUint8ArrayKey = (password: string): Uint8Array => {
    const salt = TestsUtils.getConstantSaltBytes();
    const key = TestsUtils.deriveKeyFromPassword(password, salt);
    return new Uint8Array(key);
  };

  static stringToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  static uint8ArrayToString(arr: Uint8Array): string {
    return new TextDecoder().decode(arr);
  }
  static generateNonce(): Uint8Array {
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce); // secure random bytes
    return nonce;
  }
}
