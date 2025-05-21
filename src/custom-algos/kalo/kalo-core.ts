import { KaloEncodingUtils, KaloStructureUtils, KaloError } from './utils';
import { pbkdf2Sync } from 'crypto';
import { TKaloCore } from './types';

export class KaloCore {
  // private readonly saltHex = process.env.KALO_SALT
  // private readonly nonceHex = process.env.KALO_NONCE
  private readonly saltHex = process.env.KALO_SALT;
  private readonly nonceHex = process.env.KALO_NONCE;
  private readonly nonceRemainder: Uint8Array;
  private readonly saltRemainder: Uint8Array;
  private readonly saltedKey;
  private readonly fullNonce;

  constructor({ remainderPair, password }: TKaloCore) {
    if (!this.saltHex || !this.nonceHex) {
      throw KaloError.MissingEnvVars();
    }

    if (
      !KaloCore.isValidHex(this.saltHex, 6) ||
      !KaloCore.isValidHex(this.nonceHex, 6)
    ) {
      throw KaloError.InvalidHexParts('Salt or Nonce is not valid hex.');
    }
    const saltPartOne = KaloEncodingUtils.hexToBytes(this.saltHex);
    const noncePartOne = KaloEncodingUtils.hexToBytes(this.nonceHex);
    this.validateSaltNonceLengths(saltPartOne, noncePartOne, 'Env salt/nonce');

    const { salt, nonce } = this.getSaltNoncePair(remainderPair);

    this.validateSaltNonceLengths(salt, nonce, 'Remainder salt/nonce');

    this.nonceRemainder = nonce;
    this.saltRemainder = salt;
    const fullSalt = KaloStructureUtils.concatUint8Arrays(saltPartOne, salt);
    const fullNonce = KaloStructureUtils.concatUint8Arrays(noncePartOne, nonce);

    this.fullNonce = fullNonce;

    if (!password || typeof password !== 'string') {
      throw KaloError.InvalidPassword();
    }

    this.saltedKey = this.deriveKey(password, fullSalt);
  }
  static isValidHex(hex: string, expectedBytes?: number): boolean {
    if (!hex) return false;
    hex = hex.trim(); // Trim whitespace just in case
    if (expectedBytes !== undefined && hex.length !== expectedBytes * 2)
      return false;

    return /^[0-9a-fA-F]+$/.test(hex);
  }
  validateSaltNonceLengths(
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
  protected deriveKey(
    password: string,
    salt: Uint8Array,
    iterations = 1000,
    keyLength = 32,
  ): Uint8Array {
    if (salt.length !== 12) {
      throw KaloError.InvalidHexParts();
    }

    const keyBuffer = pbkdf2Sync(
      password,
      Uint8Array.from(salt),
      iterations,
      keyLength,
      'sha256',
    );

    return new Uint8Array(keyBuffer);
  }
  protected getSaltNoncePair(remainderPair?: {
    salt: Uint8Array;
    nonce: Uint8Array;
  }): { salt: Uint8Array; nonce: Uint8Array } {
    if (remainderPair) {
      const { salt, nonce } = remainderPair;
      if (salt.length !== 6 || nonce.length !== 6) {
        throw KaloError.InvalidHexParts(
          'Full salt must be 12 bytes after concatenation',
        );
      }
      return { salt, nonce };
    }
    const { salt, nonce } = KaloStructureUtils.generateSaltAndNonce();

    return { salt, nonce };
  }

  static forEncryption(password?: string) {
    return new KaloCore({ password });
  }

  static forDecryption(
    password: string,
    remainderPair: { salt: Uint8Array; nonce: Uint8Array },
  ) {
    return new KaloCore({ password, remainderPair });
  }
  public getKeyMaterial() {
    return {
      key: this.saltedKey,
      fullNonce: this.fullNonce,
      nonceRemainder: this.nonceRemainder,
      saltRemainder: this.saltRemainder,
    };
  }
}

/**
 * FOR TESTING PURPOSES
 */
/* istanbul ignore next */
export class TestableKaloCore extends KaloCore {
  constructor(args: TKaloCore) {
    super(args); // call protected constructor from subclass
  }

  public callDeriveKey(password: string, salt: Uint8Array) {
    return this.deriveKey(password, salt);
  }
  public isValidHex(hex: string, expectedBytes?: number): boolean {
    return this.isValidHex(hex, expectedBytes);
  }
  public callGetSaltNoncePair(remainderPair?: {
    salt: Uint8Array;
    nonce: Uint8Array;
  }) {
    return this.getSaltNoncePair(remainderPair);
  }
}
