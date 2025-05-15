import { AESUtils, AESError } from './aes-utils';
import type { TByte } from './types';

/**
 *  * AESCounterCTR class
 *
 * This class manages the counter used in **AES CTR mode** (Counter mode), which is required for AES encryption and decryption when using CTR mode.
 * The counter is used as an input for AES encryption/decryption, and it is incremented after each block encryption.
 *
 * **CTR Mode** turns a block cipher into a stream cipher by using a counter value, which is incremented for each block.
 *
 */

/**
 *  @constructor  initialValue {number | TByte[] | Uint8Array}
 *  - Accepts an initial counter value:
 *    - **number**: Single number to initialize the counter.
 *    - **TByte[] or Uint8Array**: Array or `Uint8Array` representing the initial counter state (16 bytes).
 *    - Defaults to **1** if `false` or a non-valid value is provided (e.g., `0` or `null`).
 *
 * @throws
 * - `InvalidCounterValue` if the provided value or bytes are invalid.
 * @internal
 */
export class AESCounterCTR {
  public _counter: Uint8Array = new Uint8Array(16);
  private originalNonce;
  constructor(
    initialValue?: number | TByte[] | Uint8Array | null,
    nonce?: Uint8Array,
  ) {
    const resolvedNonce = nonce ?? AESUtils.generateNonce(); // Use passed nonce if cloning

    if (resolvedNonce.length !== 12) {
      throw new AESError({
        message: 'Nonce must be 12 bytes',
        customErrorCode: 'AES_NONCE_SIZE',
        name: 'AES CTR Error',
      });
    }

    this.originalNonce = resolvedNonce;
    this._counter.set(resolvedNonce, 0);
    this._counter.fill(0, 12, 16);

    if (initialValue !== 0 && !initialValue) {
      initialValue = 1;
    }

    if (typeof initialValue === 'number') {
      this.setValue(initialValue);
    } else {
      this.setBytes(initialValue);
    }
  }

  setValue(value: number | string) {
    AESUtils.validateCounterValue(value);

    for (let index = 15; index >= 12; --index) {
      this._counter[index] = value % 256;
      value = AESUtils.toSingedInteger(value / 256);
    }
  }
  setBytes(input: TByte[] | Uint8Array) {
    const bytes = AESUtils.validateAndWrapUnit8Array(input, true);
    AESUtils.validateInputLength(bytes);
    this._counter = bytes;
  }
  increment() {
    for (let i = 15; i >= 0; i--) {
      if (this._counter[i] !== 255) {
        this._counter[i]++;
        return;
      }
      this._counter[i] = 0;
    }
  }
  /**
   * FOR TESTING PURPOSES ONLY.
   * Returns the current numeric value of the counter, representing the number of encryptions/decryptions performed.
   * This is derived from the last 4 bytes of the internal 16-byte counter.
   *
   * @returns {number} The count of blocks processed (number of encryptions/decryptions).
   */
  getValue(counterValue: Uint8Array): number {
    return (
      ((counterValue[12] << 24) |
        (counterValue[13] << 16) |
        (counterValue[14] << 8) |
        counterValue[15]) >>>
      0
    ); // >>> 0 to get unsigned
  }
  public getNonce() {
    return this.originalNonce;
  }
  clone(): AESCounterCTR {
    // Pass both the counter and original nonce to ensure full fidelity
    const counterCopy = new Uint8Array(this._counter);
    const nonceCopy = new Uint8Array(this.originalNonce);
    return new AESCounterCTR(counterCopy, nonceCopy);
  }
}
