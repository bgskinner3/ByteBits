import { AESUtils } from './aes-utils';
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
 */
export class AESCounterCTR {
  public _counter: Uint8Array = new Uint8Array(16);

  constructor(initialValue: number | TByte[] | Uint8Array) {
    // We allow 0, but anything false-ish uses the default 1
    if (initialValue !== 0 && !initialValue) {
      initialValue = 1;
    }
    if (typeof initialValue === 'number') {
      this._counter = new Uint8Array(16);
      this.setValue(initialValue);
    } else {
      this.setBytes(initialValue);
    }
  }

  setValue(value: number | string) {
    AESUtils.validateCounterValue(value);
    for (let index = 15; index >= 0; --index) {
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
    // for (let i = 15; i >= 0; i--) {
    //     if (this._counter[i] === 255) {
    //         this._counter[i] = 0
    //     } else {
    //         this._counter[i]++
    //         break
    //     }
    // }
  }
}
