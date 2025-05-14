import { AESSharedResources } from './aes-shared-resources';
import { AESValidation } from './aes-validation';
import { TByte } from './types';

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
    AESValidation.validateCounterValue(value);
    for (let index = 15; index >= 0; --index) {
      this._counter[index] = value % 256;
      value = AESSharedResources.toSingedInteger(value / 256);
    }
  }
  setBytes(input: TByte[] | Uint8Array) {
    const bytes = AESSharedResources.validateAndWrapUnit8Array(input, true);
    AESValidation.validateInputLength(bytes);
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
