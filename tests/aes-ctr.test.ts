// import AESHandler
import {
  AESHandler,
  AESCore,
  AESEncryptDecrypt,
  AESCounterCTR,
} from '../src/index';
import { TAESBuffer } from '../src/index';
import { TestsUtils } from '../utils';

const password = 'yourpassword123';
const salt = TestsUtils.getConstantSaltBytes();
const key = TestsUtils.deriveKeyFromPassword(password, salt);
const keyUint8Array: Uint8Array = new Uint8Array(key);

describe('AESHandler', () => {
  let aesCore: AESCore;
  let counter: AESCounterCTR;
  let handler: AESHandler;

  beforeEach(() => {
    aesCore = new AESCore(keyUint8Array);
    counter = new AESCounterCTR(1);
    handler = new AESHandler(aesCore, counter);
  });

  it('should initialize AESHandler correctly', () => {
    // Ensure the handler has the expected core and counter state
    expect(handler).toBeDefined();
    expect(handler['_aes']).toEqual(aesCore); // Assuming the internal AESCore is accessible
    expect(handler['_counter']).toEqual(counter); // Check the counter as well
    expect(handler['_remainingCounterIndex']).toBe(16); // Initial index should be 16
    expect(handler['_remainingCounter']).toBeNull(); // Remaining counter should be null initially
  });
});
