import { TwoFishHandler } from '../src/index';

describe('TwoFish Default initialization, encryption, decryption', () => {
  let initialization: TwoFishHandler;
  test('Setting up the encryption', () => {
    initialization = new TwoFishHandler('a4MJTiDOad');

    const result = initialization.encryptData('Hello my name is Brennan');

    result && initialization.decryptData(result);
  });

});
