import { BlowfishHandler, TwoFishHandler } from '../src/index';

describe('Blowfish Default initialization, encryption, decryption', () => {
  let initialization: BlowfishHandler;
  test('Setting up the encryption', () => {
    initialization = new BlowfishHandler('a4MJr12|hTiDOad');

    expect(initialization).toBeInstanceOf(BlowfishHandler);
  });

  test('Testing encryption', () => {
    const wordToEncrypt = 'this is just a testing factor';
    const encryptedWord = initialization.encryptData(wordToEncrypt);

    expect(encryptedWord).not.toBe(wordToEncrypt);
    if (encryptedWord) {
      const decryptedWord = initialization.decryptData(encryptedWord);
      expect(decryptedWord).toBe(wordToEncrypt);
    }
  });
  test('Testing encryption with different key sizes', () => {
    const shortKeyHandler = new BlowfishHandler('shortkey');
    const longKeyHandler = new BlowfishHandler('averylongencryptionkeyvalue');

    const wordToEncrypt = 'key size test';

    const shortKeyEncrypted = shortKeyHandler.encryptData(wordToEncrypt);
    const longKeyEncrypted = longKeyHandler.encryptData(wordToEncrypt);

    expect(shortKeyEncrypted).not.toBe(longKeyEncrypted);

    const shortKeyDecrypted =
      shortKeyEncrypted && shortKeyHandler.decryptData(shortKeyEncrypted);
    const longKeyDecrypted =
      longKeyEncrypted && longKeyHandler.decryptData(longKeyEncrypted);

    expect(shortKeyDecrypted).toBe(wordToEncrypt);
    expect(longKeyDecrypted).toBe(wordToEncrypt);
  });
  test('Testing encryption of special characters and emojis', () => {
    const wordToEncrypt = 'Special chars: !@#$%^&*()';

    const encryptedWord = initialization.encryptData(wordToEncrypt);
    const decryptedWord =
      encryptedWord && initialization.decryptData(encryptedWord);

    expect(decryptedWord).toBe(wordToEncrypt);
  });
});

describe('TwoFish Default initialization, encryption, decryption', () => {
  let initialization: TwoFishHandler;
  test('Setting up the encryption', () => {
    initialization = new TwoFishHandler('a4MJTiDOad');

    const result = initialization.encryptData('sadf helllo my name is brenng ');
    result && initialization.decryptData(result);
  });
});
