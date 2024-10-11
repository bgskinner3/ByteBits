import { BlowfishHandlerV2 } from '../src/index';

describe('Blowfish Default initialization, encryption, decryption', () => {
  let initialization: BlowfishHandlerV2;
  test('Setting up the encryption', () => {
    initialization = new BlowfishHandlerV2('a4MJr12|hTiDOad');

    expect(initialization).toBeInstanceOf(BlowfishHandlerV2);
  });


  test('Testing encryption', () => {

    const wordToEncrypt = "this is just a testing factor";
    const encryptedWord = initialization.encryptData(wordToEncrypt);

    expect(encryptedWord).not.toBe(wordToEncrypt);
    if (encryptedWord) {
      const decryptedWord = initialization.decryptData(encryptedWord);
      expect(decryptedWord).toBe(wordToEncrypt);
    }


  });
  test('Testing encryption with different key sizes', () => {
    const shortKeyHandler = new BlowfishHandlerV2('shortkey');
    const longKeyHandler = new BlowfishHandlerV2('averylongencryptionkeyvalue');

    const wordToEncrypt = "key size test";

    const shortKeyEncrypted = shortKeyHandler.encryptData(wordToEncrypt);
    const longKeyEncrypted = longKeyHandler.encryptData(wordToEncrypt);

    expect(shortKeyEncrypted).not.toBe(longKeyEncrypted);

    const shortKeyDecrypted = shortKeyEncrypted && shortKeyHandler.decryptData(shortKeyEncrypted);
    const longKeyDecrypted = longKeyEncrypted && longKeyHandler.decryptData(longKeyEncrypted);

    expect(shortKeyDecrypted).toBe(wordToEncrypt);
    expect(longKeyDecrypted).toBe(wordToEncrypt);
  });
  test('Testing encryption of special characters and emojis', () => {
    const wordToEncrypt = "Special chars: !@#$%^&*()";

    const encryptedWord = initialization.encryptData(wordToEncrypt);
    const decryptedWord = encryptedWord && initialization.decryptData(encryptedWord);

    expect(decryptedWord).toBe(wordToEncrypt);
  });
});

