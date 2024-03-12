/* eslint-disable no-undef */
import { BlowfishHandler, BlowfishEncryptDecrypt } from '../src/index';

describe('Blowfish Default initialization, encryption, decryption', () => {
  let initialization: BlowfishEncryptDecrypt;
  test('Setting up the encryption', () => {
    initialization = BlowfishHandler.initializeBlowfish();

    expect(initialization).toBeInstanceOf(BlowfishEncryptDecrypt);
  });

  const word1 = 'Blowfish Encryption';
  test('Testing encryption and decryption', () => {
    let wordToEncrypt: string | null = word1;
    wordToEncrypt = BlowfishHandler.encryptData(wordToEncrypt, initialization);

    expect(wordToEncrypt).not.toBe(word1);
    // Encrypted value should match the folloowing regular expression
    expect(wordToEncrypt).toMatch(/^[0-9A-Z]+$/);

    wordToEncrypt =
      wordToEncrypt &&
      BlowfishHandler.decryptData(wordToEncrypt, initialization);

    expect(wordToEncrypt).toBe(word1);
  });
});

describe('Blowfish custom seed phrase initialization, encryption, decryption', () => {
  let initialization: BlowfishEncryptDecrypt;
  const customSeedPhrase = 'This is my custom phrase';
  test('Setting up the encryption', () => {
    initialization = BlowfishHandler.initializeBlowfish(customSeedPhrase);

    expect(initialization).toBeInstanceOf(BlowfishEncryptDecrypt);
  });

  const word1 = 'Blowfish Encryption';
  test('Testing encryption and decryption with custom phrase', () => {
    let wordToEncrypt: string | null = word1;
    wordToEncrypt = BlowfishHandler.encryptData(wordToEncrypt, initialization);

    expect(wordToEncrypt).not.toBe(word1);
    // Encrypted value should match the folloowing regular expression
    expect(wordToEncrypt).toMatch(/^[0-9A-Z]+$/);

    wordToEncrypt =
      wordToEncrypt &&
      BlowfishHandler.decryptData(wordToEncrypt, initialization);

    expect(wordToEncrypt).toBe(word1);
  });
});
