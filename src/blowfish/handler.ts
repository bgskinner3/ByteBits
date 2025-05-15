import { BlowfishEncryptDecrypt } from './blowfish-encrypted-decrypted';

export class BlowfishHandler {
  //encryption key from .env if none is passed
  private ecnKey: string;
  private bfhandler: BlowfishEncryptDecrypt;
  private privateKey = process.env.BLOWFISH_ENCRYPTION || '';

  constructor(key?: string) {
    // If a key is passed, use it; otherwise, use the key from the environment variable
    this.ecnKey = key || this.privateKey;

    if (!this.ecnKey) {
      throw new Error(
        'Encryption key must be provided or set in the environment.',
      );
    }

    // Initialize the Blowfish handler with the determined key
    this.bfhandler = new BlowfishEncryptDecrypt(this.ecnKey);
  }

  public decryptData(encryption: string) {
    try {
      const decryptedData =
        encryption && this.bfhandler.decryptString(encryption);

      return decryptedData;
    } catch (error) {
      console.error('Error during decryption:', error);
      return null;
    }
  }

  public encryptData(text?: string) {
    try {
      const encryptedData = text && this.bfhandler.encryptString(text);
      return encryptedData;
    } catch (error) {
      console.error('Error during encryption:', error);
      return null;
    }
  }
}
