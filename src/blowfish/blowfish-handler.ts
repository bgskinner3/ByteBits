import { BlowfishEncryptDecrypt } from './blowfish-encrypt-decrypt';

export class BlowfishHandler {
  private static bfhandler: BlowfishEncryptDecrypt | null = null;
  //encryption key
  private static ecnKey = process.env.BLOWFISH_ENCRYPTION || '';

  public static initializeBlowfish() {
    this.bfhandler = new BlowfishEncryptDecrypt(this.ecnKey);

    return this.bfhandler;
  }
  public static decryptData(encryption: string) {
    if (!this.bfhandler) {
      this.bfhandler = new BlowfishEncryptDecrypt(this.ecnKey);
    }

    try {
      const decryptedData =
        encryption && this.bfhandler.decryptString(encryption);
      return decryptedData;
    } catch (error) {
      console.error('Error during decryption:', error);
      return null;
    }
  }

  public static encryptData(text: string) {
    if (!this.bfhandler) {
      this.bfhandler = new BlowfishEncryptDecrypt(this.ecnKey);
    }
    try {
      const encryptedData = text && this.bfhandler.encryptString(text);
      return encryptedData;
    } catch (error) {
      console.error('Error during decryption:', error);
      return null;
    }
  }
}
