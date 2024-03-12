import { BlowfishEncryptDecrypt } from './blowfish-encrypt-decrypt';

export class BlowfishHandler {
  private static bfhandler: BlowfishEncryptDecrypt | null = null;
  //encryption key
  private static ecnKey = process.env.BLOWFISH_ENCRYPTION || '';

  public static initializeBlowfish(key: string) {

    const cypherKey = key ? key : this.ecnKey
    this.bfhandler = new BlowfishEncryptDecrypt(cypherKey);

    return this.bfhandler;
  }
  public static decryptData(encryption: string, bfHandler: BlowfishEncryptDecrypt) {
    try {
      const decryptedData =
        encryption && bfHandler.decryptString(encryption);
      return decryptedData;
    } catch (error) {
      console.error('Error during decryption:', error);
      return null;
    }
  }

  public static encryptData(text: string, bfHandler: BlowfishEncryptDecrypt) {

    try {
      const encryptedData = text && bfHandler.encryptString(text);
      return encryptedData;
    } catch (error) {
      console.error('Error during decryption:', error);
      return null;
    }
  }
}
