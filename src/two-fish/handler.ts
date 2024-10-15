import { TwoFishEncryptDecrypt } from './two-fish-encrypt-decrypt';

export class TwoFishHandler {
  private ecnKey: string;
  private twoFishHandler: TwoFishEncryptDecrypt;
  private privateKey = process.env.BLOWFISH_ENCRYPTION || '';

  constructor(key?: string) {
    this.ecnKey = key || this.privateKey;

    if (!this.ecnKey) {
      throw new Error(
        'Encryption key must be provided or set in the environment.',
      );
    }

    this.twoFishHandler = new TwoFishEncryptDecrypt(this.ecnKey);
  }
  public encryptData(text?: string) {
    try {
      const encryptedData = text && this.twoFishHandler.encryptTwoFishString(text);
      return encryptedData;
    } catch (error) {
      console.error('Error during encryption:', error);
      return null;
    }
  }

  public decryptData(encryption: string) {
    try {
      const encryptedData =
        encryption && this.twoFishHandler.decryptTwoFishString(encryption);
      return encryptedData;
    } catch (error) {
      console.error('Error during decryption:', error);
      return null;
    }
  }
}
