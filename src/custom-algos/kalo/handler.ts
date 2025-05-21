import { KaloCore } from './kalo-core';
import { KaloAESHandler } from '../../aes-ctr';
import { KaloError, KaloParsingUtils } from './utils';
import { KaloEncryptDecrypt } from './kalo-encrypt-decrypt';
type TKaloState = {
  core: KaloCore;
  aesWrapper: KaloAESHandler;
  saltRemainder: Uint8Array;
  nonceRemainder: Uint8Array;
  fullNonce: Uint8Array;
};

export class KaloSkribiHandler {
  private state: TKaloState;
  private mode: 'encrypt' | 'decrypt';
  private encryptDecrypt: KaloEncryptDecrypt;
  private constructor(state: TKaloState, mode: 'encrypt' | 'decrypt') {
    this.encryptDecrypt = new KaloEncryptDecrypt();
    this.state = state;
    this.mode = mode;
  }
  static createForEncryption(password: string) {
    const core = KaloCore.forEncryption(password);
    const { key, fullNonce, saltRemainder, nonceRemainder } =
      core.getKeyMaterial();
    const aesWrapper = new KaloAESHandler(key, fullNonce);

    return new KaloSkribiHandler(
      { core, aesWrapper, saltRemainder, nonceRemainder, fullNonce },
      'encrypt',
    );
  }
  static createForDecryption(password: string, encryptedText: string) {
    const { partialNonce, partialSalt } =
      KaloParsingUtils.getNonceAndSaltFromText(encryptedText);
    if (!partialNonce || !partialSalt) {
      throw KaloError.InvalidHexParts('Missing nonce or salt for decryption');
    }

    const core = KaloCore.forDecryption(password, {
      nonce: partialNonce,
      salt: partialSalt,
    });
    const { key, fullNonce, saltRemainder, nonceRemainder } =
      core.getKeyMaterial();
    const aesWrapper = new KaloAESHandler(key, fullNonce);

    return new KaloSkribiHandler(
      { core, aesWrapper, saltRemainder, nonceRemainder, fullNonce },
      'decrypt',
    );
  }
  public encrypt({
    encryptText,
    displayText,
  }: {
    encryptText: string;
    displayText: string;
  }) {
    if (this.mode !== 'encrypt') {
      throw KaloError.InvalidMode();
    }
    return this.encryptDecrypt.kaloEncryptString({
      encryptText: encryptText,
      displayText: displayText,
      state: {
        aesHandler: this.state.aesWrapper,
        remainders: {
          nonceRemainder: this.state.nonceRemainder,
          saltRemainder: this.state.saltRemainder,
        },
      },
    });
  }
  public decrypt({ encryptedText }: { encryptedText: string }) {
    if (this.mode !== 'decrypt') {
      throw KaloError.InvalidMode();
    }
    return this.encryptDecrypt.kaloDecryptString({
      encryptedText,
      state: {
        aesHandler: this.state.aesWrapper,
        nonce: this.state.fullNonce,
      },
    });
  }
}
