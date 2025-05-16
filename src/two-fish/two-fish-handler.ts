import { TwoFishCore } from './two-fish-core';
import { TwoFishEncryptDecrypt } from './two-fish-encrypt-decrypt';
import { TwoFishError } from './utils';

export class TwoFishHandler20 {
    private readonly blockProcessor: TwoFishEncryptDecrypt;
    constructor(password: string) {
        if (!password || typeof password !== 'string') {
            throw new Error('A valid password is required to initialize TwoFish.');
        }

        const core = new TwoFishCore(password);
        this.blockProcessor = new TwoFishEncryptDecrypt(core);
    }

    public encryptTwoFishBuffer(buffer: Buffer) {
        const buf = new Uint8Array(buffer);
        const encryptedData = this.blockProcessor?.encrypt(buf);

        if (encryptedData) return Buffer.from(encryptedData);
    }
    public decryptTwoFishBuffer(buffer?: Buffer) {
        if (!buffer) {
            throw new TwoFishError({
                message: 'No buffer provided',
                customErrorCode: 'INVALID_BUFFER',
                name: 'TWOFISH Decryption Error',
            });
        }
        const buf = new Uint8Array(buffer);
 
        const decryptedData = this.blockProcessor?.decrypt(buf);

        if (decryptedData) {
            return Buffer.from(decryptedData);
        }
    }
}
