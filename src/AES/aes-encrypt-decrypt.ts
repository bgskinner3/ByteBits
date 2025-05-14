import { AESSharedResources, AESError } from './aes-shared-resources';
import { AESValidation } from './aes-validation';

export class AESEncryptDecrypt {
    private static roundState: number[] = new Array(4).fill(0)
    public static encryptAES(plaintext: Uint8Array, roundKeys: number[][] = []) {
        AESValidation.isValidTextLength(plaintext);
        const rounds = roundKeys.length - 1
        let tempKey = AESSharedResources.convertToInt32(plaintext)

        for (let i = 0; i < 4; i++) {
            tempKey[i] ^= roundKeys[0][i]
        }
        for (let r = 1; r < rounds; r++) {
            for (let i = 0; i < 4; i++) {
                this.roundState[i] =
                    AESSharedResources.aesEncryptTransformation1[(tempKey[i] >> 24) & 0xff] ^
                    AESSharedResources.aesEncryptTransformation2[(tempKey[(i + 1) % 4] >> 16) & 0xff] ^
                    AESSharedResources.aesEncryptTransformation3[(tempKey[(i + 2) % 4] >> 8) & 0xff] ^
                    AESSharedResources.aesEncryptTransformation4[tempKey[(i + 3) % 4] & 0xff] ^
                    roundKeys[r][i]
            }
            tempKey = this.roundState.slice()
        }
        const result = new Uint8Array(16)
        for (let i = 0, tt = 0; i < 4; i++) {
            tt = roundKeys[rounds][i]
            result[4 * i] = (AESSharedResources.aesSBox[(tempKey[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff
            result[4 * i + 1] = (AESSharedResources.aesSBox[(tempKey[(i + 1) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff
            result[4 * i + 2] = (AESSharedResources.aesSBox[(tempKey[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff
            result[4 * i + 3] = (AESSharedResources.aesSBox[tempKey[(i + 3) % 4] & 0xff] ^ tt) & 0xff
        }
        return result
    }

    public static decryptAES = (cipherText: Uint8Array, roundKeys: number[][] = []) => {
        AESValidation.isValidTextLength(cipherText);

        const rounds = roundKeys.length - 1


        // convert plaintext to (ints ^ key)
        let tempKey = AESSharedResources.convertToInt32(cipherText)

        for (let i = 0; i < 4; i++) {
            tempKey[i] ^= roundKeys[0][i]
        }
        // apply round transforms
        for (let r = 1; r < rounds; r++) {
            for (let i = 0; i < 4; i++) {
                this.roundState[i] =
                    AESSharedResources.aesDecryptTransformation5[(tempKey[i] >> 24) & 0xff] ^
                    AESSharedResources.aesDecryptTransformation6[(tempKey[(i + 3) % 4] >> 16) & 0xff] ^
                    AESSharedResources.aesDecryptTransformation7[(tempKey[(i + 2) % 4] >> 8) & 0xff] ^
                    AESSharedResources.aesDecryptTransformation8[tempKey[(i + 1) % 4] & 0xff] ^
                    roundKeys[r][i]
            }
            tempKey = this.roundState.slice()
        }

        // the last round is special
        const result = new Uint8Array(16)

        for (let i = 0, tt = 0; i < 4; i++) {
            tt = roundKeys[rounds][i]
            result[4 * i] = (AESSharedResources.aesEncryptTransformation4[(tempKey[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff
            result[4 * i + 1] = (AESSharedResources.aesInverseSBox[(tempKey[(i + 3) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff
            result[4 * i + 2] = (AESSharedResources.aesInverseSBox[(tempKey[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff
            result[4 * i + 3] = (AESSharedResources.aesInverseSBox[tempKey[(i + 1) % 4] & 0xff] ^ tt) & 0xff
        }

        return result
    }

}
