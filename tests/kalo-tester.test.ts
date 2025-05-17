import { MappingHandler } from "../src";
import {
    AESHandler,
    AESCore,
    AESCounterCTR,
    AESError,
    AESEncryptDecrypt,
    AESSharedValues,
    KEY_SIZE_ROUNDS,
    AESUtils,
} from '../src/index';
import { TestsUtils, AESTestUtils } from '../utils';
import { ObjectUtils } from '../utils/common';

const password = 'yourpassword123';
const salt = TestsUtils.getConstantSaltBytes();
const key = TestsUtils.deriveKeyFromPassword(password, salt);
const keyUint8Array = new Uint8Array(key);

// TEST DATA 

const cipherEncrypted = new Uint8Array([
    44, 8, 48, 94, 237, 56, 255,
    122, 6, 252, 216, 12, 78, 104,
    94, 43, 235, 61, 167, 128, 101,
    228
])
const cipherTextEncryptedInBYtes = [
    '00101100', '00001000',
    '00110000', '01011110',
    '11101101', '00111000',
    '11111111', '01111010',
    '00000110', '11111100',
    '11011000', '00001100',
    '01001110', '01101000',
    '01011110', '00101011',
    '11101011', '00111101',
    '10100111', '10000000',
    '01100101', '11100100'
]
const encryptedNonce = new Uint8Array([
    71, 105, 17, 246,
    153, 214, 156, 230,
    101, 31, 154, 154
]
)
const encryptedNonceINBytes = [
    '01000111', '01101001',
    '00010001', '11110110',
    '10011001', '11010110',
    '10011100', '11100110',
    '01100101', '00011111',
    '10011010', '10011010'
]



describe('GET STRING', () => {
    const handler = new AESHandler(keyUint8Array);
    const originalText = 'This is a secret test!';
    const plaintext = TestsUtils.stringToUint8Array(originalText);

    // Encrypt returns { ciphertext, nonce }
    const { cipherText, nonce } = handler.encrypt(plaintext);





    const cipherBytes = MappingHandler.bytesToBitStrings(cipherText)
    const nonceBytes = MappingHandler.bytesToBitStrings(nonce)
    console.log('cipherBytes', cipherBytes)
    console.log('nonceBytes', nonceBytes)


    const stringLength = cipherBytes.join('') + nonceBytes.join("")
    console.log(stringLength.length)
    console.log(stringLength.length / 4)
    console.log(stringLength.length / 3)
    // const string = MappingHandler.uint8ArrayToString(encryptedNonce)
    // const { length } = '010001110110100100010001111101101001100111010110100111001110011001100101000111111001101010011010'
    // const x = 'ʜ𝕖ḽḽⓞⓣʜ𝕚ṡ⒤⒮𝕥ⓗḗᴛḙⓧṫ𝕥ḥa̲𝕥ⓦ⒤𝗅ĺċ𝕠⒱ᴇr̲'
    // console.log(length / 3, "HEREEEE")
    // console.log(x.length)
    // const salt = TestsUtils.getConstantSaltBytes();
    // const key = Buffer.from('th')
    // const testSmallKey = new Uint8Array(key)
    // const bytes = MappingHandler.bytesToBitStrings(testSmallKey)
    // console.log(bytes.join('').length)

    // const noneLength = encryptedNonce.join('').length
    // const encryptionLength = cipherTextEncryptedInBYtes.join('')
    //     console.log(encryptionLength)
    // console.log({ string })
    // console.log(cipherText, nonce)

    // console.log("BYTES", bytes.join(''))
    const result = MappingHandler.textToDisplayConvert('hello this is the text that will cover', cipherTextEncryptedInBYtes.join(' '))
    console.log({ result })
})

// describe('TwoFishUtils.truncateAndPadKey', () => {

//     MappingHandler.tester()
// })