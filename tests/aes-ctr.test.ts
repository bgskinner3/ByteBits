import { AESHandler } from '../src/index';
import { TestsUtils } from '../utils';

const password = 'yourpassword123';
const salt = TestsUtils.getConstantSaltBytes();
const key = TestsUtils.deriveKeyFromPassword(password, salt);
const keyUint8Array = new Uint8Array(key);

describe('AESHandler', () => {
    let handler: AESHandler;

    beforeEach(() => {
        handler = new AESHandler(keyUint8Array);
    });

    it('should initialize AESHandler correctly', () => {
        expect(handler).toBeDefined();
        // Internals are private, but you can check the handler instance exists
    });

    it('should correctly encrypt and decrypt using AES CTR mode', () => {
        const originalText = 'This is a secret test!';
        const plaintext = TestsUtils.stringToUint8Array(originalText);

        // Encrypt returns { ciphertext, nonce }
        const { cipherText, nonce } = handler.encrypt(plaintext);

        // New handler for decryption with the same key
        const decryptHandler = new AESHandler(keyUint8Array);

        // Decrypt cipherText with nonce
        const decrypted = decryptHandler.decrypt(cipherText, nonce);

        const decryptedText = TestsUtils.uint8ArrayToString(decrypted);

        expect(decrypted).toEqual(plaintext);
        expect(decryptedText).toBe(originalText);
        expect(cipherText).not.toEqual(plaintext);
    });

    it('should encrypt and decrypt plaintext of arbitrary length (non-block size)', () => {
        const originalText = 'Short!';
        const plaintext = TestsUtils.stringToUint8Array(originalText);

        const { cipherText, nonce } = handler.encrypt(plaintext);

        const decryptHandler = new AESHandler(keyUint8Array);
        const decrypted = decryptHandler.decrypt(cipherText, nonce);

        const decryptedText = TestsUtils.uint8ArrayToString(decrypted);

        expect(decrypted).toEqual(plaintext);
        expect(decryptedText).toBe(originalText);
    });

    it('should use different nonces for each encryption', () => {
        const plaintext = TestsUtils.stringToUint8Array('Block1');
        const { cipherText: ct1, nonce: nonce1 } = handler.encrypt(plaintext);
        const { cipherText: ct2, nonce: nonce2 } = handler.encrypt(plaintext);
        console.log(nonce1, nonce2)
        expect(nonce1).not.toEqual(nonce2);
        expect(ct1).not.toEqual(ct2);
    });
});
// import {
//     AESHandler,
//     AESCore,
//     AESCounterCTR
// } from '../src/index';
// import { TestsUtils } from '../utils';

// const password = 'yourpassword123';
// const salt = TestsUtils.getConstantSaltBytes();
// const key = TestsUtils.deriveKeyFromPassword(password, salt);
// const keyUint8Array: Uint8Array = new Uint8Array(key);

// describe('AESHandler', () => {
//     let aesCore: AESCore;
//     let counter: AESCounterCTR;
//     let handler: AESHandler;

//     beforeEach(() => {
//         aesCore = new AESCore(keyUint8Array);
//         counter = new AESCounterCTR(1);
//         handler = new AESHandler(aesCore, counter);
//     });

//     it('should initialize AESHandler correctly', () => {
//         expect(handler).toBeDefined();
//         expect(handler['_aes']).toEqual(aesCore);
//         expect(handler['_counter']).toEqual(counter);
//         expect(handler['_remainingCounterIndex']).toBe(16);
//         expect(handler['_remainingCounter']).toBeNull();
//     });

//     it('should correctly encrypt and decrypt using AES CTR mode', () => {
//         const originalText = 'This is a secret test!';
//         const plaintext = TestsUtils.stringToUint8Array(originalText);

//         // Clone counter BEFORE encryption
//         const counterSnapshot = new Uint8Array(counter._counter);
//         const cipherText = handler.encrypt(plaintext);

//         const decryptCounter = new AESCounterCTR(counterSnapshot);
//         const decryptHandler = new AESHandler(aesCore, decryptCounter);
//         const decrypted = decryptHandler.encrypt(cipherText);
//         const decryptedText = TestsUtils.uint8ArrayToString(decrypted);

//         expect(decrypted).toEqual(plaintext);
//         expect(decryptedText).toBe(originalText);
//         expect(cipherText).not.toEqual(plaintext);
//     });

//     it('should encrypt and decrypt plaintext of arbitrary length (non-block size)', () => {
//         const originalText = 'Short!';
//         const plaintext = TestsUtils.stringToUint8Array(originalText);

//         const counterSnapshot = new Uint8Array(counter._counter);
//         const cipherText = handler.encrypt(plaintext);

//         const decryptCounter = new AESCounterCTR(counterSnapshot);
//         const decryptHandler = new AESHandler(aesCore, decryptCounter);
//         const decrypted = decryptHandler.encrypt(cipherText);
//         const decryptedText = TestsUtils.uint8ArrayToString(decrypted);

//         expect(decrypted).toEqual(plaintext);
//         expect(decryptedText).toBe(originalText);
//     });

//     it('should increment counter correctly after each block', () => {
//         const freshCounter = new AESCounterCTR(0);
//         const handlerWithFreshCounter = new AESHandler(aesCore, freshCounter);
//         const counterValue = freshCounter._counter;

//         const plaintext = new Uint8Array(32); // two blocks

//         handlerWithFreshCounter.encrypt(plaintext.subarray(0, 16));
//         const firstValue = freshCounter.getValue(counterValue);
//         expect(firstValue).toBe(1);

//         handlerWithFreshCounter.encrypt(plaintext.subarray(16, 32));
//         const secondValue = freshCounter.getValue(counterValue);
//         expect(secondValue).toBe(2);
//     });
// });
