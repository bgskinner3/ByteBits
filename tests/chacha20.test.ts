import { ChaCha20Handler } from '../src';
// import { TestsUtils } from "../utils";
const testENVHex =
  '90513894050b0d9953772cb8dad4e8911ec96869fb8960c0b388f6095da6ed99';
const testNonce = new Uint8Array([
  249, 57, 16, 44, 76, 233, 251, 234, 3, 203, 140, 149,
]);
describe('CHaCha20', () => {
  test('should encrypt and decrypt correctly', () => {
    const plaintextStr = 'Hello ChaCha20 Test!';
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(plaintextStr);

    // Initialize handler for encryption
    const encryptHandler = new ChaCha20Handler(testENVHex, testNonce);
    const ciphertext = encryptHandler.processCipher(plaintext);

    // Initialize handler for decryption (same key and nonce)
    const decryptHandler = new ChaCha20Handler(testENVHex, testNonce);
    const decrypted = decryptHandler.processCipher(ciphertext);

    const decoder = new TextDecoder();
    const decryptedStr = decoder.decode(decrypted);
    console.log({ decryptedStr });
    expect(decryptedStr).toBe(plaintextStr);
  });
});
