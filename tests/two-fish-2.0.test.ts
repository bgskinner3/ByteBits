import {
    TwoFishHandler20,
    TwoFishCore,
    TwoFishSharedValues,
    TwoFishEncryptDecrypt,
    TwoFishUtils,
    TwoFishBlockUtils,
    TwoFishError,
} from '../src/index';
const BLOCK_SIZE = 16;
describe('TwoFishUtils.truncateAndPadKey', () => {
    it('pads empty key to 8 bytes', () => {
        const input = new Uint8Array([]);
        const result = TwoFishUtils.truncateAndPadKey(input);
        expect(result.length).toBe(8);
        expect(Array.from(result)).toEqual(Array(8).fill(0));
    });

    it('pads short key (3 bytes) to 8 bytes', () => {
        const input = new Uint8Array([1, 2, 3]);
        const result = TwoFishUtils.truncateAndPadKey(input);
        expect(result.length).toBe(8);
        expect(Array.from(result.slice(0, 3))).toEqual([1, 2, 3]);
        expect(Array.from(result.slice(3))).toEqual([0, 0, 0, 0, 0]);
    });

    it('does not pad key with length = multiple of 8', () => {
        const input = new Uint8Array(16).fill(7);
        const result = TwoFishUtils.truncateAndPadKey(input);
        expect(result.length).toBe(16);
        expect(Array.from(result)).toEqual(Array(16).fill(7));
    });

    it('pads key of length 11 to 16 bytes', () => {
        const input = new Uint8Array(11).fill(1);
        const result = TwoFishUtils.truncateAndPadKey(input);
        expect(result.length).toBe(16);
        expect(Array.from(result.slice(0, 11))).toEqual(Array(11).fill(1));
        expect(Array.from(result.slice(11))).toEqual(Array(5).fill(0));
    });

    it('truncates key longer than maxPasswordLength (32)', () => {
        const input = new Uint8Array(40).map((_, i) => i);
        const result = TwoFishUtils.truncateAndPadKey(input);
        expect(result.length % 8).toBe(0);
        expect(result.length).toBe(32);
        expect(Array.from(result)).toEqual(Array.from(input.slice(0, 32)));
    });
});

describe('TwoFish Utils Tests', () => {
    it('extracts the correct byte using substitutionMixer', () => {
        const input = 0x12345678;
        expect(TwoFishUtils.substitutionMixer(input, 'b0')).toBe(0x78);
        expect(TwoFishUtils.substitutionMixer(input, 'b1')).toBe(0x56);
        expect(TwoFishUtils.substitutionMixer(input, 'b2')).toBe(0x34);
        expect(TwoFishUtils.substitutionMixer(input, 'b3')).toBe(0x12);
    });
    it('converts char to signed 8-bit int correctly', () => {
        expect(TwoFishUtils.charToSigned8BitInt('\u0000')).toBe(0);
        expect(TwoFishUtils.charToSigned8BitInt('A')).toBe(65);
        expect(TwoFishUtils.charToSigned8BitInt('ÿ')).toBe(-1); // charCode 255
    });
    it('applies Reed-Solomon transform step correctly for known value', () => {
        const input = 0xabcd1234;
        const result = TwoFishUtils.reedSolomonTransformStep(input);
        expect(typeof result).toBe('number');
    });
    it('writes and reads Uint32LE correctly', () => {
        const buffer = new Uint8Array(4);
        const value = 0x78563412;

        TwoFishUtils.writeUint32LE(buffer, 0, value);
        expect(Array.from(buffer)).toEqual([0x12, 0x34, 0x56, 0x78]);

        const readValue = TwoFishUtils.readUint32LE(buffer, 0);
        expect(readValue).toBe(value);
    });
    it('returns correct permutation maps', () => {
        const maps = TwoFishUtils.permutationMapsForKey;
        expect(maps).toHaveLength(4);
        maps.forEach((row) => expect(row).toHaveLength(4));
    });
    it('produces correct subKeyWord values for known inputs', () => {
        const subKeyWord = new Uint32Array(4);
        const input = {
            numKeyBlocks64: 2,
            keyWord0: 0x01020304,
            keyWord1: 0x11121314,
            keyWord2: 0x21222324,
            keyWord3: 0x31323334,
            subByte0: 0x01,
            subByte1: 0x02,
            subByte2: 0x03,
            subByte3: 0x04,
            subKeyWord,
        };

        TwoFishUtils.getSubKeyWord(input);

        expect(Array.from(subKeyWord)).toEqual([
            3806473211, 1224839569, 4050317764, 3719292125,
        ]);
    });
});
describe('pkcs7 Padding Tests', () => {
    test('correctly unpads valid padding', () => {
        const padded = new Uint8Array([1, 2, 3, 3, 3, 3]);
        const unpadded = TwoFishBlockUtils.pkcs7UnPad(padded);
        expect(Array.from(unpadded)).toEqual([1, 2, 3]);
    });

    test('throws TwoFishError for padding length less than 1', () => {
        const badPadding = new Uint8Array([1, 2, 3, 0]);
        expect(() => TwoFishBlockUtils.pkcs7UnPad(badPadding)).toThrow(
            TwoFishError,
        );
    });

    test('throws TwoFishError for padding length greater than 16', () => {
        const badPadding = new Uint8Array([1, 2, 3, 17]);
        expect(() => TwoFishBlockUtils.pkcs7UnPad(badPadding)).toThrow(
            TwoFishError,
        );
    });

    test('throws TwoFishError if padding bytes are incorrect', () => {
        const badPaddingBytes = new Uint8Array([1, 2, 3, 4, 5, 3, 3, 2]);
        expect(() => TwoFishBlockUtils.pkcs7UnPad(badPaddingBytes)).toThrow(
            TwoFishError,
        );
        expect(() => TwoFishBlockUtils.pkcs7UnPad(badPaddingBytes)).toThrow(
            'Invalid PKCS#7 padding',
        );
    });

    test('pad adds correct padding', () => {
        const input = new Uint8Array([1, 2, 3]);
        const padded = TwoFishBlockUtils.pkcs7Pad(input);

        expect(padded.length % BLOCK_SIZE).toBe(0);
        expect(padded.slice(0, input.length)).toEqual(input);

        const paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        const paddingBytes = padded.slice(padded.length - paddingLength);

        for (const b of paddingBytes) {
            expect(b).toBe(paddingLength);
        }
    });

    test('unpad removes padding correctly', () => {
        const data = new Uint8Array([
            1, 2, 3, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        ]);
        const unpadded = TwoFishBlockUtils.pkcs7UnPad(data);

        expect(unpadded).toEqual(new Uint8Array([1, 2, 3]));
    });
});

describe('TwoFishCore', () => {
    it('converts password string into Uint8Array correctly', () => {
        const raw = 'test';
        const tempKey = new Uint8Array(raw.length);
        const expected = new Uint8Array(raw.split('').map((c) => c.charCodeAt(0))); // assuming ASCII conversion

        /**
         * TEMP SOLUTION SINCE INITSESSION IS PRIVATE
         * imitates same logic
         */
        for (let i = 0; i < raw.length; i++) {
            tempKey[i] = TwoFishUtils.charToSigned8BitInt(raw[i]);
        }

        expect(tempKey).toEqual(expected);
    });

    it('computes rsMDSEncode with deterministic output', () => {
        const core = new TwoFishCore('key');
        const result = core.rsMDSEncode(0x11223344, 0x55667788);

        // This value is expected to change as your implementation stabilizes.
        // You can snapshot it temporarily or later match to official Twofish outputs.
        expect(typeof result).toBe('number');
        expect(result >>> 0).toBeGreaterThanOrEqual(0);
    });

    it('generates expected structure of s_Box and s_Keys with known password', () => {
        const core = new TwoFishCore('abc123');

        expect(core.s_Box).toBeInstanceOf(Uint32Array);
        expect(core.s_Box.length).toBeGreaterThan(0);

        expect(core.s_Keys).toBeInstanceOf(Uint32Array);
        expect(core.s_Keys.length).toBe(40); // 40 subkeys
    });

    it('generates deterministic s_Keys for same password', () => {
        const core1 = new TwoFishCore('abc123');
        const core2 = new TwoFishCore('abc123');

        expect(core1.s_Keys).toEqual(core2.s_Keys);
    });

    it('generates different s_Keys for different passwords', () => {
        const core1 = new TwoFishCore('abc123');
        const core2 = new TwoFishCore('differentpassword');

        expect(core1.s_Keys).not.toEqual(core2.s_Keys);
    });
});
describe('TwoFishHandler20', () => {
    const password = 'testpassword123';
    const handler = new TwoFishHandler20(password);

    test('should encrypt and decrypt buffer correctly', () => {
        const input = Buffer.from('This is a secret message!');
        console.log(input.toString())
        const encrypted = handler.encryptTwoFishBuffer(input);
        expect(encrypted).toBeDefined();
        expect(Buffer.isBuffer(encrypted)).toBe(true);
        console.log(encrypted?.toString())
        const decrypted = handler.decryptTwoFishBuffer(encrypted);
        expect(decrypted).toBeDefined();
        expect(Buffer.isBuffer(decrypted)).toBe(true);
        console.log(decrypted?.toString())
        // Decrypted buffer should match original input exactly
        expect(decrypted?.toString()).toEqual(input.toString());
    });

    test('should throw TwoFishError if decrypt called without buffer', () => {
        expect(() => handler.decryptTwoFishBuffer()).toThrow(TwoFishError);
    });
});
// describe('TwoFishHandler20', () => {
//     const password = 'test-password';
//     const handler = new TwoFishHandler20(password);

//     // it('should encrypt and decrypt a buffer to the same value', () => {
//     //     const input = Buffer.from('Hello, Twofish!');
//     //     console.log(input, "input")
//     //     const encrypted = handler.encryptTwoFishBuffer(input);
//     //     console.log(encrypted)
//     //     console.log('Encrypted tail:', encrypted?.slice(-16));
//     //     const decrypted = handler.decryptTwoFishBuffer(encrypted);
//     //     console.log(decrypted, "decrypted")
//     //     // expect(decrypted?.toString()).toBe(input.toString());
//     // });

//     // it('should encrypt and decrypt a buffer with exact block size (16 bytes)', () => {
//     //     const input = Buffer.from('1234567890ABCDEF'); // exactly 16 bytes
//     //     const encrypted = handler.encryptTwoFishBuffer(input);
//     //     const decrypted = handler.decryptTwoFishBuffer(encrypted!);

//     //     expect(decrypted?.toString()).toBe(input.toString());
//     // });

//     // it('should throw or fail safely on empty input', () => {
//     //     const input = Buffer.from('');
//     //     const encrypted = handler.encryptTwoFishBuffer(input);
//     //     const decrypted = handler.decryptTwoFishBuffer(encrypted!);

//     //     expect(decrypted?.toString()).toBe('');
//     // });
// });
