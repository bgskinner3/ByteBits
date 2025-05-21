import type { KaloAESHandler } from '../../aes-ctr';
import { BASE_LIB, PADDED_LIB, FOUR_BIT_KEYS } from './constants-kalo';

type AllCharArrays =
    | (typeof BASE_LIB)[keyof typeof BASE_LIB]
    | (typeof PADDED_LIB)[keyof typeof PADDED_LIB];
type TAllChars = AllCharArrays[number];

type TLookUpObjectKeys = keyof typeof BASE_LIB | keyof typeof PADDED_LIB;
type TFourBitKey = (typeof FOUR_BIT_KEYS)[number];
type TVariantObject = Record<TFourBitKey, TAllChars>;

type TInverseVariantObject = Record<TAllChars, TFourBitKey>;
type TLookUpDecryptObject = Record<TAllChars, TFourBitKey>;
type TLookUpEncryptObject = Record<TLookUpObjectKeys, TVariantObject>;

type TKaloCore = {
    password?: string;
    remainderPair?: {
        salt: Uint8Array;
        nonce: Uint8Array;
    };
};
type TKaloEncrypt = {
    encryptText: string;
    displayText: string;
    state: {
        aesHandler: KaloAESHandler;
        remainders: {
            nonceRemainder: Uint8Array;
            saltRemainder: Uint8Array;
        };
    };
};
type TKaloDecrypt = {
    encryptedText: string;
    state: {
        aesHandler: KaloAESHandler;
        nonce: Uint8Array;
    };
};
export type {
    TKaloCore,
    TVariantObject,
    TInverseVariantObject,
    TLookUpEncryptObject,
    TLookUpObjectKeys,
    TFourBitKey,
    TAllChars,
    TLookUpDecryptObject,
    TKaloEncrypt,
    TKaloDecrypt,
};
