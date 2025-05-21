import { BASE_LIB, PADDED_LIB, FOUR_BIT_KEYS } from './constants-kalo';
import type {
  TVariantObject,
  TLookUpObjectKeys,
  TAllChars,
  TInverseVariantObject,
  TLookUpEncryptObject,
  TLookUpDecryptObject,
} from './types';

class KaloMapper {
  public readonly encryptMap: TLookUpEncryptObject;
  public readonly decryptMap: TLookUpDecryptObject;
  public readonly paddedEncryptMap: TLookUpEncryptObject;
  public readonly paddedDecryptMap: TLookUpDecryptObject;

  constructor() {
    const baseMaps = this.buildMaps();
    this.encryptMap = baseMaps.encryptMap;
    this.decryptMap = baseMaps.decryptMap;
    this.paddedEncryptMap = baseMaps.paddedEncryptMap;
    this.paddedDecryptMap = baseMaps.paddedDecryptMap;
  }
  private buildLookUpVariants(
    _charKey: TLookUpObjectKeys,
    variantChars: readonly TAllChars[],
  ): {
    variants: TVariantObject;
    inverseVariants: TInverseVariantObject;
  } {
    const variants = {} as TVariantObject;
    const inverseVariants = {} as TInverseVariantObject;

    for (let i = 0; i < variantChars.length; i++) {
      const bitKey = FOUR_BIT_KEYS[i];
      const char = variantChars[i];
      variants[bitKey] = char;
      inverseVariants[char] = bitKey;
    }

    return {
      variants,
      inverseVariants,
    };
  }

  private buildMaps(): {
    encryptMap: TLookUpEncryptObject;
    decryptMap: TLookUpDecryptObject;
    paddedEncryptMap: TLookUpEncryptObject;
    paddedDecryptMap: TLookUpDecryptObject;
  } {
    const encryptMap: Partial<TLookUpEncryptObject> = {};
    const decryptMap: Partial<TLookUpDecryptObject> = {};
    const paddedEncryptMap: Partial<TLookUpEncryptObject> = {};
    const paddedDecryptMap: Partial<TLookUpDecryptObject> = {};
    for (const [charKey, variantChars] of Object.entries(BASE_LIB)) {
      const charcaterkey = charKey as TLookUpObjectKeys;
      const { variants, inverseVariants } = this.buildLookUpVariants(
        charcaterkey,
        variantChars,
      );
      encryptMap[charKey as TLookUpObjectKeys] = variants;
      for (const [char, bitKey] of Object.entries(inverseVariants)) {
        decryptMap[char as TAllChars] = bitKey;
      }
    }
    for (const [charKey, variantChars] of Object.entries(PADDED_LIB)) {
      const charcaterkey = charKey as TLookUpObjectKeys;
      const { variants, inverseVariants } = this.buildLookUpVariants(
        charcaterkey,
        variantChars,
      );
      paddedEncryptMap[charKey as TLookUpObjectKeys] = variants;
      for (const [char, bitKey] of Object.entries(inverseVariants)) {
        paddedDecryptMap[char as TAllChars] = bitKey;
      }
    }
    return {
      encryptMap: encryptMap as TLookUpEncryptObject,
      decryptMap: decryptMap as TLookUpDecryptObject,
      paddedEncryptMap: paddedEncryptMap as TLookUpEncryptObject,
      paddedDecryptMap: paddedDecryptMap as TLookUpDecryptObject,
    };
  }
}
export const kaloMapper = new KaloMapper();
