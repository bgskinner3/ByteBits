import { MAPPER_LIB, FOUR_BIT_KEYS } from './constants';
import { KaloUtils } from './utils';
import {
  TLookUpDecryptObject,
  TLookUpEncryptObject,
  TLookUpObjectKeys,
  TAllChars,
  TVariantObject,
  TInverseVariantObject,
} from './constants';

function buildCharEncoding<
  K extends TLookUpObjectKeys,
  V extends readonly TAllChars[],
>(
  _charKey: K,
  variantChars: V,
): {
  variants: TVariantObject;
  inverseVariants: TInverseVariantObject;
} {
  const n = variantChars.length;

  const variants = {} as TVariantObject;
  const inverseVariants = {} as TInverseVariantObject;

  for (let i = 0; i < n; i++) {
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

function buildKaloMappers(): {
  encryptMap: TLookUpEncryptObject;
  decryptMap: TLookUpDecryptObject;
} {
  const encryptMap: Partial<TLookUpEncryptObject> = {};
  const decryptMap: Partial<TLookUpDecryptObject> = {};

  for (const [charKey, variantChars] of KaloUtils.entries(MAPPER_LIB)) {
    const { variants, inverseVariants } = buildCharEncoding(
      charKey,
      variantChars,
    );
    encryptMap[charKey] = variants;

    // flatten inverseVariants into decryptMap
    for (const [char, bitKey] of KaloUtils.entries(inverseVariants)) {
      decryptMap[char] = bitKey;
    }
  }

  return {
    encryptMap: encryptMap as TLookUpEncryptObject,
    decryptMap: decryptMap as TLookUpDecryptObject,
  };
}

export const { encryptMap: KALO_ENCRYPT_MAP, decryptMap: KALO_DECRYPT_MAP } =
  buildKaloMappers();
