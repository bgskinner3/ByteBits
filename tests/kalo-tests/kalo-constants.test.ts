import { BASE_LIB, PADDED_LIB, FOUR_BIT_KEYS } from '../../src';
import { ObjectUtils } from '../../utils/common';

describe('Constant variables', () => {
  it('LIBS - has keys for all lowercase letters a-z', () => {
    const expectedCharCodes = Array.from({ length: 26 }, (_, i) => 0x0061 + i);
    const expectedKeys = expectedCharCodes.map(
      (code) => `U${code.toString(16).toUpperCase().padStart(4, '0')}`,
    );

    const actualPaddedKeys = ObjectUtils.keys(PADDED_LIB).sort();
    const actualBaseKeys = ObjectUtils.keys(BASE_LIB).sort();

    expect(actualPaddedKeys).toEqual(expectedKeys);
    expect(actualBaseKeys).toEqual(expectedKeys);
  });
  it('FOUR BIT KEYS - should contain 16 unique 4-bit binary strings', () => {
    expect(FOUR_BIT_KEYS.length).toBe(16);
    const seen = new Set<string>();

    for (const key of FOUR_BIT_KEYS) {
      expect(typeof key).toBe('string');
      expect(key).toHaveLength(4);
      expect(/^[01]{4}$/.test(key)).toBe(true);
      seen.add(key);
    }

    expect(seen.size).toBe(16);
  });
});

describe('Character Libraries', () => {
  const keys = ObjectUtils.keys(PADDED_LIB);
  // Check if the objects have the correct structure
  it('should have correct structure for all character keys', () => {
    // Check that both PADDED_LIB and BASE_LIB have the same keys
    const keys = ObjectUtils.keys(PADDED_LIB);
    keys.forEach((key) => {
      expect(BASE_LIB).toHaveProperty(key); // Ensure both have the same keys
    });
  });

  // Check if arrays for each key match in length between PADDED_LIB and BASE_LIB
  it('PADDED_LIB should have all unique characters across all arrays', () => {
    const allPaddedChars = keys.flatMap((key) => PADDED_LIB[key]);
    const uniquePaddedChars = new Set(allPaddedChars);
    expect(uniquePaddedChars.size).toBe(allPaddedChars.length);
  });

  it('BASE_LIB should have all unique characters across all arrays', () => {
    const allBaseLibChars = keys.flatMap((key) => BASE_LIB[key]);
    const uniqueBaseChars = new Set(allBaseLibChars);
    expect(uniqueBaseChars.size).toBe(allBaseLibChars.length);
  });

  it('should have no overlapping characters between PADDED_LIB and BASE_LIB', () => {
    const allPaddedChars = keys.flatMap((key) => PADDED_LIB[key]);
    const allBaseLibChars = keys.flatMap((key) => BASE_LIB[key]);

    const combinedLength = allPaddedChars.length + allBaseLibChars.length;
    const uniqueChars = new Set([...allPaddedChars, ...allBaseLibChars]);

    expect(uniqueChars.size).toBe(combinedLength);
  });
});
