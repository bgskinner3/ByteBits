import { TRoundKey } from '../src';

export class AESTestUtils {
  static is4x4Matrix(arr: TRoundKey): boolean {
    return (
      Array.isArray(arr) &&
      arr.length === 4 &&
      arr.every(
        (row) =>
          Array.isArray(row) &&
          row.length === 4 &&
          row.every((n) => typeof n === 'number'),
      )
    );
  }
  static isFlatArrayOfNumbers(arr: TRoundKey): boolean {
    return Array.isArray(arr) && arr.every((n) => typeof n === 'number');
  }
}
