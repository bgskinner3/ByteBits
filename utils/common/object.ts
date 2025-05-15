/**
 * Utility class for handling objects with type safety.
 */
export class ObjectUtils {
  /**
   * Returns the keys of an object while protecting key inference.
   *
   * @template Obj - The object type
   * @param {Obj} obj - The object to extract keys from
   */
  static keys<Obj extends object>(obj: Obj) {
    return Object.keys(obj) as (keyof Obj)[];
  }
  /**
   * Returns the key-value pairs of an object while protecting type inference.
   *
   * @template T - The object type
   * @param {T} obj - The object to extract key-value pairs from
   */
  static entries<T extends Record<string, unknown>>(
    obj: T,
  ): [keyof T, T[keyof T]][] {
    return obj ? (Object.entries(obj) as [keyof T, T[keyof T]][]) : [];
  }
  /**
   * Constructs an object from an array of entries with type safety.
   */
  static fromEntries<T extends [string, unknown][]>(
    entries: T,
  ): { [K in T[number][0]]: Extract<T[number], [K, unknown]>[1] } {
    return Object.fromEntries(entries) as {
      [K in T[number][0]]: Extract<T[number], [K, unknown]>[1];
    };
  }
  /**
   * Returns the values of an object while protecting type inference.
   *
   * @template Obj - The object type
   * @param {Obj} obj - The object to extract values from
   */
  static values<Obj extends object>(obj: Obj) {
    return Object.values(obj) as Obj[keyof Obj][];
  }
}
