



export class KaloUtils {
    static entries<T extends Record<string, unknown>>(
        obj: T,
      ): [keyof T, T[keyof T]][] {
        return obj ? (Object.entries(obj) as [keyof T, T[keyof T]][]) : [];
      }
}