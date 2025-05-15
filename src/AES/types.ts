/** @internal */
type TAESBuffer = Uint8Array | number[];
type TByte = number;
type TKeySizeRounds = { 16: number; 24: number; 32: number };
type TRoundKey = [number, number, number, number]; // 4 words, 32 bits each
type Maybe<T> = T | undefined;
export type { TAESBuffer, TKeySizeRounds, TByte, TRoundKey, Maybe };
