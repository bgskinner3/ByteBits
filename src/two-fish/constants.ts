




export const TWO_FISH_CONSTANTS = {
    ROUNDS: 16,
    SK_STEP: 0x01010101,
    SK_ROTL: 9,
    ROUND_SUBKEYS: 8,
    SUBKEY_CNT: 40,
    RS_GF_FDBK: 0x14d,
    SESSION_MEMORY: new ArrayBuffer(4256),
    SUB_KEY_WORD: new Uint32Array(4),
    MAXPASSKEYLENGTH: 64
} as const;