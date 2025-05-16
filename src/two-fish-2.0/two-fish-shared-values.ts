import {
    ROUNDS,
    HEX_TAB,
    SUB_KEY_WORD,
    SUB_KEY_COUNT,
    SUB_KEY_STEP,
    SUB_KEY_ROUNDS,
    SESSION_MEMORY,
    SUB_KEY_ROTATE_LEFT,
    MAX_PASSKEY_LENGTH,
    DIFFUSION_MATRIX_0,
    DIFFUSION_MATRIX_1,
    DIFFUSION_MATRIX_2,
    DIFFUSION_MATRIX_3,
    PERMUTATION_TABLE_0,
    PERMUTATION_TABLE_1,
    REED_SOL_GAL_FIELD
} from "./constants";


export class TwoFishSharedValues {
    static totalRounds = ROUNDS
    static hexDecimalTab = HEX_TAB
    static subKeyWord = SUB_KEY_WORD
    static subKeyCount = SUB_KEY_COUNT
    static subKeyStep = SUB_KEY_STEP
    static subKeyRounds = SUB_KEY_ROUNDS
    static sessionMemory = SESSION_MEMORY
    static reedSolGalField = REED_SOL_GAL_FIELD
    static totalSubKEyROtationLeft = SUB_KEY_ROTATE_LEFT
    static maxPasswordLength = MAX_PASSKEY_LENGTH
    static P0: Uint8Array = PERMUTATION_TABLE_0
    static P1: Uint8Array = PERMUTATION_TABLE_1
    static MDS0: Uint32Array = DIFFUSION_MATRIX_0
    static MDS1: Uint32Array = DIFFUSION_MATRIX_1
    static MDS2: Uint32Array = DIFFUSION_MATRIX_2
    static MDS3: Uint32Array = DIFFUSION_MATRIX_3

    static permutationMapsForKey = [
        [this.P0, this.P0, this.P1, this.P1],  // step 0 (64-bit key final step)
        [this.P0, this.P1, this.P0, this.P1],  // step 1 (128 bit)
        [this.P1, this.P1, this.P0, this.P0],  // step 2 (192 bit)
        [this.P1, this.P0, this.P0, this.P1],  // step 3 (256 bit)
    ];
}
