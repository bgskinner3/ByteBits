const SIGMA_CONSTANTS =
  /* prettier-ignore */ Object.freeze(([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,] as const));

Object.freeze([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] as const);
const CHA_CHA_ROUNDS = 20 as const;
const CHA_CHA_PROCESS_BLOCK_SIZE = 64 as const;

export { SIGMA_CONSTANTS, CHA_CHA_ROUNDS, CHA_CHA_PROCESS_BLOCK_SIZE };
