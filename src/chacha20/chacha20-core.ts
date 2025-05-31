import { SIGMA_CONSTANTS, CHA_CHA_ROUNDS } from './constants';
import {
  ChaCha20Error,
  ChaCha20EncodingUtils,
  ChaCha20ParsingUtils,
} from './utils';

/**
 * Core of the ChaCha20 stream cipher.
 *
 * we initlize and generate the 512 bit keystream blocks using:
 *   - 256-bit key,
 *   - 96-bit nonce
 *   - 32-bit block counter
 *
 * For full specification and algorithm details, see:
 * https://cr.yp.to/chacha/chacha-20080128.pdf
 *
 * Usage:
 *  - Initialize with a key and nonce
 *  - Call `generateBlock()` to get a 64-byte keystream block
 *  - Manage the counter manually or via `resetCounter()`
 */
export class ChaCha20Core {
  private readonly key: Uint8Array; // 32 bytes
  private readonly nonce: Uint8Array; // 12 bytes
  private counter: number;
  private readonly constants = SIGMA_CONSTANTS;
  private readonly rounds = CHA_CHA_ROUNDS;
  private stateMatrix = new Uint32Array(16);

  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw ChaCha20Error.CoreConstructorError(
        'Key must be 32 bytes (256 bits).',
      );
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
      throw ChaCha20Error.CoreConstructorError(
        'Nonce must be 12 bytes (96 bits).',
      );
    }
    this.key = key;
    this.nonce = nonce;
    this.counter = counter;

    this.initializeState();
  }
  private initializeState() {
    this.stateMatrix.set(this.constants, 0);

    // Key: 32 bytes -> 8 Uint32 words little-endian
    for (let i = 0; i < 8; i++) {
      this.stateMatrix[4 + i] = ChaCha20ParsingUtils.readUint32LE(
        this.key,
        i * 4,
      );
    }

    this.stateMatrix[12] = this.counter;

    // Nonce: 12 bytes -> 3 Uint32 words little-endian
    for (let i = 0; i < 3; i++) {
      this.stateMatrix[13 + i] = ChaCha20ParsingUtils.readUint32LE(
        this.nonce,
        i * 4,
      );
    }
  }
  /**
   * Heart and secret sauce of ChaCha20 The Quarter round in shirt, scrambles the absoulte heck out 512-bit
   * blocks, using 80 applications of the quarter-round.
   *
   * The quarter round scrambles 4 32-bit numbers (1/4 of the state block)
   * with a mix of additions, XORs, and bit rotations to spread entropy everywhere.
   *
   *
   * Further reading: https://sciresol.s3.us-east-2.amazonaws.com/IJST/Articles/2016/Issue-3/Article24.pdf
   */
  private quarterRound(
    state: Uint32Array,
    a: number,
    b: number,
    c: number,
    d: number,
  ) {
    state[a] += state[b];
    state[d] = ChaCha20EncodingUtils.rotateLeft(state[d] ^ state[a], 16);

    state[c] += state[d];
    state[b] = ChaCha20EncodingUtils.rotateLeft(state[b] ^ state[c], 12);

    state[a] += state[b];
    state[d] = ChaCha20EncodingUtils.rotateLeft(state[d] ^ state[a], 8);

    state[c] += state[d];
    state[b] = ChaCha20EncodingUtils.rotateLeft(state[b] ^ state[c], 7);
  }

  private chacha20Block(state: Uint32Array): Uint32Array {
    const workingState = new Uint32Array(state); // copy of the state
    const rounds = this.rounds / 2;
    /**
     * we apply the 20 rounds.
     * (10 iterations of 2 rounds: column + diagonal)
     */
    for (let i = 0; i < rounds; i++) {
      // Column
      this.quarterRound(workingState, 0, 4, 8, 12);
      this.quarterRound(workingState, 1, 5, 9, 13);
      this.quarterRound(workingState, 2, 6, 10, 14);
      this.quarterRound(workingState, 3, 7, 11, 15);

      // Diagonal
      this.quarterRound(workingState, 0, 5, 10, 15);
      this.quarterRound(workingState, 1, 6, 11, 12);
      this.quarterRound(workingState, 2, 7, 8, 13);
      this.quarterRound(workingState, 3, 4, 9, 14);
    }

    for (let i = 0; i < 16; i++) {
      workingState[i] = (workingState[i] + state[i]) >>> 0;
    }

    return workingState;
  }

  generateBlock(): Uint8Array {
    /**
     * validate teh maximum value of a 32 bit unsinged int (4,294,967,295)
     * counter is designed to track how many 64-byte blocks have been generated the cap is here
     * which will render it to overflow
     */
    if (this.counter > 0xffffffff) {
      throw ChaCha20Error.CounterError();
    }
    this.initializeState();

    const blockState = this.chacha20Block(this.stateMatrix);
    const output = new Uint8Array(64);

    // Convert Uint32 words to little-endian bytes
    for (let i = 0; i < 16; i++) {
      ChaCha20EncodingUtils.writeUint32LE(output, i * 4, blockState[i]);
    }

    this.counter++;
    return output;
  }

  resetCounter(counter: number) {
    this.counter = counter;
  }
}
