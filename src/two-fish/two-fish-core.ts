import { TwoFishSharedValues } from './two-fish-shared-values';
import { TwoFishUtils } from './utils/two-fish-utils';

/**
 * TwoFishCore
 *
 * We intilize and set the session here
 * 1. Key Ingestion & Sanitization
 * 2. Truncate and Pad to Block Size
 * 3. Split Key into 32-bit words
 * 4. RS-MDS Encode the Key Words
 * 5. Subkey Generation
 * 6. S-Box Table Expansion
 * 7. set skeys and s boxes with the finializatio
 * @internal
 */

export class TwoFishCore {
  private sessionMemory: ArrayBuffer;
  public s_Box: Uint32Array;
  public s_Keys: Uint32Array;
  private KEY: Uint8Array;
  // private twoFish;
  private SUB_KEY_WORD = TwoFishSharedValues.subKeyWord;
  private SUB_KEY_CNT = TwoFishSharedValues.subKeyCount;
  private SK_STEP = TwoFishSharedValues.subKeyStep;
  private SK_ROTL = TwoFishSharedValues.totalSubKEyROtationLeft;

  constructor(passphrase: string) {
    this.sessionMemory = new ArrayBuffer(4256);
    this.KEY = new Uint8Array(passphrase.length);
    // handle no password error
    this.s_Box = new Uint32Array();
    this.s_Keys = new Uint32Array();
    const sessionKey = this.initSessionKey(passphrase);
    this.makeSession(sessionKey);

    this.KEY.fill(0);
  }
  private initSessionKey(passphrase: string): Uint8Array {
    const tempKey = this.KEY;

    for (let i = 0; i < passphrase.length; i++) {
      tempKey[i] = TwoFishUtils.charToSigned8BitInt(passphrase[i]);
    }
    return tempKey;
  }

  private makeSession(key: Uint8Array) {
    key = TwoFishUtils.truncateAndPadKey(key);
    const numKeyBlocks64 = key.length / 8;
    // const sessionMemory = TwoFishSharedValues.sessionMemory; // constant new ArrayBuffer(4256)
    const tempSBox = new Uint32Array(this.sessionMemory, 0, 1024);
    const tempSKeys = new Uint32Array(this.sessionMemory, 4096, 40);

    // Step 3: Extract 32-bit words from key
    const kWords: number[] = [];
    for (let offset = 0; offset < key.length; offset += 4) {
      kWords.push(TwoFishUtils.readUint32LE(key, offset));
    }

    // Step 4: Fill last 4 sBox slots with rsMDSEncode of word pairs
    for (let i = 0; i < 4; i++) {
      const boxIndex = numKeyBlocks64 - 1 - i;
      const wordIndex = i * 2;
      tempSBox[boxIndex] = this.rsMDSEncode(
        kWords[wordIndex],
        kWords[wordIndex + 1],
      );
    }
    /**
            TODO
            Safe 32-bit masking for addition,
           
           More detailed comments,
           
           Initialization for SUB_KEY_WORD and constants,
           
           Validation checks for key length or array lengths.
            */
    this.generateSubKeys({ keyWords: kWords, numKeyBlocks64, tempSKeys });

    /**
     * 128-bit key → 4 words (k0 to k3)
     * 192-bit key → 6 words (k0 to k5)
     * 256-bit key → 8 words (k0 to k7)
     *
     */
    let [keyWord0, keyWord1, keyWord2, keyWord3] = kWords;
    keyWord0 = tempSBox[0];
    keyWord1 = tempSBox[1];
    keyWord2 = tempSBox[2];
    keyWord3 = tempSBox[3];
    for (let i = 0, j = 0; i < 256; i++, j += 2) {
      // @note we pass the same subByte index (i) into all four lanes
      TwoFishUtils.getSubKeyWord({
        numKeyBlocks64,
        keyWord0,
        keyWord1,
        keyWord2,
        keyWord3,
        subByte0: i,
        subByte1: i,
        subByte2: i,
        subByte3: i,
        subKeyWord: this.SUB_KEY_WORD,
      });

      // Store output words into the S-box table.
      // The S-box uses interleaved storage for 4 lookup tables (one per byte position)
      tempSBox[j] = this.SUB_KEY_WORD[0]; // Table 0
      tempSBox[j + 1] = this.SUB_KEY_WORD[1]; // Table 1
      tempSBox[0x200 + j] = this.SUB_KEY_WORD[2]; // Table 2
      tempSBox[0x201 + j] = this.SUB_KEY_WORD[3]; // Table 3
    }
    this.s_Box = tempSBox;
    this.s_Keys = tempSKeys;
  }

  protected generateSubKeys({
    keyWords,
    numKeyBlocks64,
    tempSKeys,
  }: {
    keyWords: number[];
    numKeyBlocks64: number;
    tempSKeys: Uint32Array;
  }) {
    const [k0, k1, k2, k3, k4, k5, k6, k7] = keyWords;
    let combinedLeft: number; // holds the XOR combination of 4 words generated
    let combinedRight: number; //holds the XOR combination of 4 words from the odd key words (k1, k3, k5, k7) with substitution bytes, then bit-rotated left by 8 bits.
    for (let i = 0, q = 0, j = 0; i < this.SUB_KEY_CNT / 2; i++, j += 2) {
      // Calculate the substitution bytes from the current q value for use in key mixing
      const subByte0 = TwoFishUtils.substitutionMixer(q, 'b0');
      const subByte1 = TwoFishUtils.substitutionMixer(q, 'b1');
      const subByte2 = TwoFishUtils.substitutionMixer(q, 'b2');
      const subByte3 = TwoFishUtils.substitutionMixer(q, 'b3');

      // Generate the first subkey word using even indexed key words (k0, k2, k4, k6)
      // This applies permutations and substitutions to produce the intermediate subkey word parts
      TwoFishUtils.getSubKeyWord({
        numKeyBlocks64,
        keyWord0: k0,
        keyWord1: k2,
        keyWord2: k4,
        keyWord3: k6,
        subByte0,
        subByte1,
        subByte2,
        subByte3,
        subKeyWord: this.SUB_KEY_WORD,
      });
      // is  this.SUB_KEY_WORD mutated ??
      // test if subkey is mutated

      // XOR the left key
      combinedLeft =
        this.SUB_KEY_WORD[0] ^
        this.SUB_KEY_WORD[1] ^
        this.SUB_KEY_WORD[2] ^
        this.SUB_KEY_WORD[3];
      // Increment for next round of substitution
      q += this.SK_STEP;

      // Generate the second subkey word using odd indexed key words (k1, k3, k5, k7)
      TwoFishUtils.getSubKeyWord({
        numKeyBlocks64,
        keyWord0: k1,
        keyWord1: k3,
        keyWord2: k5,
        keyWord3: k7,
        subByte0,
        subByte1,
        subByte2,
        subByte3,
        subKeyWord: this.SUB_KEY_WORD,
      });
      // XOR the right key
      combinedRight =
        this.SUB_KEY_WORD[0] ^
        this.SUB_KEY_WORD[1] ^
        this.SUB_KEY_WORD[2] ^
        this.SUB_KEY_WORD[3];
      q += this.SK_STEP;
      combinedRight = (combinedRight << 8) | (combinedRight >>> 24);
      combinedLeft += combinedRight;
      tempSKeys[j] = combinedLeft;
      combinedLeft += combinedRight;
      // Store the second subkey, after rotation, into the temporary subkeys array
      tempSKeys[j + 1] =
        (combinedLeft << this.SK_ROTL) | (combinedLeft >>> (32 - this.SK_ROTL));
    }
  }
  public rsMDSEncode(keyWord0: number, keyWord1: number): number {
    // Initial step + 3 more steps (total 4)
    keyWord1 = TwoFishUtils.reedSolomonTransformStep(keyWord1);
    for (let i = 0; i < 3; i++) {
      keyWord1 = TwoFishUtils.reedSolomonTransformStep(keyWord1);
    }
    // XOR with keyWord0
    keyWord1 ^= keyWord0;

    // 4 more steps after XOR
    for (let i = 0; i < 4; i++) {
      keyWord1 = TwoFishUtils.reedSolomonTransformStep(keyWord1);
    }

    return keyWord1 >>> 0; // ensure unsigned 32-bit result
  }
}
