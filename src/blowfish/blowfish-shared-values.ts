
import { BLOWFISH_CONSTANTS } from "./constants";
/**
It might be better to create them at runtime to make the class
file smaller, e.g. by calculating the hexdigits of pi (default)
 or just a fixed random sequence (out of the standard)

Changed the pboxes and sboxes which produce the (Key Expansion) as an
------
The boxes to init data
we take the seed phrase and get the correct sequence
Changed the pboxes and sboxes which produce the (Key Expansion) as an
env variable for added layer of security.

 */
export class BlowfishSharedVar {
  private static OPTIMIZED_DEFAULT_HEX = BLOWFISH_CONSTANTS.OPTIMIZED_DEFAULT_HEX
  static parsedBoxes: { p: Uint32Array; s: Uint32Array[] } = BlowfishSharedVar.parseStaticBoxes();
  static pbox_init: Uint32Array = this.parseENVBoxes(process.env.PBOX_INIT, 'pbox_init');
  static sbox_init_1: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_1, 'sbox_init_1');
  static sbox_init_2: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_2, 'sbox_init_2');
  static sbox_init_3: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_3, 'sbox_init_3');
  static sbox_init_4: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_4, 'sbox_init_4');




  private static parseENVBoxes(envVariable?: string, boxName?: 'pbox_init' | 'sbox_init_1' | 'sbox_init_2' | 'sbox_init_3' | 'sbox_init_4'): Uint32Array {
    // If the environment variable exists, parse it
    if (envVariable) {
      return new Uint32Array(envVariable.split(',').map(hex => parseInt(hex, 16)));
    }

    // Otherwise, return fallback from parsedBoxes
    if (boxName === 'pbox_init') {
      return this.parsedBoxes.p;
    } else {
      // Use shift to return each sbox sequentially
      const sboxIndex = { 'sbox_init_1': 0, 'sbox_init_2': 1, 'sbox_init_3': 2, 'sbox_init_4': 3 }[boxName!];
      const res = this.parsedBoxes.s[sboxIndex!];
   
      return res
    }
  }
  private static parseStaticBoxes(): { p: Uint32Array; s: Uint32Array[] } {
    const boxes: { p: Uint32Array; s: Uint32Array[] } = {
      p: new Uint32Array(18),  // Array of 18 elements
      s: [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)], // Four arrays of 256 elements each
    };

    let piPos = 0;


    for (let i = 0; i < 18; i++) {
      const elemHex = this.OPTIMIZED_DEFAULT_HEX.substring(piPos, piPos + 8);
      piPos += 8;
      boxes.p[i] = Number(`0x${elemHex}`);
    }

    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 256; j++) {
        const elemHex = this.OPTIMIZED_DEFAULT_HEX.substring(piPos, piPos + 8);
        piPos += 8;
        boxes.s[i][j] = Number(`0x${elemHex}`);
      }
    }

    return boxes;
  }

}

// export class BlowfishSharedVar {
//   static pbox_init: Uint32Array = this.parseENVBoxes(process.env.PBOX_INIT);
//   static sbox_init_1: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_1);
//   static sbox_init_2: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_2);
//   static sbox_init_3: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_3);
//   static sbox_init_4: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_4);

//   private static parseENVBoxes(envVariable?: string): Uint32Array {
//     let ENVHexdigits = envVariable ? envVariable : new Uint32Array();

//     if (typeof ENVHexdigits === 'string') {
//       ENVHexdigits = new Uint32Array(ENVHexdigits.split(',').map(Number));
//     }

//     return ENVHexdigits;
//   }
// }
