//the boxes to init data
// we take the seed phrase and get the correct sequence
// TODO:
// it might be better to create them at runtime to make the class
// file smaller, e.g. by calculating the hexdigits of pi (default)
//  or just a fixed random sequence (out of the standard)

// Changed the pboxes and sboxes which produce the (Key Expansion) as an
// env variable for added layer of security.
// will handle these env variables differently when we have DB
// Speak with johnnie

export class BlowfishSharedVar {
  /**
   allowed keys for the memberInfo Cookie
   this will serve as a home for all keys to monitor for decryption
   */

  static pbox_init: Uint32Array = this.parseENVBoxes(process.env.PBOX_INIT);
  static sbox_init_1: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_1);
  static sbox_init_2: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_2);
  static sbox_init_3: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_3);
  static sbox_init_4: Uint32Array = this.parseENVBoxes(process.env.SBOX_INIT_4);

  private static parseENVBoxes(envVariable?: string): Uint32Array {
    let ENVHexdigits = envVariable ? envVariable : new Uint32Array();

    if (typeof ENVHexdigits === 'string') {
      ENVHexdigits = new Uint32Array(ENVHexdigits.split(',').map(Number));
    }

    return ENVHexdigits;
  }
}
