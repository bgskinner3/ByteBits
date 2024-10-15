import { TWO_FISH_CONSTANTS } from './constants';
import { TwoFishSession } from '../types/two-fish';
import { TwoFish } from './two-fish';

export class TwoFishEncryptDecrypt {
  // public ROUNDS = TWO_FISH_CONSTANTS.ROUNDS
  // public ROUND_SUB_KEYS = TWO_FISH_CONSTANTS.ROUND_SUBKEYS
  private MAXPASSWLEN = TwoFish.MAXKEYLENGTH >> 1;
  private twoFish: TwoFish | null = null;
  private HEXTAB = TWO_FISH_CONSTANTS.HEXTAB;
  constructor(password: string) {
    this.initSessionKey(password);
  }

  private initSessionKey(passphrase: string) {
    const encoder = new TextEncoder();
    let key = encoder.encode(passphrase); // Convert string to Uint8Array

    // Truncate if the key is too long
    const keyLength = key.length;
    if (keyLength > this.MAXPASSWLEN) {
      key = key.subarray(0, 32); // Truncate to 32 bytes if too long
    } else {
      // Calculate the padding needed to make the key length a multiple of 8
      const mod = keyLength % 8;

      if (keyLength === 0 || mod !== 0) {
        const paddingLength = 8 - mod; // Add padding to make the length a multiple of 8
        const paddedKey = new Uint8Array(keyLength + paddingLength);
        paddedKey.set(key); // Set the original key
        key = paddedKey; // Now, key is padded
      }
    }
    this.twoFish = new TwoFish(key);

    // keyLength <<= 1;
    // for (position = 0; position < nLength; position++) {
    //   bkey[position] = 0;
    // }
  }
  private charToSigned8BitInt(char: string): number {
    const charCode = char.charCodeAt(0);
    // Apply bitwise AND with 0xff to keep only the least sigindexficant 8 bits
    let result = charCode & 0xff;
    // If the result is greater than 127, subtract 256 to make it a signed value
    if (result > 127) {
      result -= 256;
    }
    return result;
  }
  private setCharAt(ins: string, position: number, chr: string): string {
    const result = [];
    if (position > 0) {
      result.push(ins.substring(0, position));
    }
    result.push(chr);

    if (position < ins.length) {
      result.push(ins.substring(position + 1, ins.length));
    }

    return result.join('');
  }
  public encryptString(sPlainText: string): string {
    // calculate a CRC for the text string and append it onto the string delimited with a |
    // if (this._CRCEncryption) {
    //     sPlainText += '|' + this.calculateCRC(sPlainText);
    //   }

    // allocate the buffer (align to the next 8 byte border)
    const originLength: number = sPlainText.length;
    let length: number = sPlainText.length;

    let buf: Uint8Array = new Uint8Array();

    // one character equals two bytes
    if ((length & 3) !== 0) {
      length = (length & ~3) + 4;
    }
    buf = new Uint8Array(length << 1);

    // copy all bytes of the string into the buffer (use network byte order)
    let position = 0;
    for (let index = 0; index < length; index++) {
      let char;
      // pad with blanks if the index is less htan the original length
      index < originLength ? (char = sPlainText[index]) : (char = ' ');
      if (index < originLength) {
        char = sPlainText[index];
      } else {
        char = ' ';
      }
      // we have to convert the character to a 8-bit signed intger
      const siginedInt8Bit = this.charToSigned8BitInt(char);
      buf[position++] = (siginedInt8Bit >> 8) & 0x0ff;
      buf[position++] = siginedInt8Bit & 0x0ff;
    }
    console.log(buf, sPlainText);
    this.twoFish?.encrypt(buf);

    // convert the buffer content back to a binhex string
    length <<= 1;

    let sbuf: string = ' '.repeat(length << 1);
    position = 0;
    for (let index = 0; index < length; index++) {
      sbuf = this.setCharAt(
        sbuf,
        position++,
        this.HEXTAB[(buf[index] >> 4) & 0x0f],
      );
      sbuf = this.setCharAt(sbuf, position++, this.HEXTAB[buf[index] & 0x0f]);
    }
    console.log(sbuf.toString(), 'SHITTTT encrypt');
    return sbuf.toString();
  }

  public decryptString(sCipherText: string): string {
    let nLength = sCipherText.length & ~15;
    // if (_CRCDecryption === false) {
    //   this._CRCDecryption = false;
    // }
    // if (this._CRCDecryption) {
    //   if (nLength !== sCipherText.length) {
    //     return '';
    //   }
    // }

    nLength >>= 1;

    const buf: Uint8Array = new Uint8Array(nLength);
    let position = 0;
    for (let index = 0; index < nLength; index++) {
      let bActByte = 0;
      for (let nJ = 0; nJ < 2; nJ++) {
        bActByte <<= 4;
        const cActChar = sCipherText[position++];
        if (cActChar >= 'A' && cActChar <= 'F') {
          bActByte |= cActChar.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
        } else if (cActChar >= '0' && cActChar <= '9') {
          bActByte |= cActChar.charCodeAt(0) - '0'.charCodeAt(0);
        }
      }
      buf[index] = bActByte;
    }

    this.twoFish?.decrypt(buf);
    nLength >>= 1;

    let sbuf: string = ' '.repeat(nLength);

    position = 0;

    // GETTING the 8-bit ASCII character
    for (let index = 0; index < nLength; index++) {
      const left = ((buf[position] << 8) & 0xff00) >>> 0;
      const right = (buf[position + 1] & 0xff) >>> 0;

      sbuf = this.setCharAt(sbuf, index, String.fromCharCode(left | right));

      position += 2;
    }
    console.log(sbuf.toString(), 'SHITTTT decrypt');

    return '';
  }
}
