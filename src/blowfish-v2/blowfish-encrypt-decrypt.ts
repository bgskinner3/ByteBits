import { Blowfish } from './blowfish';

export class BlowfishEncryptDecrypt {
  private MAXPASSWLEN = Blowfish.MAXKEYLENGTH >> 1;
  private bfish: Blowfish | null = null;

  // our hex
  private HEXTAB = '0123456789ABCDEF';
  // to determine whether or not to use the CRC value
  // will possibly need later
  private _CRCDecryption: boolean = true;
  private _CRCEncryption: boolean = true;

  constructor(password: string) {
    this.initalize(password);
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

  private initalize(password: string) {
    // allocate the key buffer
    let nLength = password.length;
    if (nLength > this.MAXPASSWLEN) {
      nLength = this.MAXPASSWLEN;
    }
    const bkey = new Uint8Array(nLength << 1);

    // get all bytes of the key in network byte order
    let position = 0;
    let index;

    for (index = 0; index < nLength; index++) {
      const cActChar: string = password[index];
      // we have to convert the character to a 8-bit signed intger
      const siginedInt8Bit = this.charToSigned8BitInt(cActChar);

      bkey[position++] = (siginedInt8Bit >> 8) & 0x0ff;
      bkey[position++] = siginedInt8Bit & 0x0ff;
    }

    // setup the encryptor
    this.bfish = new Blowfish(bkey);

    // clear the key buffer
    nLength <<= 1;
    for (position = 0; position < nLength; position++) {
      bkey[position] = 0;
    }
  }

  private calculateCRC(text: string): number {
    const temp = Buffer.from(text, 'ascii');
    let count = 0;
    for (let i = 0; i < temp.length; i++) {
      count += temp[i];
    }
    return count;
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

  public decryptString(sCipherText: string, _CRCDecryption?: boolean): string {
    let nLength = sCipherText.length & ~15;
    if (_CRCDecryption === false) {
      this._CRCDecryption = false;
    }
    if (this._CRCDecryption) {
      if (nLength !== sCipherText.length) {
        return '';
      }
    }

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

    this.bfish?.decrypt(buf);
    // convert the buffer back to a string
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

    let result = '';
    if (this._CRCDecryption) {
      const temp = sbuf.toString();
      const CRCIndex = temp.lastIndexOf('|');
      const wordIndex = temp.indexOf('|');

      if (CRCIndex > 0) {
        try {
          const tempcrc: string = temp
            .substring(CRCIndex + 1, temp.length)
            .trim();

          const oldCRC: number = parseInt(tempcrc, 10);

          const newText = temp.substring(0, wordIndex);
          const newCRC = this.calculateCRC(newText);

          if (newCRC === oldCRC) {
            result = newText;
          }
        } catch (error) {
          result = '';
        }
      } else {
        result = '';
      }
    } else {
      result = sbuf.toString();
    }

    return result;
  }
  /**
   * encrypts a string (in 100% unicode mode)
   * @param sPlainText string to encrypt
   * @return encrypted string in binhex format
   */
  public encryptString(sPlainText: string): string {
    // calculate a CRC for the text string and append it onto the string delimited with a |
    if (this._CRCEncryption) {
      sPlainText += '|' + this.calculateCRC(sPlainText);
    }

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

    this.bfish?.encrypt(buf);

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

    return sbuf.toString();
  }
}
