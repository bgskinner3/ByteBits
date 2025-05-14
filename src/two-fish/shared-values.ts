export class TwoFishSharedValues {
  static P0: Uint8Array = this.parseUnit8Boxes(process.env.P0 ?? '');
  static P1: Uint8Array = this.parseUnit8Boxes(process.env.P1 ?? '');
  static MDS0: Uint32Array = this.parseUnit32Boxes(process.env.MDS0 ?? '');
  static MDS1: Uint32Array = this.parseUnit32Boxes(process.env.MDS1 ?? '');
  static MDS2: Uint32Array = this.parseUnit32Boxes(process.env.MDS2 ?? '');
  static MDS3: Uint32Array = this.parseUnit32Boxes(process.env.MDS3 ?? '');

  private static parseUnit32Boxes(envVariable: string) {
    let ENVHexdigits = envVariable ? envVariable : new Uint32Array();

    if (typeof ENVHexdigits === 'string') {
      ENVHexdigits = new Uint32Array(ENVHexdigits.split(',').map(Number));
    }

    return ENVHexdigits;
  }
  private static parseUnit8Boxes(envVariable: string) {
    let ENVHexdigits = envVariable ? envVariable : new Uint8Array();

    if (typeof ENVHexdigits === 'string') {
      ENVHexdigits = new Uint8Array(ENVHexdigits.split(',').map(Number));
    }

    return ENVHexdigits;
  }
}
