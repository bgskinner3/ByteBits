import { TWO_FISH_CONSTANTS } from "./constants";
import { TwoFishSession } from "../types/two-fish";
import { TwoFish } from "./two-fish";



export class TwoFishEncryptDecrypt {
    // public ROUNDS = TWO_FISH_CONSTANTS.ROUNDS
    // public ROUND_SUB_KEYS = TWO_FISH_CONSTANTS.ROUND_SUBKEYS
    private MAXPASSWLEN = TwoFish.MAXKEYLENGTH >> 1
    private twoFish: TwoFish | null = null;

    constructor(password: string) {
        this.initSessionKey(password);
    }



    private initSessionKey(passphrase: string) {
        const encoder = new TextEncoder();
        let key = encoder.encode(passphrase);  // Convert string to Uint8Array

        // Truncate if the key is too long
        const keyLength = key.length;
        if (keyLength > this.MAXPASSWLEN) {
            key = key.subarray(0, 32);  // Truncate to 32 bytes if too long
        } else {
            // Calculate the padding needed to make the key length a multiple of 8
            const mod = keyLength % 8;

            if (keyLength === 0 || mod !== 0) {
                const paddingLength = 8 - mod;  // Add padding to make the length a multiple of 8
                const paddedKey = new Uint8Array(keyLength + paddingLength);
                paddedKey.set(key);  // Set the original key
                key = paddedKey;  // Now, key is padded
            }
        }
        this.twoFish = new TwoFish(key);

        // keyLength <<= 1;
        // for (position = 0; position < nLength; position++) {
        //   bkey[position] = 0;
        // }
    }













 
}