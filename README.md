## Blowfish Data Encryption

The Blowfish Algorithim is a two way encryption method that enables data to be passed securely if both entities share the same pboxes, sboxes and encryption key word. Here

## Table of Contents

- [Usage](#usage)
  - [Example](#example)

## Usage

All input data plaintext and ciphertext should be a `String`. Strings support all unicode including emoji ✨.

### ENVs

```
BLOWFISH_ENCRYPTION=
PBOX_INIT=
SBOX_INIT_1=
SBOX_INIT_2=
SBOX_INIT_3=
SBOX_INIT_4=
```

### Example

```ts
import { BlowfishHandler } from '--- when you put it ---';

/*
The key can be optional if there is a .env set 
*/
const bf = new BlowfishHandler('a4MJr12|hTiDOad');

const encoded = bf.encryptData('input text even with emoji 🎅');
const decoded = bf.decryptData(encoded);
```
