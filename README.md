## Blowfish Data Encryption

The Blowfish Algorithim is a two way encryption method that enables data to be passed securely if both entities share the same pboxes, sboxes and encryption key word. Here

## Table of Contents

- [Usage](#usage)
  - [Example](#example)

## Usage

All input data plaintext and ciphertext should be a `String`. Strings support all unicode including emoji ✨.

## ENVs

```
The encryption key is your seed phrase
BLOWFISH_ENCRYPTION=

When incorporating personalized 
PBOX_INIT=
SBOX_INIT_1=
SBOX_INIT_2=
SBOX_INIT_3=
SBOX_INIT_4=
```
## S & P Boxes

P-boxes and S-boxes are fundamental components of the Blowfish encryption algorithm, responsible for performing key transformations and data substitution. Custom P-boxes and S-boxes allow you to replace the default values with your own, adding unpredictability and potentially improving security.

### How to Define Custom Boxes

- Environment Variables allow you to define custom values for P-boxes and S-boxes. These values are provided in a comma-separated hexadecimal format, and will override default static values if set. 

### Example:

```ts
PBOX_INIT=0x00000000,0x00000000,...,0x00000000
SBOX_INIT_1=0x00000000,0x00000000,...,0x00000000
SBOX_INIT_2=0x00000000,0x00000000,...,0x00000000
SBOX_INIT_3=0x00000000,0x00000000,...,0x00000000
SBOX_INIT_4=0x00000000,0x00000000,...,0x00000000
```
----

### Fallback to Static Boxes

If environment variables are not provided, the system will automatically fallback to predefined static P-box and S-box values derived from π (pi). This ensures the algorithm can still function securely even if custom values are not set.



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
