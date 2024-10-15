# Data Encryption Library

This repository serves as a comprehensive collection of encryption methods implemented in TypeScript. It provides tested, documented, and reusable implementations of various cryptographic algorithms, designed to help developers integrate encryption into their applications easily and securely. While this library is continuously maintained and improved, it currently includes the following encryption methods:

- ### Blowfish
- ### TwoFish \*(in progress)

<br />

<br />

# I. Blowfish Data Encryption

The Blowfish Algorithm is a two-way encryption method that enables secure data transmission when both entities share the same pboxes, sboxes, and encryption key. It operates by using key-dependent permutations of its internal structures, ensuring the encryption and decryption processes are closely tied to the specific key. This method ensures confidentiality and is widely used for its efficiency in various applications requiring fast and secure encryption.

<br />

In this implementation, we also incorporate Cyclic Redundancy Check (CRC) as an integrity verification step. Before encryption, a CRC checksum is calculated for the plaintext and appended to it. This ensures that the data can be verified for integrity after decryption, providing an additional layer of security by detecting any modifications or corruption of the encrypted data.

## Table of Contents

- [Usage](#usage)
  - [Example](#example)
  - [ENVs](#envs)
  - [S & P boxes overview](#s&pboxes)

## Usage

All input data plaintext and ciphertext should be a `String`. Strings support all unicode including emoji ✨.

## ENVs

```
BLOWFISH_ENCRYPTION=
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

---

### Fallback to Static Boxes

If environment variables are not provided, the system will automatically fallback to predefined static P-box and S-box values derived from π (pi). This ensures the algorithm can still function securely even if custom values are not set.

### Security Considerations

Custom P-boxes and S-boxes can increase security by introducing additional complexity and reducing the predictability of the encryption. However, they don't guarantee perfect security. Always ensure the values used are random, cryptographically strong, and managed securely.

### Performance Impact

Using custom P-boxes and S-boxes may introduce a minor performance overhead, especially during initialization, as the system parses the environment variables and loads custom values. Performance benchmarks are recommended if this is a concern.

---

### Minor Example implementation

```ts
import { BlowfishHandler } from '--- when you put it ---';

/*
The key can be optional if there is a .env set 
*/
const bf = new BlowfishHandler('a4MJr12|hTiDOad');

const encoded = bf.encryptData('input text even with emoji 🎅');
const decoded = bf.decryptData(encoded);
```

# II. TwoFish Data Encryption

## Table of Contents

### WIP
