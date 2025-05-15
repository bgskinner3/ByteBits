# ByteBits — Multi-Language Encryption Library

ByteBits is a comprehensive repository housing a collection of robust, well-tested encryption algorithms implemented across different programming languages. This project includes both widely recognized cryptographic standards—such as Blowfish, Twofish, and AES—as well as custom-built encryption methods developed from the ground up.

Designed for developers seeking reliable and reusable encryption solutions, ByteBits provides documented, maintainable, and secure implementations to help integrate strong data protection into your applications with ease. The repository is actively maintained and expanded to cover more algorithms and enhancements.

## Included Encryption Methods

- Blowfish
- Twofish
- AES (CTR Mode)
- Custom-built algorithms

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

<br />

<br />

<br />

# II. TwoFish Data Encryption

TwoFish is the successor and spiritual successor to the Blowfish encryption algorithm, designed to improve upon Blowfish’s strengths while addressing its limitations. Developed by renowned cryptographers as a finalist for the Advanced Encryption Standard (AES) competition, TwoFish offers enhanced security features, greater flexibility with key sizes up to 256 bits, and improved performance.

Building on the foundation laid by Blowfish, TwoFish incorporates advanced techniques such as key-dependent S-boxes, a Feistel network, and a more complex key schedule. This makes it more resistant to modern cryptanalytic attacks while maintaining the efficiency and versatility that made Blowfish popular.

In this implementation, we deliver a robust TypeScript-based TwoFish encryption module designed for secure and efficient data encryption in modern applications.

<br />

<br />

<br />

# III. AES Data Encryption (CTR Mode)

The AES (Advanced Encryption Standard) algorithm is a symmetric key encryption method used widely across modern cryptographic systems. In this library, we implement AES using **CTR (Counter) mode**, which converts the block cipher into a stream cipher—ideal for encrypting data of arbitrary length.

CTR mode works by combining a unique **nonce** (number used once) and a counter value with each block of plaintext using AES encryption. The resulting keystream is XORed with the plaintext to produce the ciphertext. For decryption, the same process is reversed using the original nonce and counter value.

<br />

## Key Features

- AES-CTR mode for high performance and stream support.
- Stateless and symmetric encryption/decryption.
- Optional custom nonces or automatic nonce generation.
- Supports `Uint8Array` input/output for flexible binary handling.
- Supports `unicoded` encryption and emojis

<br />

## Table of Contents

- [Usage](#usage-1)
  - [Example](#example-1)
  - [Nonce Handling](#nonce-handling)
- [Benefits of CTR with AES][#]
- [Security Considerations](#security-considerations-1)

<br />

## Usage

All encryption inputs and outputs are handled as `Uint8Array`, allowing compatibility with binary protocols, file buffers, or custom string encodings.

> 🔐 AES CTR requires the same nonce and counter value for decryption. You must **store or transmit** the nonce securely along with the encrypted output.

---

### Example

```ts
import { AESHandler } from '@your-lib-path/aes';

const key = crypto.getRandomValues(new Uint8Array(16)); // AES-128
const aes = new AESHandler(key);

const data = new TextEncoder().encode('Secret Message ✉️');

const { cipherText, nonce } = aes.encrypt(data);

const decrypted = aes.decrypt(cipherText, nonce);
console.log(new TextDecoder().decode(decrypted)); // "Secret Message ✉️"
```

## Benefits of CTR with AES

CTR (Counter) mode brings several advantages to AES encryption, especially for modern applications that require speed, scalability, and flexibility. Here's why it's a strong choice for this library:

---

### 🚀 Parallel Processing

Unlike modes like CBC, where each block depends on the previous one, CTR mode allows blocks to be encrypted independently. This enables **parallel processing**, significantly improving performance on multi-core systems or when handling large data sets.

---

### Efficient for Streaming Data

CTR transforms AES into a stream cipher, allowing encryption of data with **arbitrary length** and without block alignment constraints. This is perfect for applications like:

- Real-time messaging
- Live data feeds
- Encrypted file uploads or downloads

---

### No Padding Required (thank the heaves!)

CTR mode eliminates the need for padding schemes like PKCS7. This:

- Simplifies the implementation
- Avoids padding-related bugs or attacks
- Maintains a consistent ciphertext length relative to the input

---

### 🧷 Lower IV Misuse Risk

Instead of a traditional IV (Initialization Vector), CTR mode uses a **nonce + counter** pair. As long as the nonce is **unique per encryption**, reuse vulnerabilities (which plague modes like CBC) are avoided.

> 🔐 Nonce uniqueness is critical. Never reuse the same nonce-key pair.

---

### ⚙️ High Throughput & Scalability

CTR's structure makes it ideal for **high-throughput** applications:

- Scales easily with parallelism
- Suitable for large file or batch encryption
- Performs well in real-world web and server applications

---

# Security Considerations

While CTR mode provides robust security, its strength heavily depends on never reusing the nonce with the same key. In our application, we ensure the nonce is randomly generated and unique per encryption, mitigating potential vulnerabilities that can arise from nonce reuse.
