# Kalo encryption method

### AES Implementation

## 📌 Implementation Checklist

---

### I. 🔍 Research & Planning (Ongoing)

- ✅ Determine overall encryption strategy: K1 + K2 key split
- ✅ Decide on encoding format for encrypted output (e.g., base64, hex)
- ✅ Plan obfuscation mechanism for embedding K2 (invisible chars, delimiters, Unicode)
- ❌ Decide on integrity check method (CRC32, SHA256 hash, HMAC)
- ❌ Research UX patterns for encryption tools / user engagement
- ❌ Identify edge cases (e.g., empty message, emoji input, control characters)
- ❌ Define limits: max message length, valid cover text input, supported char sets
- ❌ Explore multilingual character handling and normalization (NFC/NFD)

---

### II. 🔐 Core AES-based `EncryptionMethodBase`

- ✅ Stub `AESEncryption` class and key expansion framework
- ✅ Add AES constants: S-box, inverse S-box, round constants
- ✅ Validate AES key format (length, hex string, byte array, etc.)
- ✅ Implement `expandKey()` function to generate all round keys
- ✅ Implement AES encryption core:
  - `encryptBlock()`, `addRoundKey()`, `subBytes()`, `shiftRows()`, `mixColumns()`
- ✅ Implement AES decryption core (inverse operations)
- ✅ Add CTR mode

---

### III. 🧬 Key Handling Logic (K1 + K2)

- ✅ Plan structure of K1 (derived from passphrase or shared protocol key)
- ✅ Define strategy to derive K1 (e.g., SHA256 of passphrase)
- ✅ K2: Randomly generated per message
- ❌ Implement `embedK2InCoverText(k2, coverText)`
- ❌ Implement `extractK2FromCoverText(coverText)`
- ❌ Ensure K2 obfuscation preserves message readability
- ❌ Encode K2 using zero-width characters, invisible delimiters, or fake emoji

---

### IV. 🔎 Message Handling & Validation

- ❌ Add checksum/hash (e.g., SHA256, CRC32) to message payload
- ❌ Verify hash during decryption to detect tampering
- ❌ Normalize all inputs (NFC) to ensure consistency across devices
- ❌ Support multilingual input (Unicode emoji, symbols, RTL text)
- ❌ Fallback handling for invalid K2 or corrupted embedded key
- ❌ Validate decrypted message matches expectations (length, format)
- ❌ Expose high-level `encryptMessage()` and `decryptMessage()` with K1+K2

---

### V. 🧪 Testing & Hardening

- ❌ Add static test vectors (known input/output pairs)
- ❌ Test with random data of varying length and encoding
- ❌ Simulate corrupted message / missing K2 scenarios
- ❌ Benchmark performance: short, medium, long messages
- ❌ Harden against brute-force (slow KDF, entropy requirements)
- ❌ Security review of obfuscation method for K2

---

### VI. 🎨 UX / DX Enhancements

- ❌ CLI or UI prototype for encrypt/decrypt cycle
- ❌ Show embedded K2 with toggle visibility (developer/debug mode)
- ❌ Add clear copy/share UX for final encoded message
- ❌ Option to “validate message” before full decryption
- ❌ Document usage patterns, examples, and warnings

---

## MUST DO

- Update all test units for each method

# Notes

## COUNTER MODE (CTR)

### 🔐 Step-by-Step: Encryption

Let's say you're encrypting this plaintext:  
`"HELLO_WORLD"`

---

### Step One

**Choose a Key and a random IV (called a nonce here)**

The nonce ensures each encryption is unique even if the same key is reused.

```typescript
key = your 128- or 256-bit AES key
nonce = random 128-bit (or shorter) value, e.g. 12 bytes

```

---

### Step Two

**Initialize a counter block:**  
Example: `[ nonce | counter ]`

```typescript
counter_0 = nonce + 0;
counter_1 = nonce + 1;
counter_2 = nonce + 2;
```

### Step Three

**For each plaintext block:**

1. Encrypt the counter using AES:

```typescript
encrypted_counter = AES(key, counter_i);
```

2. XOR the result with your plaintext block:

```typescript
cipher_block = encrypted_counter ^ plaintext_block;
```

3. Increment the counter:

```typescript
counter_i++;
```

# Benefits of CTR

## Parallel Processing

CTR mode allows for parallel encryption. Since each block depends only on the nonce and counter (which are independent of the plaintext), the blocks can be processed simultaneously. This significantly improves performance compared to modes like CBC, where each block depends on the previous one.

---

## Efficient for Streaming Data

CTR is ideal for streaming data encryption, as it turns AES into a stream cipher. It can encrypt arbitrary-length data without needing padding, unlike ECB or CBC. This makes it especially useful for our application, where we may handle varying-length inputs like user messages, files, and real-time data.

---

## No Padding

In CTR mode, no padding is necessary. This simplifies the encryption process since it avoids dealing with padding schemes (like PKCS7) required in modes like CBC or ECB.

---

## Reduced Risk of IV Reuse

CTR mode uses a nonce and counter combination, which reduces the risk of IV reuse. As long as the nonce is unique for each encryption, the encryption process is safe from the vulnerability of IV repetition, which is a concern in CBC mode.

---

## Better for High-Throughput Applications

Since CTR mode allows encryption in parallel and works efficiently with long data streams, it is better suited for high-throughput applications like ours. Whether encrypting files, messages, or data streams, CTR mode can scale efficiently without bottlenecks.

---

## Security Considerations

While CTR mode provides robust security, its strength heavily depends on never reusing the nonce with the same key. In our application, we ensure the nonce is randomly generated and unique per encryption, mitigating potential vulnerabilities that can arise from nonce reuse.
