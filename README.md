# pgp-encryption
Utility to encrypt and decrypt anything (bytes, file, streams) with pgp encryption

## How to use:

The best way is to look at the test class `PgpEncryptionTest`. But I have shared some quick snippets below if you are in a hurry

For a detailed explanation of how the utility works go [here]( https://medium.com/@kthsingh.ms/encrypt-and-decrypt-anything-bytes-files-streams-with-pgp-using-bouncy-castle-and-java-ad335ae9f747 "Medium")

### Encryption:
First instantiate a `PgpEncryptionUtil` object like so:
```groovy
PgpEncryptionUtil pgpEncryptionUtil = PgpEncryptionUtil.builder()
                                      .armor(true)
                                      .compressionAlgorithm(CompressionAlgorithmTags.ZIP)
                                      .symmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_128)
                                      .withIntegrityCheck(true)
                                      .build();                                      
```
To encrypt bytes call:

```groovy
byte[] encryptedBytes = pgpEncryptionUtil.encrypt(bytesToEncrypt, publicKey)
```

To encrypt inputstream call:

```groovy
InputStream encryptedIn = pgpEncryptionUtil.encrypt(<inputstreamToEncrypt>, lengthOfInputstreamToEncrypt, publicKey);
```

To encrypt file use:

```groovy
pgpEncryptionUtil.encrypt(fileOutputstream, fileInputstream, fileLength, publicKey))
```

### Decryption:

First instantiate a `PgpDecryptionUtil` object like so:

```groovy
 PgpDecryptionUtil pgpDecryptionUtil = new PgpDecryptionUtil(privateKey, passKey);
```

To decrypt bytes call:

```groovy
 byte[] decryptedBytes = pgpDecryptionUtil.decrypt(encryptedBytes);
```

To decrypt files / inputstreams call:

```groovy
 pgpDecryptionUtil.decrypt(encryptedIn, fileOutputstream);
```
