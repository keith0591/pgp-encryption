package com.malkeith.pgpUtils;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Objects;

@Getter
@Builder
@AllArgsConstructor
public class PgpEncryptionUtil {

    static {
        // Add Bouncy castle to JVM
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Builder.Default
    private int compressionAlgorithm = CompressionAlgorithmTags.ZIP;
    @Builder.Default
    private int symmetricKeyAlgorithm = SymmetricKeyAlgorithmTags.AES_128;
    @Builder.Default
    private boolean armor = true;
    @Builder.Default
    private boolean withIntegrityCheck = true;
    @Builder.Default
    private int bufferSize = 1 << 16;


    public void encrypt(OutputStream encryptOut, InputStream clearIn, long length, InputStream publicKeyIn)
            throws IOException, PGPException {
        PGPCompressedDataGenerator compressedDataGenerator =
                new PGPCompressedDataGenerator(compressionAlgorithm);
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
                // This bit here configures the encrypted data generator
                new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );
        // Adding public key
        pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(
                CommonUtils.getPublicKey(publicKeyIn)));
        if (armor) {
            encryptOut = new ArmoredOutputStream(encryptOut);
        }
        OutputStream cipherOutStream = pgpEncryptedDataGenerator.open(encryptOut, new byte[bufferSize]);
        CommonUtils.copyAsLiteralData(compressedDataGenerator.open(cipherOutStream), clearIn, length, bufferSize);
        // Closing all output streams in sequence
        compressedDataGenerator.close();
        cipherOutStream.close();
        encryptOut.close();
    }

    public byte[] encrypt(byte[] clearData, InputStream pubicKeyIn) throws PGPException, IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(clearData);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        encrypt(outputStream, inputStream, clearData.length, pubicKeyIn);
        return outputStream.toByteArray();
    }

    public InputStream encrypt(InputStream clearIn, long length, InputStream publicKeyIn)
            throws IOException, PGPException {
        File tempFile = File.createTempFile("pgp-", "-encrypted");
        encrypt(Files.newOutputStream(tempFile.toPath()), clearIn, length, publicKeyIn);
        return Files.newInputStream(tempFile.toPath());
    }

    public byte[] encrypt(byte[] clearData, String publicKeyStr) throws PGPException, IOException {
        return encrypt(clearData, IOUtils.toInputStream(publicKeyStr, Charset.defaultCharset()));
    }

    public InputStream encrypt(InputStream clearIn, long length, String publicKeyStr) throws IOException, PGPException {
        return encrypt(clearIn, length, IOUtils.toInputStream(publicKeyStr, Charset.defaultCharset()));
    }


}
