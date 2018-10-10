package ru.i_novus.common.sign.util;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.i_novus.common.sign.Init;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class CryptoIO {
    private static final int BUFFER_SIZE = 1024;

    private CryptoIO() {
        Init.init();
    }

    public static CryptoIO getInstance() {
        return new CryptoIO();
    }

    @SneakyThrows
    public PKCS8EncodedKeySpec readPkFromDer(final String keyPath) {
        byte[] data = Files.readAllBytes(Paths.get(keyPath));
        return new PKCS8EncodedKeySpec(data);
    }

    @SneakyThrows
    public X509CertificateHolder readCertFromDer(final String crtPath) {
        byte[] data = Files.readAllBytes(Paths.get(crtPath));
        return new X509CertificateHolder(data);
    }

    @SneakyThrows
    public String writeCertToFile(final X509CertificateHolder certificateHolder, final Path path) {
        if (path.toFile().exists()) {
            Files.delete(path);
        }
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            fos.write(certificateHolder.getEncoded());
        }
        return path.toString();
    }

    @SneakyThrows
    public byte[] writeCertToByteArray(final X509CertificateHolder certificateHolder) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(certificateHolder.getEncoded());
        return stream.toByteArray();
    }

    @SneakyThrows
    public String writePKToFile(final KeyPair keyPair, final Path path) {
        if (path.toFile().exists()) {
            Files.delete(path);
        }
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            fos.write(pkcs8EncodedKeySpec.getEncoded());
        }
        return path.toString();
    }

    @SneakyThrows
    public byte[] writePKToByteArray(PrivateKey privateKey) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        stream.write(pkcs8EncodedKeySpec.getEncoded());
        return stream.toByteArray();
    }

    @SneakyThrows
    public PrivateKey readPrivateKeyFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore ks = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(inputStream, keystorePass == null ? null : keystorePass.toCharArray());

        String alias = ks.aliases().nextElement();

        return (PrivateKey) ks.getKey(alias, keystorePass == null ? null : keystorePass.toCharArray());
    }

    @SneakyThrows
    public X509Certificate readCertificateFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore ks = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(inputStream, keystorePass == null ? null : keystorePass.toCharArray());

        String alias = ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        return (X509Certificate) chain[chain.length - 1];
    }

    /**
     * Get data in byte array format from Base64 byte array format
     *
     * @param data Base64 byte array representation of data
     * @return data in byte array format
     */
    public byte[] getBase64Decoded(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    /**
     * Get data in byte array format from Base64 string format
     *
     * @param data Base64 String representation
     * @return data in byte array format
     */
    public byte[] getBase64Decoded(String data) {
        return getBase64Decoded(data.getBytes());
    }

    /**
     * Get Base64 byte array for data in byte array format
     *
     * @param data input data
     * @return Base64 encoded data in byte array representation
     */
    public byte[] getBase64Encoded(byte[] data) {
        return Base64.getEncoder().encode(data);
    }

    /**
     * Get Base64 string for data in byte array format
     *
     * @param data input data
     * @return Base64 String representation
     */
    public String getBase64EncodedString(byte[] data) {
        return new String(getBase64Encoded(data));
    }

    /**
     * Convert input stream to byte array using default buffer size
     *
     * @param inputStream input stream
     * @return byte array
     */
    @SneakyThrows
    public byte[] inputStreamToByteArray(InputStream inputStream) {
        return inputStreamToByteArray(inputStream, BUFFER_SIZE);
    }

    /**
     * Convert input stream to byte array
     *
     * @param inputStream input stream
     * @param bufferSize buffer size to process data
     * @return byte array
     */
    @SneakyThrows
    public byte[] inputStreamToByteArray(InputStream inputStream, int bufferSize) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[bufferSize];
        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        return buffer.toByteArray();
    }
}
