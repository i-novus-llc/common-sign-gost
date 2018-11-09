package ru.i_novus.common.sign.util;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import ru.i_novus.common.sign.api.SignAlgorithmType;

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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

@Slf4j
public class CryptoIO {
    private static final int BUFFER_SIZE = 1024;

    private CryptoIO() {
        // don't instantiate
    }

    public static CryptoIO getInstance() {
        return new CryptoIO();
    }

    @SneakyThrows
    public PKCS8EncodedKeySpec readPkFromDER(final String keyPath) {
        byte[] data = Files.readAllBytes(Paths.get(keyPath));
        return new PKCS8EncodedKeySpec(data);
    }

    @SneakyThrows
    public PrivateKey readPkFromPEM(final Path keyPath, SignAlgorithmType algorithmType) {
        byte[] data = Files.readAllBytes(keyPath);
        return CryptoFormatConverter.getInstance().getPKFromPEMEncoded(algorithmType, new String(data));
    }

    @SneakyThrows
    public X509CertificateHolder readCertFromDER(final String crtPath) {
        byte[] data = Files.readAllBytes(Paths.get(crtPath));
        return new X509CertificateHolder(data);
    }

    @SneakyThrows
    public X509Certificate readCertFromPEM(final Path crtPath) {
        byte[] data = Files.readAllBytes(crtPath);
        return CryptoFormatConverter.getInstance().getCertificateFromPEMEncoded(new String(data));
    }

    @SneakyThrows
    public String writeCertToDERFile(final X509CertificateHolder certificateHolder, final Path path) {
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
    public String writePKToDERFile(final KeyPair keyPair, final Path path) {
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
    public PrivateKey readPrivateKeyFromPKCS12(Path filePath, String keystorePass) {
        return readPrivateKeyFromPKCS12(Files.newInputStream(filePath), keystorePass);
    }

    @SneakyThrows
    public PrivateKey readPrivateKeyFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore ks = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(inputStream, keystorePass == null ? null : keystorePass.toCharArray());

        String alias = ks.aliases().nextElement();

        return (PrivateKey) ks.getKey(alias, keystorePass == null ? null : keystorePass.toCharArray());
    }

    @SneakyThrows
    public X509Certificate readCertificateFromPKCS12(Path filePath, String keystorePass) {
        return readCertificateFromPKCS12(Files.newInputStream(filePath), keystorePass);
    }

    @SneakyThrows
    public X509Certificate readCertificateFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore ks = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(inputStream, keystorePass == null ? null : keystorePass.toCharArray());

        String alias = ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        return (X509Certificate) chain[chain.length - 1];
    }

    @SneakyThrows
    public void createPkcs12File(Path filePath, String password, PrivateKey privateKey, X509Certificate[] chain) {
        if (chain.length == 0) {
            throw new IllegalArgumentException("Cannot build PKCS12 without certificates");
        }

        PublicKey publicKey = chain[0].getPublicKey();
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBag[] safeBags = new PKCS12SafeBag[chain.length];
        for (int i = chain.length - 1; i >= 0; i--) {
            PKCS12SafeBagBuilder certBagBuilder = new JcaPKCS12SafeBagBuilder(chain[i]);
            if (i == 0) {
                certBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(publicKey));
            }
            safeBags[i] = certBagBuilder.build();
        }
/*
        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);

        taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Primary Certificate"));

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);

        caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Intermediate Certificate"));

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);

        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(publicKey));
*/

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privateKey,
                new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(password.toCharArray()));

//        keyBagBuilder.addBagAttribute(PKCSObjectIdentбifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(publicKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

        pfxPduBuilder.addEncryptedData(
                new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(password.toCharArray()), safeBags);

        pfxPduBuilder.addData(keyBagBuilder.build());

        PKCS12PfxPdu pfx = pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), password.toCharArray());
        try (OutputStream stream = Files.newOutputStream(filePath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
             stream.write(pfx.getEncoded());
        }
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
