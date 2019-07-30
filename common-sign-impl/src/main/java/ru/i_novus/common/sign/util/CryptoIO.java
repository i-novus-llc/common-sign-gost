package ru.i_novus.common.sign.util;

/*-
 * -----------------------------------------------------------------
 * common-sign-gost
 * -----------------------------------------------------------------
 * Copyright (C) 2018 - 2019 I-Novus LLC
 * -----------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------
 */

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
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
    public PKCS8EncodedKeySpec readPkFromPKCS8(final String keyPath) {
        byte[] data = Files.readAllBytes(Paths.get(keyPath));
        return new PKCS8EncodedKeySpec(data);
    }

    public PrivateKey readPrivateKey(InputStream input) throws IOException, GeneralSecurityException {
//        byte[] bytes = inputStreamToByteArray(input);
        PEMParser pemReader = new PEMParser(new InputStreamReader(input));

        /*
         * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm
         * OID and use that to construct a KeyFactory.
         */
        PrivateKeyInfo pki = (PrivateKeyInfo)pemReader.readObject();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pki.getEncoded());

        String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
        return KeyFactory.getInstance(algOid).generatePrivate(spec);
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
    public String writePKToPKCS8File(final KeyPair keyPair, final Path path) {
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
    public KeyStore getPkcs12KeyStore(InputStream inputStream, String keystorePass) {
        KeyStore keyStore = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(inputStream, keystorePass == null ? null : keystorePass.toCharArray());
        return keyStore;
    }

    @SneakyThrows
    public PrivateKey readPrivateKeyFromPKCS12(KeyStore keyStore, String keystorePass) {
        final String alias = keyStore.aliases().nextElement();
        return (PrivateKey) keyStore.getKey(alias, keystorePass == null ? null : keystorePass.toCharArray());
    }

    @SneakyThrows
    public X509Certificate readCertificateFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore keyStore = getPkcs12KeyStore(inputStream, keystorePass);
        return readCertificateFromPKCS12(keyStore);
    }

    @SneakyThrows
    public X509Certificate readCertificateFromPKCS12(KeyStore keyStore) {
        String alias = keyStore.aliases().nextElement();
        Certificate[] chain = keyStore.getCertificateChain(alias);
        return (X509Certificate) chain[chain.length - 1];
    }

    @SneakyThrows
    public PrivateKey readPrivateKeyFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore keyStore = getPkcs12KeyStore(inputStream, keystorePass);
        return readPrivateKeyFromPKCS12(keyStore, keystorePass);
    }

    @SneakyThrows
    public X509Certificate readCertificateFromPKCS12(Path filePath, String keystorePass) {
        return readCertificateFromPKCS12(Files.newInputStream(filePath), keystorePass);
    }

    @SneakyThrows
    public void createPkcs12File(Path filePath, String password, PrivateKey privateKey, X509Certificate[] chain) {

        PKCS12PfxPdu pfx = createPkcs12PfxPdu(password, privateKey, chain);

        try (OutputStream stream = Files.newOutputStream(filePath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
             stream.write(pfx.getEncoded());
        }
    }

    @SneakyThrows
    public String createPkcs12FileEncoded(String password, PrivateKey privateKey, X509Certificate[] chain) {
        PKCS12PfxPdu pfx = createPkcs12PfxPdu(password, privateKey, chain);
        return Base64Util.getBase64EncodedString(pfx.getEncoded());
    }

    @SneakyThrows
    public PKCS12PfxPdu createPkcs12PfxPdu(String password, PrivateKey privateKey, X509Certificate[] chain) {

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

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privateKey,
                new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(password.toCharArray()));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(publicKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

        pfxPduBuilder.addEncryptedData(
                new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(password.toCharArray()), safeBags);

        pfxPduBuilder.addData(keyBagBuilder.build());

        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), password.toCharArray());
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
