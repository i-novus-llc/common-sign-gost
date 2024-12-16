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

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class CryptoIO {
    private static final Logger logger = LoggerFactory.getLogger(CryptoIO.class);
    private static final int BUFFER_SIZE = 1024;

    private CryptoIO() {
        // don't instantiate
    }

    public static CryptoIO getInstance() {
        return new CryptoIO();
    }

    public PKCS8EncodedKeySpec readPkFromPKCS8(final String keyPath) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(keyPath));
            return new PKCS8EncodedKeySpec(data);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read PK from PKCS8", e);
        }
    }

    public PrivateKey readPrivateKey(InputStream input) throws IOException, GeneralSecurityException {
        PEMParser pemReader = new PEMParser(new InputStreamReader(input));

        /*
         * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm
         * OID and use that to construct a KeyFactory.
         */
        PrivateKeyInfo pki = (PrivateKeyInfo) pemReader.readObject();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pki.getEncoded());

        String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
        return KeyFactory.getInstance(algOid).generatePrivate(spec);
    }

    public PrivateKey readPkFromPEM(final Path keyPath, SignAlgorithmType algorithmType) {
        try {
            byte[] data = Files.readAllBytes(keyPath);
            return CryptoFormatConverter.getInstance().getPKFromPEMEncoded(algorithmType, new String(data));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read key from path '" + keyPath + "'", e);
        }
    }

    public X509CertificateHolder readCertFromDER(final String crtPath) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(crtPath));
            return new X509CertificateHolder(data);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read certificate from path '" + crtPath + "'", e);
        }
    }

    public X509Certificate readCertFromPEM(final Path crtPath) {
        try {
            byte[] data = Files.readAllBytes(crtPath);
            return CryptoFormatConverter.getInstance().getCertificateFromPEMEncoded(new String(data));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read certificate from path '" + crtPath + "'", e);
        }
    }

    public String writeCertToDERFile(final X509CertificateHolder certificateHolder, final Path path) {
        try {
            if (path.toFile().exists()) {
                Files.delete(path);
            }
            try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
                fos.write(certificateHolder.getEncoded());
            }
            return path.toString();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write certificate to path '" + path + "' in DER", e);
        }
    }

    public byte[] writeCertToByteArray(final X509CertificateHolder certificateHolder) {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(certificateHolder.getEncoded());
            return stream.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot convert certificate to byte array", e);
        }
    }

    public String writePKToPKCS8File(final KeyPair keyPair, final Path path) {
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            fos.write(pkcs8EncodedKeySpec.getEncoded());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write PK to file '" + path + "'", e);
        }
        return path.toString();
    }

    public byte[] writePKToByteArray(PrivateKey privateKey) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        try {
            stream.write(pkcs8EncodedKeySpec.getEncoded());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write PKCS8 encoded key to byte array", e);
        }
        return stream.toByteArray();
    }

    public PrivateKey readPrivateKeyFromPKCS12(Path filePath, String keystorePass) {
        try {
            return readPrivateKeyFromPKCS12(Files.newInputStream(filePath), keystorePass);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read file '" + filePath + "'", e);
        }
    }

    public KeyStore getPkcs12KeyStore(InputStream inputStream, String keystorePass) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
            keyStore.load(inputStream, keystorePass == null ? null : keystorePass.toCharArray());
            return keyStore;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchProviderException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Cannot read private key from keystore", e);
        }
    }

    public PrivateKey readPrivateKeyFromPKCS12(KeyStore keyStore, String keystorePass) {
        String alias;
        try {
             alias = keyStore.aliases().nextElement();
        } catch (KeyStoreException e) {
            throw new IllegalArgumentException("Keystore is invalid. Cannot read certificate chain", e);
        }
        try {
            return (PrivateKey) keyStore.getKey(alias, keystorePass == null ? null : keystorePass.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new IllegalArgumentException("Cannot read private key from keystore", e);
        }
    }

    public X509Certificate readCertificateFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore keyStore = getPkcs12KeyStore(inputStream, keystorePass);
        return readCertificateFromPKCS12(keyStore);
    }

    public X509Certificate readCertificateFromPKCS12(KeyStore keyStore) {
        try {
            String alias = keyStore.aliases().nextElement();
            Certificate[] chain = keyStore.getCertificateChain(alias);
            return (X509Certificate) chain[chain.length - 1];
        } catch (KeyStoreException e) {
            throw new IllegalArgumentException("Keystore is invalid. Cannot read certificate chain", e);
        }
    }

    public PrivateKey readPrivateKeyFromPKCS12(InputStream inputStream, String keystorePass) {
        KeyStore keyStore = getPkcs12KeyStore(inputStream, keystorePass);
        return readPrivateKeyFromPKCS12(keyStore, keystorePass);
    }

    public X509Certificate readCertificateFromPKCS12(Path filePath, String keystorePass) {
        try {
            return readCertificateFromPKCS12(Files.newInputStream(filePath), keystorePass);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read file '" + filePath + "'", e);
        }
    }

    public void createPkcs12File(Path filePath, String password, PrivateKey privateKey, X509Certificate[] chain) {

        PKCS12PfxPdu pfx = createPkcs12PfxPdu(password, privateKey, chain);

        try (OutputStream stream = Files.newOutputStream(filePath,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            stream.write(pfx.getEncoded());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String createPkcs12FileEncoded(String password, PrivateKey privateKey, X509Certificate[] chain) {
        try {
            PKCS12PfxPdu pfx = createPkcs12PfxPdu(password, privateKey, chain);
            return Base64Util.getBase64EncodedString(pfx.getEncoded());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create Pkcs12File", e);
        }
    }

    public PKCS12PfxPdu createPkcs12PfxPdu(String password, PrivateKey privateKey, X509Certificate[] chain) {
        if (chain.length == 0) {
            throw new IllegalArgumentException("Cannot build PKCS12 without certificates");
        }

        PublicKey publicKey = chain[0].getPublicKey();
        JcaX509ExtensionUtils extUtils = null;
        try {
            extUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Cannot find algorithm 'SHA1'", e);
        }

        PKCS12SafeBag[] safeBags = new PKCS12SafeBag[chain.length];
        for (int i = chain.length - 1; i >= 0; i--) {
            PKCS12SafeBagBuilder certBagBuilder = null;
            try {
                certBagBuilder = new JcaPKCS12SafeBagBuilder(chain[i]);
            } catch (IOException e) {
                throw new UncheckedIOException("Cannot init certificate chain entry", e);
            }
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

        try {
            pfxPduBuilder.addEncryptedData(
                    new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                            new CBCBlockCipher(new RC2Engine())).build(password.toCharArray()), safeBags);

            pfxPduBuilder.addData(keyBagBuilder.build());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot build PFX", e);
        }

        try {
            return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), password.toCharArray());
        } catch (PKCSException e) {
            throw new RuntimeException("Cannot build PFX container", e);
        }
    }

    /**
     * Convert input stream to byte array using default buffer size
     *
     * @param inputStream input stream
     * @return byte array
     */
    public byte[] inputStreamToByteArray(InputStream inputStream) {
        try {
            return inputStreamToByteArray(inputStream, BUFFER_SIZE);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read input stream", e);
        }
    }

    /**
     * Convert input stream to byte array
     *
     * @param inputStream input stream
     * @param bufferSize  buffer size to process data
     * @return byte array
     */
    public byte[] inputStreamToByteArray(InputStream inputStream, int bufferSize) throws IOException {
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
