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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static ru.i_novus.common.sign.util.Base64Util.getBase64Decoded;
import static ru.i_novus.common.sign.util.Base64Util.getBase64EncodedString;

public class CryptoFormatConverter {
    private static final Logger logger = LoggerFactory.getLogger(CryptoFormatConverter.class);

    private CryptoFormatConverter() {
        Security.addProvider(new BouncyCastleProvider());
        Init.init();
    }

    /**
     * Create an instance of CryptoFormatConverter object
     *
     * @return CryptoFormatConverter instance
     */
    public static CryptoFormatConverter getInstance() {
        return new CryptoFormatConverter();
    }

    /**
     * Convert X509Certificate to PEM encoded
     *
     * @param certificate certificate
     * @return certificate in PEM format
     */
    public String getPEMEncodedCertificate(X509Certificate certificate) {
        try {
            return getBase64EncodedString(CryptoIO.getInstance().writeCertToByteArray(new JcaX509CertificateHolder(certificate)));
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("Cannot convert certificate to PEM", e);
        }
    }

    /**
     * Convert PEM encoded certificate to X509Certificate
     *
     * @param pemEncodedCertificate PEM encoded certificate
     * @return certificate in {@link X509Certificate} format
     */
    public X509Certificate getCertificateFromPEMEncoded(String pemEncodedCertificate) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509", CryptoUtil.CRYPTO_PROVIDER_NAME).
                    generateCertificate(new ByteArrayInputStream(decodePem(pemEncodedCertificate)));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Cannot convert certificate from PEM", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider is unknown", e);
        }
    }

    public X509Certificate getCertificateFromHolder(X509CertificateHolder certificateHolder) {
        JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();
        jcaConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        try {
            return jcaConverter.getCertificate(certificateHolder);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Cannot receive certificate from Holder", e);
        }
    }

    /**
     * Convert PEM encoded private key to {@link PrivateKey} instance
     *
     * @param signAlgorithmType signature algorithm
     * @param pemEncodedKey PEM encoded private key
     * @return private key in {@link PrivateKey} format
     */
    public PrivateKey getPKFromPEMEncoded(SignAlgorithmType signAlgorithmType, String pemEncodedKey) {
        try {
            return KeyFactory.getInstance(signAlgorithmType.getBouncyKeyAlgorithmName(), CryptoUtil.CRYPTO_PROVIDER_NAME)
                    .generatePrivate(new PKCS8EncodedKeySpec(decodePem(pemEncodedKey)));
        } catch (NoSuchProviderException e) {
            throw new IllegalArgumentException ("Provider is not initialized", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + signAlgorithmType + " is not supported", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Wrong private key", e);
        }
    }

    /**
     * Convert PKCS#12 to PEM encoded certificate
     *
     * @param pfxFileEncoded PKCS#12(PFX) file encoded
     * @return certificate in PEM format
     */
    public String getPEMEncodedCertificateFromPKCS12(String pfxFileEncoded, String keystorePass){
        byte[] decoded = Base64Util.getBase64Decoded(pfxFileEncoded);
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(decoded)) {
            X509Certificate x509Certificate = CryptoIO.getInstance().readCertificateFromPKCS12(inputStream, keystorePass);
            return getPEMEncodedCertificate(x509Certificate);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Получает закрытый ключ PKCS#8 или сертификат из PEM-формата
     *
     * @param pemEncoded данные в base64 (PEM-формат в base64)
     * @return закрытый ключ PKCS#8 либо сертификат
     */
    public static byte[] decodePem(final String pemEncoded) {
        String pem = pemEncoded;
        try {
            pem = pem.replace(pem.substring(pem.indexOf("-----END"), pem.lastIndexOf("-----") + 5), "");
        } catch (Exception ignore) {
            //NOP
        }
        try {
            pem = pem.replace(pem.substring(pem.indexOf("-----BEGIN"), pem.lastIndexOf("-----") + 5), "");
        } catch (Exception ignore) {
            //NOP
        }
        return getBase64Decoded(pem.replaceAll("\\r\\n|\\n", ""));
    }
}
