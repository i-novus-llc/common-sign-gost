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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import static ru.i_novus.common.sign.util.Base64Util.getBase64Decoded;
import static ru.i_novus.common.sign.util.Base64Util.getBase64EncodedString;

@Slf4j
public class CryptoFormatConverter {
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
    @SneakyThrows
    public String getPEMEncodedCertificate(X509Certificate certificate) {
        return getBase64EncodedString(CryptoIO.getInstance().writeCertToByteArray(new JcaX509CertificateHolder(certificate)));
    }

    /**
     * Convert PEM encoded certificate to X509Certificate
     *
     * @param pemEncodedCertificate PEM encoded certificate
     * @return certificate in {@link X509Certificate} format
     */
    @SneakyThrows
    public X509Certificate getCertificateFromPEMEncoded(String pemEncodedCertificate) {
        return (X509Certificate) CertificateFactory.getInstance("X.509", CryptoUtil.CRYPTO_PROVIDER_NAME).
                generateCertificate(new ByteArrayInputStream(decodePem(pemEncodedCertificate)));
    }

    @SneakyThrows
    public X509Certificate getCertificateFromHolder(X509CertificateHolder certificateHolder) {
        JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();
        jcaConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return jcaConverter.getCertificate(certificateHolder);
    }

    /**
     * Convert PEM encoded private key to {@link PrivateKey} instance
     *
     * @param signAlgorithmType signature algorithm
     * @param pemEncodedKey PEM encoded private key
     * @return private key in {@link PrivateKey} format
     */
    @SneakyThrows
    public PrivateKey getPKFromPEMEncoded(SignAlgorithmType signAlgorithmType, String pemEncodedKey) {
        return KeyFactory.getInstance(signAlgorithmType.getBouncyKeyAlgorithmName(), CryptoUtil.CRYPTO_PROVIDER_NAME)
                .generatePrivate(new PKCS8EncodedKeySpec(decodePem(pemEncodedKey)));
    }

    /**
     * Convert PKCS#12 to PEM encoded certificate
     *
     * @param pfxFileEncoded PKCS#12(PFX) file encoded
     * @return certificate in PEM format
     */
    @SneakyThrows
    public String getPEMEncodedCertificateFromPKCS12(String pfxFileEncoded, String keystorePass){
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxFileEncoded))) {
            X509Certificate x509Certificate = CryptoIO.getInstance().readCertificateFromPKCS12(inputStream, keystorePass);
            return getPEMEncodedCertificate(x509Certificate);
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
