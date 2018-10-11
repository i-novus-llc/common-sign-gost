package ru.i_novus.common.sign.util;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.i_novus.common.sign.Init;

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
     * Получает закрытый ключ PKCS#8 или сертификат из PEM-формата
     *
     * @param pemEncoded данные в base64 (PEM-формат в base64)
     * @return закрытый ключ PKCS#8 либо сертификат
     */
    private byte[] decodePem(final String pemEncoded) {
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
