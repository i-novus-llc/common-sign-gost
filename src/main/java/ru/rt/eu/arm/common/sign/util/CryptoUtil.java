package ru.rt.eu.arm.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.MessageFormat;
import java.util.Base64;

@Slf4j
public final class CryptoUtil {

    public static final String CRYPTO_PROVIDER_NAME = "BC";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CryptoUtil() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static KeyPair generateKeyPair(final SignAlgorithmType signAlgorithmType, final String parameterSpecName) throws
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(signAlgorithmType.bouncyKeyAlgorithmName(), CRYPTO_PROVIDER_NAME);

        String selectedParamSpec = null;
        if (parameterSpecName == null) {
            if (!signAlgorithmType.getAvailableParameterSpecificationNames().isEmpty()) {
                selectedParamSpec = signAlgorithmType.getAvailableParameterSpecificationNames().get(0);
            }
        } else {
            if (!signAlgorithmType.getAvailableParameterSpecificationNames().contains(parameterSpecName)) {
                throw new IllegalArgumentException(MessageFormat.format(
                        "Parameter specification name {0} is not supported for algorithm {1}. Supported values: {2}",
                        parameterSpecName, signAlgorithmType.name(), signAlgorithmType.getAvailableParameterSpecificationNames()));
            } else {
                selectedParamSpec = parameterSpecName;
            }
        }

        logger.info("selected parameter specification name: {}", selectedParamSpec);
        if (selectedParamSpec != null) {
            keyGen.initialize(ECGOST3410NamedCurveTable.getParameterSpec(selectedParamSpec));
        }

        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey priv = keyPair.getPrivate();
        PublicKey pub = keyPair.getPublic();
        String privateKey = new String(Base64.getEncoder().encode(priv.getEncoded()));
        String publicKey1 = new String(Base64.getEncoder().encode(pub.getEncoded()));
        String publicKey = new String(Base64.getEncoder().encode(publicKey1.getBytes()));

        logger.info("privateKey: {}", privateKey);
        logger.info("publicKey1: {}", publicKey1);
        logger.info("publicKey: {}", publicKey);

        return keyPair;
    }

    /**
     * Формирует хэш данных и кодирует его в base64
     *
     * @param data входные данные
     * @return хэш в base64
     */
    public static String getBase64Digest(String data, SignAlgorithmType signAlgorithmType) {
        ExtendedDigest digest;
        switch (signAlgorithmType) {
            case ECGOST3410:
                digest = new GOST3411Digest();
                break;
            case ECGOST3410_2012_256:
                digest = new GOST3411_2012_256Digest();
                break;
            case ECGOST3410_2012_512:
                digest = new GOST3411_2012_512Digest();
                break;
            default:
                throw new IllegalArgumentException("Unsupported Digest Algorithm: " + signAlgorithmType);
        }
        digest.update(data.getBytes(), 0, data.getBytes().length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);
        return new String(Base64.getEncoder().encode(resBuf));
    }

    /**
     * Подписывает данные ЭЦП по ГОСТ 34.10 и кодирует ее в base64
     *
     * @param data              входные данные
     * @param key               закрытый ключ в base64
     * @param signAlgorithmType параметры алгоритма подписи
     * @return подпись в base64
     * @throws GeneralSecurityException исключении о невозможности использования переданного ключа и алгоритма подписи с поддерживаемым криптопровайдером
     */
    public static String getBase64Signature(String data, String key, SignAlgorithmType signAlgorithmType) throws GeneralSecurityException {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodePem(key));
        PrivateKey privateKey = KeyFactory.getInstance(signAlgorithmType.bouncyKeyAlgorithmName(), CRYPTO_PROVIDER_NAME).generatePrivate(privateKeySpec);
        Signature signature = Signature.getInstance(signAlgorithmType.bouncySignatureAlgorithmName(), CRYPTO_PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signBytes = signature.sign();
        return new String(Base64.getEncoder().encode(signBytes));
    }

    /**
     * Получает закрытый ключ PKCS#8 из PEM-формата
     *
     * @param key закрытый ключ в base64 (PEM-формат в base64)
     * @return закрытый ключ PKCS#8
     */
    public static byte[] decodePem(String key) {
        String pem = new String(Base64.getDecoder().decode(key), StandardCharsets.UTF_8);
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
        return Base64.getDecoder().decode(pem.replaceAll("\\r\\n|\\n", ""));
    }

    public static String getThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return hexify(digest);
    }

    private static String hexify(byte[] data) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder(data.length * 2);
        for (byte aByte : data) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }
}
