package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.MessageFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Slf4j
public class CryptoUtil {

    public static final String CRYPTO_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CryptoUtil() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Формирование ключевой пары по заданным алгоритмам
     *
     * @param signAlgorithmType тип алгоритма
     * @param parameterSpecName наименование спецификации параметров алгоритма
     * @return ключевая пара (открытый и закрытый ключи)
     * @throws NoSuchAlgorithmException           указанный алгоритм не найден
     * @throws NoSuchProviderException            криптопровайдер "Bouncy castle" не инициализирован
     * @throws InvalidAlgorithmParameterException неверное наименование спецификации параметров алгоритма
     */
    public static KeyPair generateKeyPair(final SignAlgorithmType signAlgorithmType, final String parameterSpecName) throws
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        logger.info("Generating keypair, signAlgorithm: {}, parameterSpecName: {}", signAlgorithmType, parameterSpecName);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(signAlgorithmType.getBouncyKeyAlgorithmName(), CRYPTO_PROVIDER_NAME);
        String selectedParamSpec = getParamSpec(signAlgorithmType, parameterSpecName);

        logger.info("selected parameter specification name: {}", selectedParamSpec);
        if (selectedParamSpec != null) {
            keyGen.initialize(new ECNamedCurveGenParameterSpec(selectedParamSpec), new SecureRandom());
        }

        return keyGen.generateKeyPair();
    }

    private static String getParamSpec(final SignAlgorithmType signAlgorithmType, final String parameterSpecName) {
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
        return selectedParamSpec;
    }

    /**
     * Формирование сертификата в формате X.509 на основе переданной ключевой пары
     *
     * @param x509Name      основные параметры сертификата (должно быть как минимум указано значение CN)
     * @param keyPair       ключевая пара, для которой формируется сертификат
     * @param signAlgorithm алгоритм подписи
     * @param validFrom     момент времени, с которого будет действителен формируемый сертификат. Если передано null, берется текущее время
     * @param validTo       момент времени, до которого будет действителен формируемый сертификат. Если передано null, берется текущее время + 1 год
     * @return данные сертификата в формате X.509
     * @throws IOException               оишбка записи данных в формат сертификата
     * @throws OperatorCreationException ошибка формирования сертификата
     */
    public static X509CertificateHolder selfSignedCertificate(String x509Name, KeyPair keyPair, SignAlgorithmType signAlgorithm,
                                                              Date validFrom, Date validTo)
            throws IOException, OperatorCreationException {
        X500Name name = new X500Name(x509Name);
        AsymmetricKeyParameter privateKeyParameter = null;
        AsymmetricKeyParameter publicKeyParameter = null;
        if (keyPair.getPublic() instanceof ECPublicKey) {
            ECPublicKey k = (ECPublicKey) keyPair.getPublic();
            ECParameterSpec s = k.getParameters();
            publicKeyParameter = new ECPublicKeyParameters(
                    k.getQ(),
                    new ECDomainParameters(s.getCurve(), s.getG(), s.getN()));

            ECPrivateKey kk = (ECPrivateKey) keyPair.getPrivate();
            ECParameterSpec ss = kk.getParameters();

            privateKeyParameter = new ECPrivateKeyParameters(
                    kk.getD(),
                    new ECDomainParameters(ss.getCurve(), ss.getG(), ss.getN()));
        } else if (keyPair.getPublic() instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey) keyPair.getPublic();
            publicKeyParameter = new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent());

            RSAPrivateKey kk = (RSAPrivateKey) keyPair.getPrivate();
            privateKeyParameter = new RSAKeyParameters(true, kk.getModulus(), kk.getPrivateExponent());
        }

        if (publicKeyParameter == null)
            return null;

        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                name,
                BigInteger.ONE,
                validFrom == null ? new Date() : validFrom,
                validTo == null ? new Date(LocalDateTime.now().plusYears(1).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()) : validTo,
                name,
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter));

        DefaultSignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier signAlgId = signatureAlgorithmIdentifierFinder.find(signAlgorithm.getSignatureAlgorithmName());
        AlgorithmIdentifier digestAlgId = digestAlgorithmIdentifierFinder.find(signAlgId);

        BcContentSignerBuilder signerBuilder;
        if (keyPair.getPublic() instanceof ECPublicKey) {
            signerBuilder = new BcECContentSignerBuilder(signAlgId, digestAlgId);
        } else {
            signerBuilder = new BcRSAContentSignerBuilder(signAlgId, digestAlgId);
        }

        int val = KeyUsage.cRLSign;
        val = val | KeyUsage.dataEncipherment;
        val = val | KeyUsage.decipherOnly;
        val = val | KeyUsage.digitalSignature;
        val = val | KeyUsage.encipherOnly;
        val = val | KeyUsage.keyAgreement;
        val = val | KeyUsage.keyEncipherment;
        val = val | KeyUsage.nonRepudiation;
        myCertificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(val));

        myCertificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        myCertificateGenerator.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        return myCertificateGenerator.build(signerBuilder.build(privateKeyParameter));
    }

    /**
     * Формирует хэш данных и кодирует его в base64
     *
     * @param data входные данные
     * @return хэш в base64
     */
    public static String getBase64Digest(String data, SignAlgorithmType signAlgorithmType) {
        return new String(Base64.getEncoder().encode(getDigest(data.getBytes(), signAlgorithmType)));
    }

    /**
     * Формирует хэш данных для заданного алгоритма
     *
     * @param data входные данные
     * @return хэш в base64
     */
    public static byte[] getDigest(byte[] data, SignAlgorithmType signAlgorithmType) {
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
        digest.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);
        return resBuf;
    }

    /**
     * Создание CMS подписи по ГОСТ 34.10
     *
     * @param data        входные данные в виде массива байт
     * @param privateKey  закрытый ключ
     * @param certificate сертификат ЭП
     * @return подпись
     * @throws GeneralSecurityException  исключении о невозможности использования переданного ключа и алгоритма подписи с поддерживаемым криптопровайдером
     * @throws CMSException              исключение о невозможности формирования подписи CMS по предоставленным данным
     * @throws OperatorCreationException исключении о невозможнсти использования указаного ключа ЭП
     * @throws IOException               исключение при формировании массива байт из объекта класса CMSSignedData
     */
    public static byte[] getCMSSignature(byte[] data, PrivateKey privateKey, X509Certificate certificate) throws GeneralSecurityException, IOException, CMSException, OperatorCreationException {
        List<X509Certificate> certList = new ArrayList<>();
        CMSTypedData msg = new CMSProcessableByteArray(data);
        certList.add(certificate);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder(certificate.getSigAlgName()).setProvider(CRYPTO_PROVIDER_NAME).build(privateKey);

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                .setProvider(CRYPTO_PROVIDER_NAME).build()).build(signer, certificate));

        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, false);
        return sigData.getEncoded();
    }

    /**
     * Подписывает данные ЭП по ГОСТ 34.10
     *
     * @param data              входные данные в виде массива байт
     * @param privateKey        закрытый ключ
     * @param signAlgorithmType параметры алгоритма подписи
     * @return подпись
     * @throws GeneralSecurityException исключении о невозможности использования переданного ключа и алгоритма подписи с поддерживаемым криптопровайдером
     */
    public static byte[] getSignature(byte[] data, PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(signAlgorithmType.getSignatureAlgorithmName(), CRYPTO_PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Подписывает данные ЭП по ГОСТ 34.10 и кодирует ее в base64
     *
     * @param data              входные данные
     * @param key               закрытый ключ в base64
     * @param signAlgorithmType параметры алгоритма подписи
     * @return подпись в base64
     * @throws GeneralSecurityException исключении о невозможности использования переданного ключа и алгоритма подписи с поддерживаемым криптопровайдером
     */
    public static String getBase64Signature(String data, String key, SignAlgorithmType signAlgorithmType) throws GeneralSecurityException {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodePem(key));
        PrivateKey privateKey = KeyFactory.getInstance(signAlgorithmType.getBouncyKeyAlgorithmName(), CRYPTO_PROVIDER_NAME).generatePrivate(privateKeySpec);
        byte[] signBytes = getSignature(data.getBytes(), privateKey, signAlgorithmType);
        return new String(Base64.getEncoder().encode(signBytes));
    }

    /**
     * Получает закрытый ключ PKCS#8 из PEM-формата
     *
     * @param key закрытый ключ в base64 (PEM-формат в base64)
     * @return закрытый ключ PKCS#8
     */
    public static byte[] decodePem(final String key) {
        String pem = key;
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
