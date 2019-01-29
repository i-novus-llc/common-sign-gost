package ru.i_novus.common.sign.util;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey;
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
import ru.i_novus.common.sign.api.SignAlgorithmType;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static ru.i_novus.common.sign.util.Base64Util.getBase64EncodedString;

@Slf4j
public class CryptoUtil {
    static final String CRYPTO_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private static final int BUFFER_SIZE = 1024;

    private CryptoUtil() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Формирование ключевой пары по заданным алгоритмам
     *
     * @param signAlgorithmType тип алгоритма
     * @param parameterSpecName наименование спецификации параметров алгоритма
     * @return ключевая пара (открытый и закрытый ключи)
     */
    @SneakyThrows
    public static KeyPair generateKeyPair(final SignAlgorithmType signAlgorithmType, final String parameterSpecName) {
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
     */
    @SneakyThrows
    public static X509CertificateHolder selfSignedCertificate(String x509Name, KeyPair keyPair, SignAlgorithmType signAlgorithm,
                                                              Date validFrom, Date validTo) {
        X500Name name = new X500Name(x509Name);
        AsymmetricKeyParameter privateKeyParameter = null;
        AsymmetricKeyParameter publicKeyParameter = null;

        BigInteger serial = BigInteger.ONE; // serial number for self-signed does not matter a lot

        Date notBefore = validFrom == null ? new Date() : validFrom;
        Date notAfter = validTo == null ? new Date(LocalDateTime.now().plusYears(1).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()) : validTo;

        X509v3CertificateBuilder certificateBuilder = null;

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

            certificateBuilder = new JcaX509v3CertificateBuilder(
                    name, serial,
                    notBefore,
                    notAfter,
                    name, keyPair.getPublic()
            );

        } else if (keyPair.getPublic() instanceof RSAPublicKey) {

            RSAPublicKey k = (RSAPublicKey) keyPair.getPublic();
            publicKeyParameter = new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent());

            RSAPrivateKey kk = (RSAPrivateKey) keyPair.getPrivate();
            privateKeyParameter = new RSAKeyParameters(true, kk.getModulus(), kk.getPrivateExponent());

            certificateBuilder = new X509v3CertificateBuilder(
                    name, serial,
                    notBefore,
                    notAfter,
                    name,
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter));
        }

        if (publicKeyParameter == null)
            return null;

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
        certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(val));

        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        certificateBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        return certificateBuilder.build(signerBuilder.build(privateKeyParameter));
    }

    /**
     * Формирует хэш данных и кодирует его в base64
     *
     * @param data входные данные
     * @return хэш в base64
     */
    public static String getBase64Digest(String data, SignAlgorithmType signAlgorithmType) {
        return getBase64EncodedString(getDigest(data.getBytes(), signAlgorithmType));
    }

    /**
     * Формирует хэш данных для заданного алгоритма
     *
     * @param data входные данные
     * @return хэш в base64
     */
    public static byte[] getDigest(byte[] data, SignAlgorithmType signAlgorithmType) {
        ExtendedDigest digest = fillDigest(signAlgorithmType);
        digest.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);

        return resBuf;
    }

    /**
     * Формирует хэш данных для файла
     *
     * @param fileBytes входные данные
     * @return хэш в base64
     */
    public static byte[] getFileDigest(byte[] fileBytes, SignAlgorithmType signAlgorithmType) {

        ExtendedDigest extendedDigest = fillDigest(signAlgorithmType);

        final String algorithmName = extendedDigest.getAlgorithmName();

        MessageDigest digest;

        try {
            digest = MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Криптопровайдер не поддерживает алгоритм:" + algorithmName, ex);
        }

        digest.update(fileBytes);

        return digest.digest();
    }

    /**
     * Формирует хэш данных для заданного алгоритма
     *
     * @param inputStream входные данные
     * @return хэш
     */
    public static byte[] getDigest(InputStream inputStream, SignAlgorithmType signAlgorithmType) throws IOException {
        ExtendedDigest digest = fillDigest(signAlgorithmType);

        try {
            byte[] dataBytes = new byte[BUFFER_SIZE];
            int numRead;
            while ((numRead = inputStream.read(dataBytes)) != -1) {
                digest.update(dataBytes, 0, numRead);
            }
            byte[] resBuf = new byte[digest.getDigestSize()];
            digest.doFinal(resBuf, 0);

            return resBuf;
        } finally {
            inputStream.close();
        }
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

        ContentSigner signer = new JcaContentSignerBuilder(getSignatureAlgorithmName(certificate, privateKey)).setProvider(CRYPTO_PROVIDER_NAME).build(privateKey);

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                .setProvider(CRYPTO_PROVIDER_NAME).build()).build(signer, certificate));

        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, false);
        return sigData.getEncoded();
    }

    private static String getSignatureAlgorithmName(X509Certificate certificate, PrivateKey privateKey) {
        if (privateKey instanceof BCECGOST3410_2012PrivateKey && ((BCECGOST3410_2012PrivateKey) privateKey).getParams().getOrder().bitLength() == 512) {
            return SignAlgorithmType.ECGOST3410_2012_512.getSignatureAlgorithmName();
        } else {
            return certificate.getSigAlgName();
        }
    }

    /**
     * Подписывает данные ЭП
     *
     * @param data              входные данные в виде массива байт
     * @param privateKey        закрытый ключ
     * @param signAlgorithmType параметры алгоритма подписи
     * @return подпись
     * @throws GeneralSecurityException
     */
    public static byte[] getSignature(byte[] data, PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws GeneralSecurityException {
        Signature signature = getSignatureInstance(signAlgorithmType);
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
        PrivateKey privateKey = CryptoFormatConverter.getInstance().getPKFromPEMEncoded(signAlgorithmType, key);
        byte[] signBytes = getSignature(data.getBytes(), privateKey, signAlgorithmType);
        return getBase64EncodedString(signBytes);
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

    private static ExtendedDigest fillDigest(SignAlgorithmType signAlgorithmType) {
        switch (signAlgorithmType) {
            case ECGOST3410:
                return new GOST3411Digest();
            case ECGOST3410_2012_256:
                return new GOST3411_2012_256Digest();
            case ECGOST3410_2012_512:
                return new GOST3411_2012_512Digest();
            default:
                throw new IllegalArgumentException("Unsupported Digest Algorithm: " + signAlgorithmType);
        }
    }

    public static Signature getSignatureInstance(SignAlgorithmType signAlgorithmType) throws GeneralSecurityException {
        final String algorithmName = signAlgorithmType.getSignatureAlgorithmName();
        return Signature.getInstance(algorithmName, CRYPTO_PROVIDER_NAME);
    }

}
