package ru.i_novus.common.sign.smev;

import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.datatypes.FileSignatureInfo;
import ru.i_novus.common.sign.util.*;
import sun.security.pkcs.*;
import sun.security.x509.AlgorithmId;

import javax.activation.DataHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class Smev3AttachmentSigner {

    public Smev3AttachmentSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Подписывает файловое вложение для сервиса СМЭВ 3
     *
     * @param content               данные вложения
     * @param pemEncodedPrivateKey  закрытый ключ в формате PEM
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static FileSignatureInfo signSmev3Attachment(DataHandler content, final String pemEncodedPrivateKey, final String pemEncodedCertificate) throws IOException, GeneralSecurityException {

        CryptoFormatConverter cryptoFormatConverter = CryptoFormatConverter.getInstance();

        X509Certificate x509Certificate = cryptoFormatConverter.getCertificateFromPEMEncoded(pemEncodedCertificate);

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByAlgorithmName(x509Certificate.getSigAlgName());

        PrivateKey privateKey = cryptoFormatConverter.getPKFromPEMEncoded(signAlgorithmType, pemEncodedPrivateKey);

        return signSmev3Attachment(content, x509Certificate, privateKey);
    }

    /**
     * Подписывает файловое вложение для сервиса СМЭВ 3
     *
     * @param content          данные вложения
     * @param x509Certificate  сертификат ЭП в формате {@link X509Certificate}
     * @param privateKey       закрытый ключ в формате {@link PrivateKey}
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static FileSignatureInfo signSmev3Attachment(DataHandler content, X509Certificate x509Certificate, PrivateKey privateKey) throws IOException, GeneralSecurityException {

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByAlgorithmName(x509Certificate.getSigAlgName());

        return sign(content, x509Certificate, privateKey, signAlgorithmType);
    }

    /**
     * Подписывает файловое вложение для сервиса СМЭВ 3
     *
     * @param content          данные вложения
     * @param pfxEncoded       двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param keystorePassword пароль к закрытому ключу
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static FileSignatureInfo signSmev3AttachmentWithPkcs12(DataHandler content, final String pfxEncoded, final String keystorePassword) throws IOException, GeneralSecurityException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            KeyStore $ex = cryptoIO.getPkcs12KeyStore(inputStream, keystorePassword);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12($ex, keystorePassword);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12($ex);

            return signSmev3Attachment(content, x509Certificate, privateKey);
        }
    }

    /**
     * Подписывает файловое вложение для сервиса СМЭВ 3
     *
     * @param content           данные вложения
     * @param x509Certificate   сертификат ЭП в формате {@link X509Certificate}
     * @param privateKey        закрытый ключ в формате {@link PrivateKey}
     * @param signAlgorithmType тип алгоритма ЭП
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private static FileSignatureInfo sign(DataHandler content, X509Certificate x509Certificate, PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws IOException, GeneralSecurityException {

        final byte[] attachmentBytes = StreamUtil.dataHandlerToByteArray(content);

        final byte[] attachmentDigest = CryptoUtil.getFileDigest(attachmentBytes, signAlgorithmType);

        PKCS7 p7 = sign(attachmentDigest, x509Certificate, privateKey, signAlgorithmType);

        byte[] signaturePKCS7;

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            p7.encodeSignedData(bos);

            signaturePKCS7 = bos.toByteArray();
        }

        return new FileSignatureInfo(Base64Util.getBase64EncodedString(attachmentDigest), signaturePKCS7);
    }

    /**
     * Подписывает файловое вложение для сервиса СМЭВ 3
     *
     * @param attachmentDigest  хэш данных вложения
     * @param x509Certificate   сертификат ЭП в формате {@link X509Certificate}
     * @param privateKey        закрытый ключ в формате {@link PrivateKey}
     * @param signAlgorithmType тип алгоритма ЭП
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private static PKCS7 sign(byte[] attachmentDigest, final X509Certificate x509Certificate, final PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws IOException, GeneralSecurityException {

        // Данные для подписи.
        PKCS9Attributes authenticatedAttributes = PKCS7Util.getPKCS9Attributes(attachmentDigest);

        // Подписываем.
        byte[] signedAttributes = CryptoUtil.getSignature(authenticatedAttributes.getDerEncoding(), privateKey, signAlgorithmType);

        // Алгоритм подписи.
        String hashAlgorithmOid = signAlgorithmType.getHashAlgorithmOid();

        AlgorithmId[] digestAlgorithmIds = new AlgorithmId[]{AlgorithmId.get(hashAlgorithmOid)};

        // SignerInfo
        SignerInfo[] signerInfos = PKCS7Util.getSignerInfos(x509Certificate, authenticatedAttributes, signedAttributes, signAlgorithmType.getEncryptionAlgorithmOid(), hashAlgorithmOid);

        // Сертификат.
        X509Certificate[] certificates = {x509Certificate};

        ContentInfo contentInfo = new ContentInfo(sun.security.pkcs.ContentInfo.DATA_OID, null);

        // Собираем все вместе и пишем в стрим.
        return new PKCS7(digestAlgorithmIds, contentInfo, certificates, signerInfos);
    }
}
