package ru.i_novus.common.sign.smev;

import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.util.Base64Util;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoIO;
import ru.i_novus.common.sign.util.CryptoUtil;
import sun.security.pkcs.*;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import javax.activation.DataHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

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
    public static byte[] signSmev3Attachment(DataHandler content, final String pemEncodedPrivateKey, final String pemEncodedCertificate) throws IOException, GeneralSecurityException {

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
    public static byte[] signSmev3Attachment(DataHandler content, X509Certificate x509Certificate, PrivateKey privateKey) throws IOException, GeneralSecurityException {

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByAlgorithmName(x509Certificate.getSigAlgName());

        return sign(content, x509Certificate, privateKey, signAlgorithmType);
    }

    /**
     * Подписывает файловое вложение для сервиса СМЭВ 3
     *
     * @param content    данные вложения
     * @param pfxEncoded двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param password   пароль к закрытому ключу
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static byte[] signSmev3AttachmentWithPkcs12(DataHandler content, final String pfxEncoded, final String password) throws IOException, GeneralSecurityException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(inputStream, password);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(inputStream, password);

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
    private static byte[] sign(DataHandler content, X509Certificate x509Certificate, PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws IOException, GeneralSecurityException {

        final byte[] attachmentBytes = dataHandlerToByteArray(content);

        final byte[] attachmentDigest = CryptoUtil.getFileDigest(attachmentBytes, signAlgorithmType);

        PKCS7 p7 = sign(attachmentDigest, x509Certificate, privateKey, signAlgorithmType);

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            p7.encodeSignedData(bos);

            return bos.toByteArray();
        }
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
        PKCS9Attributes authenticatedAttributes = getPKCS9Attributes(attachmentDigest);

        // Подписываем.
        byte[] signedAttributes = CryptoUtil.getSignature(authenticatedAttributes.getDerEncoding(), privateKey, signAlgorithmType);

        // SignerInfo
        SignerInfo[] signerInfos = getSignerInfos(x509Certificate, authenticatedAttributes, signedAttributes, signAlgorithmType);

        // Сертификат.
        X509Certificate[] certificates = {x509Certificate};

        // Алгоритм подписи.
        AlgorithmId[] digestAlgorithmIds = new AlgorithmId[]{AlgorithmId.get(signAlgorithmType.getHashAlgorithmOid())};

        ContentInfo contentInfo = new ContentInfo(sun.security.pkcs.ContentInfo.DATA_OID, null);

        // Собираем все вместе и пишем в стрим.
        return new PKCS7(digestAlgorithmIds, contentInfo, certificates, signerInfos);
    }

    private static PKCS9Attributes getPKCS9Attributes(byte[] attachmentDigest) throws IOException {

        PKCS9Attribute[] authenticatedAttributeList = {
                new PKCS9Attribute(PKCS9Attribute.CONTENT_TYPE_OID, sun.security.pkcs.ContentInfo.DATA_OID),
                new PKCS9Attribute(PKCS9Attribute.SIGNING_TIME_OID, new Date()),
                new PKCS9Attribute(PKCS9Attribute.MESSAGE_DIGEST_OID, attachmentDigest)
        };

        return new PKCS9Attributes(authenticatedAttributeList);
    }

    private static SignerInfo[] getSignerInfos(final X509Certificate certificate, PKCS9Attributes authenticatedAttributes, byte[] signedAttributes, SignAlgorithmType signAlgorithmType) throws IOException, NoSuchAlgorithmException {

        BigInteger serial = certificate.getSerialNumber();

        SignerInfo si = new SignerInfo(
                new X500Name(certificate.getIssuerDN().getName()),
                serial,
                AlgorithmId.get(signAlgorithmType.getHashAlgorithmOid()),
                authenticatedAttributes,
                new AlgorithmId(new ObjectIdentifier(signAlgorithmType.getEncryptionAlgorithmOid())),
                signedAttributes,
                null);

        return new SignerInfo[]{si};
    }

    public static byte[] dataHandlerToByteArray(final DataHandler content) throws IOException {

        try (InputStream in = content.getInputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream(4096)) {

            int byteCount = 0;

            byte[] buffer = new byte[4096];

            int bytesRead1;

            for (boolean bytesRead = true; (bytesRead1 = in.read(buffer)) != -1; byteCount += bytesRead1) {
                out.write(buffer, 0, bytesRead1);
            }

            out.flush();

            return out.toByteArray();
        }
    }
}
