package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import javax.activation.DataHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import ru.i_novus.common.sign.api.SignAlgorithmType;

/**
 * Утилита для верификации подписи файла
 */
@Slf4j
public class FileSignatureVerifier {

    private static final int BUFFER_SIZE = 4096;

    private FileSignatureVerifier() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Верифицирует значение Digest использованный при подписи
     * @param dataHandler          интерфейс для получения бинарных данных исходного файла
     * @param signedDataByteArray  бинарные данные подписи файла
     * @return
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static boolean verifyDigest(DataHandler dataHandler, byte[] signedDataByteArray) throws CMSException, GeneralSecurityException, IOException {

        byte[] data = StreamUtil.dataHandlerToByteArray(dataHandler);

        CMSSignedData signedData = new CMSSignedData(signedDataByteArray);

        X509Certificate x509Certificate = getX509Certificate(signedData);

        SignerInformation signerInformation = getSignerInformation(signedData);

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

        final byte[] argDigestedData = CryptoUtil.getFileDigest(data, signAlgorithmType);

        ASN1ObjectIdentifier asn1ObjectIdentifier = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_messageDigest;

        org.bouncycastle.asn1.cms.Attribute attribute = signerInformation.getSignedAttributes().get(asn1ObjectIdentifier);

        DEROctetString oct = (DEROctetString) attribute.getAttributeValues()[0];

        byte[] signedDigestedData = oct.getOctets();

        return Arrays.equals(argDigestedData, signedDigestedData);
    }

    /**
     * Верифицирует подпись файла
     * @param signedDataByteArray бинарные данные подписи файла
     * @return
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static boolean verifyPKCS7Signature(byte[] signedDataByteArray) throws CMSException, GeneralSecurityException, IOException {

        CMSSignedData signedData = new CMSSignedData(signedDataByteArray);

        X509Certificate x509Certificate = getX509Certificate(signedData);

        SignerInformation signerInformation = getSignerInformation(signedData);

        byte[] signatureAsByteArray = signerInformation.getSignature();

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

        boolean signatureIsVerified;

        try (InputStream inputStream = new ByteArrayInputStream(signerInformation.getEncodedSignedAttributes())) {

            Signature signature = CryptoUtil.getSignatureInstance(signAlgorithmType);
            signature.initVerify(x509Certificate);

            byte[] localBuffer = new byte[BUFFER_SIZE];
            for (int readBytesCount; (readBytesCount = inputStream.read(localBuffer)) > 0; ) {
                signature.update(localBuffer, 0, readBytesCount);
            }

            signatureIsVerified = signature.verify(signatureAsByteArray);
        }

        return signatureIsVerified;
    }

    /**
     * Получает метаданные подписи из объекта CMSSignedData
     * @param signedData объектное представление подписи
     * @return
     */
    private static SignerInformation getSignerInformation(CMSSignedData signedData) {
        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        return signerInformationStore.getSigners().stream().findFirst().get();
    }

    /**
     * Получает метаданные сертификата ЭП из объекта CMSSignedData
     * @param signedData объектное представление подписи
     * @return
     */
    private static X509Certificate getX509Certificate(CMSSignedData signedData) throws CMSException {
        X509CertificateHolder x509CertificateHolder = signedData.getCertificates().getMatches(null).stream().findFirst().get();
        return CryptoFormatConverter.getInstance().getCertificateFromHolder(x509CertificateHolder);
    }
}