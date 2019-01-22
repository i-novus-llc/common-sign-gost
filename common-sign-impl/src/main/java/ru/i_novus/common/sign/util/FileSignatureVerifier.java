package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import javax.activation.DataHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import ru.i_novus.common.sign.api.SignAlgorithmType;

@Slf4j
public class FileSignatureVerifier {

    private static final int BUFFER_SIZE = 4096;

    private FileSignatureVerifier() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static boolean verifyPKCS7Signature(DataHandler dataHandler, byte[] signedDataByteArray) throws CMSException, GeneralSecurityException, IOException {

        CMSSignedData signedData = new CMSSignedData(signedDataByteArray);

        X509CertificateHolder x509CertificateHolder = signedData.getCertificates().getMatches(null).stream().findFirst().get();

        X509Certificate x509Certificate = CryptoFormatConverter.getInstance().getCertificateFromHolder(x509CertificateHolder);

        SignerInformationStore signerInformationStore = signedData.getSignerInfos();

        SignerInformation signerInformation = signerInformationStore.getSigners().stream().findFirst().get();

        if (signerInformation.getSignedAttributes() == null) {
            throw new RuntimeException("Подпись в формате PKCS#7 не содержит подписанных данных!");
        }

        ASN1ObjectIdentifier asn1ObjectIdentifier = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_messageDigest;

        org.bouncycastle.asn1.cms.Attribute attribute = signerInformation.getSignedAttributes().get(asn1ObjectIdentifier);

        DEROctetString oct = (DEROctetString) attribute.getAttributeValues()[0];

        byte[] signedDigestedData = oct.getOctets();

        byte[] signatureAsByteArray = signerInformation.getSignature();

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

        byte[] data = StreamUtil.dataHandlerToByteArray(dataHandler);

        final byte[] argDigestedData = CryptoUtil.getFileDigest(data, signAlgorithmType);

        if (!java.util.Arrays.equals(argDigestedData, signedDigestedData)) {
            throw new RuntimeException("Дайджест не прошел проверку!");
        }

        boolean signatureIsVerified;

        try (InputStream isCheckData = new ByteArrayInputStream(signerInformation.getEncodedSignedAttributes())) {

            Signature signature = CryptoUtil.getSignatureInstance(signAlgorithmType);
            signature.initVerify(x509Certificate);

            byte[] localBuffer = new byte[BUFFER_SIZE];
            for (int readBytesCount; (readBytesCount = isCheckData.read(localBuffer)) > 0; ) {
                signature.update(localBuffer, 0, readBytesCount);
            }

            signatureIsVerified = signature.verify(signatureAsByteArray);
        }

        return signatureIsVerified;
    }
}