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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import jakarta.activation.DataHandler;

/**
 * Утилита для верификации подписи файла
 */
public class FileSignatureVerifier {

    private static final Logger logger = LoggerFactory.getLogger(FileSignatureVerifier.class);
    private static final int BUFFER_SIZE = 4096;

    private FileSignatureVerifier() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Верифицирует значение Digest, использованного при подписи
     * @param dataHandler          интерфейс для получения бинарных данных исходного файла
     * @param signedDataByteArray  бинарные данные подписи файла
     * @return результат верификации Digest, использованного при подписи. true - значение Digest верно, false - Digest не прошел проверку
     *
     * @throws CMSException
     */
    public static boolean verifyDigest(DataHandler dataHandler, byte[] signedDataByteArray) throws CMSException {

        byte[] data;
        try {
            data = org.bouncycastle.util.io.Streams.readAll(dataHandler.getInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read data from DataHandler", e);
        }

        CMSSignedData signedData = new CMSSignedData(signedDataByteArray);

        X509Certificate x509Certificate = getX509Certificate(signedData)
                .orElseThrow(() -> new IllegalStateException("Certificate was not received from signed data"));

        SignerInformation signerInformation = getSignerInformation(signedData)
                .orElseThrow(() -> new IllegalStateException("Signature metadata was not received from signed data"));

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
     * @return результат верификации подписи. true - подпись верна, false - подпись не прошла проверку
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static boolean verifyPKCS7Signature(byte[] signedDataByteArray) throws CMSException, GeneralSecurityException, IOException {

        CMSSignedData signedData = new CMSSignedData(signedDataByteArray);

        X509Certificate x509Certificate = getX509Certificate(signedData)
                .orElseThrow(() -> new IllegalStateException("Certificate was not received from signed data"));

        SignerInformation signerInformation = getSignerInformation(signedData)
                .orElseThrow(() -> new IllegalStateException("Signature metadata was not received from signed data"));

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
     * @return метаданные подписи
     */
    private static Optional<SignerInformation> getSignerInformation(CMSSignedData signedData) {
        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        return signerInformationStore.getSigners().stream().findFirst();
    }

    /**
     * Получает метаданные сертификата ЭП из объекта CMSSignedData
     * @param signedData объектное представление подписи
     * @return метаданные сертификата ЭП
     */
    private static Optional<X509Certificate> getX509Certificate(CMSSignedData signedData) {
        Optional<X509CertificateHolder> x509CertificateHolder = signedData.getCertificates().getMatches(null).stream().findFirst();
        return x509CertificateHolder.map(certificateHolder -> CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder));
    }
}
