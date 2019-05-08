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
package ru.i_novus.common.sign.smev3;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.datatypes.FileSignatureInfo;
import ru.i_novus.common.sign.util.*;
import javax.activation.DataHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class Smev3AttachmentSigner {

    private Smev3AttachmentSigner() {
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
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws OperatorCreationException
     */
    public static FileSignatureInfo signSmev3Attachment(DataHandler content, final String pemEncodedPrivateKey, final String pemEncodedCertificate) throws IOException, CMSException, GeneralSecurityException, OperatorCreationException {

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
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws OperatorCreationException
     */
    public static FileSignatureInfo signSmev3Attachment(DataHandler content, X509Certificate x509Certificate, PrivateKey privateKey) throws IOException, CMSException, GeneralSecurityException, OperatorCreationException {

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
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws OperatorCreationException
     */
    public static FileSignatureInfo signSmev3AttachmentWithPkcs12(DataHandler content, final String pfxEncoded, final String keystorePassword) throws IOException, CMSException, GeneralSecurityException, OperatorCreationException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            KeyStore keyStore = cryptoIO.getPkcs12KeyStore(inputStream, keystorePassword);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(keyStore, keystorePassword);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(keyStore);

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
     * @throws CMSException
     * @throws GeneralSecurityException
     * @throws OperatorCreationException
     */
    private static FileSignatureInfo sign(DataHandler content, X509Certificate x509Certificate, PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws IOException, CMSException, GeneralSecurityException, OperatorCreationException {

        final byte[] attachmentBytes = org.bouncycastle.util.io.Streams.readAll(content.getInputStream());

        final byte[] attachmentDigest = CryptoUtil.getFileDigest(attachmentBytes, signAlgorithmType);

        byte[] signaturePKCS7 = CryptoUtil.getCMSSignature(attachmentBytes, privateKey, x509Certificate);

        return new FileSignatureInfo(Base64Util.getBase64EncodedString(attachmentDigest), signaturePKCS7);
    }
}
