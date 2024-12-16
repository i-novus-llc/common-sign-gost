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
package ru.i_novus.common.sign.smev2;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.soap.GostSoapSignature;
import ru.i_novus.common.sign.util.Base64Util;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoIO;

import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static ru.i_novus.common.sign.soap.GostSoapSignature.DS_NS;
import static ru.i_novus.common.sign.soap.GostSoapSignature.WSSE_NS;
import static ru.i_novus.common.sign.soap.GostSoapSignature.WSU_NS;

public final class Smev2RequestSigner {
    private Smev2RequestSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message сообщение
     * @param encodedCertificate сертификат
     * @param encodedKey закрытый ключ в формате PEM
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException ошибка каноникализации сообщения
     * @throws IOException ошибка ввода-вывода
     */
    public static void signSmevRequest(SOAPMessage message, String encodedCertificate, String encodedKey) throws SOAPException,
            InvalidCanonicalizerException, GeneralSecurityException, TransformerException, CanonicalizationException, IOException {
        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate certificate = converter.getCertificateFromPEMEncoded(encodedCertificate);
        PrivateKey privateKey = converter.getPKFromPEMEncoded(SignAlgorithmType.findByCertificate(certificate), encodedKey);
        signSmevRequest(message, privateKey, certificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message          SOAP-сообщение
     * @param pfxEncoded       двоичные данные файла PKCS#12 закодированный в Base64
     * @param keystorePassword пароль к закрытому ключу
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws XMLSecurityException ошибка безопасности при обработке XML
     * @throws IOException ошибка ввода-вывода
     */
    public static void signSmev2RequestWithPkcs12(SOAPMessage message, String pfxEncoded, String keystorePassword)
            throws IOException, XMLSecurityException, SOAPException, GeneralSecurityException, TransformerException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            KeyStore keyStore = cryptoIO.getPkcs12KeyStore(inputStream, keystorePassword);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(keyStore, keystorePassword);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(keyStore);

            signSmevRequest(message, privateKey, x509Certificate);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message сообщение
     * @param privateKey закрытый ключ в формате {@link PrivateKey}
     * @param certificate сертификат в формате {@link X509Certificate}
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException ошибка каноникализации сообщения
     * @throws IOException ошибка ввода-вывода
     */
    public static void signSmevRequest(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate) throws SOAPException,
            InvalidCanonicalizerException, GeneralSecurityException, TransformerException, CanonicalizationException, IOException {
        // Добавляем требуемые пространства имен
        message.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", "body");
        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);
        // Добавляем элемент Security
        GostSoapSignature.addSecurityElement(message, CryptoFormatConverter.getInstance().getPEMEncodedCertificate(certificate),
                "http://smev.gosuslugi.ru/actors/smev", signAlgorithmType);
        // Подписываем сообщение
        GostSoapSignature.sign(message, privateKey, signAlgorithmType);
    }
}
