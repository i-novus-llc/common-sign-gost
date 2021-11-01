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
package ru.i_novus.common.sign.ips;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Node;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.soap.GostSoapSignature;
import ru.i_novus.common.sign.soap.dto.SecurityElementInfo;
import ru.i_novus.common.sign.util.CryptoFormatConverter;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.UUID;

import static ru.i_novus.common.sign.soap.GostSoapSignature.*;

public final class IpsRequestSigner {
    private static final String WSA_NS = "http://www.w3.org/2005/08/addressing";
    private static final String WSA_ANONYMOUS = "http://www.w3.org/2005/08/addressing/anonymous";
    private static final String EGISZ_NS = "http://egisz.rosminzdrav.ru";
    private static final String EGISZ_PREFIX = "egisz";
    private static final String MESSAGE_ID_LOCAL_NAME = "MessageID";
    private static final String ACTION_LOCAL_NAME = "Action";
    private static final String TO_LOCAL_NAME = "To";
    private static final String REPLY_TO_LOCAL_NAME = "ReplyTo";

    private IpsRequestSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Подписывает SOAP-запрос для сервиса ИПС
     *
     * @param message сообщение
     * @param soapService адрес сервиса в ИПС
     * @param soapAction действие сервиса
     * @param clientEntityId идентификатор системы
     * @param encodedCertificate сертификат в формате PEM
     * @param encodedPrivateKey закрытый ключ в формате PEM
     * @param expireDateTime временная метка срока истечения действия ЭП
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException ошибка каноникализации сообщения
     * @throws IOException ошибка ввода-вывода
     */
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId,
                                      String encodedCertificate, String encodedPrivateKey, ZonedDateTime expireDateTime) throws
            SOAPException, GeneralSecurityException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, IOException {

        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate x509Certificate = converter.getCertificateFromPEMEncoded(encodedCertificate);
        PrivateKey privateKey = converter.getPKFromPEMEncoded(SignAlgorithmType.findByCertificate(x509Certificate), encodedPrivateKey);
        signIpsRequest(message, soapService, soapAction, clientEntityId, privateKey, x509Certificate, expireDateTime);
    }

    /**
     * Подписывает SOAP-запрос для сервиса ИПС
     *
     * @param message сообщение
     * @param soapService адрес сервиса в ИПС
     * @param soapAction действие сервиса
     * @param clientEntityId идентификатор системы
     * @param certificate сертификат в формате
     * @param privateKey закрытый ключ в формате {@link java.security.PrivateKey}
     * @param expireDateTime временная метка срока истечения действия ЭП
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException ошибка каноникализации сообщения
     * @throws IOException ошибка ввода-вывода
     */
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId,
                                      PrivateKey privateKey, X509Certificate certificate, ZonedDateTime expireDateTime) throws
            SOAPException, GeneralSecurityException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, IOException {

        final SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);
        SecurityElementInfo elemInfo = createSecurityElementInfo(message, certificate, expireDateTime, signAlgorithmType);
        // Добавляем требуемые пространства имен
        addNamespaceDeclaration(message);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", elemInfo.getBodyReferenceId());
        // Добавляем элемент Security
        GostSoapSignature.addSecurityElement(elemInfo);

        SOAPHeader soapHeader = getSoapHeader(message);

        // Добавляем элементы transportHeader, authInfo и clientEntityId
        addTransportHeader(soapHeader, clientEntityId);
        // Добавляем элемент MessageID
        addHeaderChildElement(soapHeader, MESSAGE_ID_LOCAL_NAME, UUID.randomUUID().toString(), elemInfo.getMessageIdReferenceId());
        // Добавляем элемент ReplyTo
        addReplyTo(soapHeader, elemInfo);
        // Добавляем элемент To
        addHeaderChildElement(soapHeader, TO_LOCAL_NAME, soapService, elemInfo.getToReferenceId());
        // Добавляем элемент Action
        addHeaderChildElement(soapHeader, ACTION_LOCAL_NAME, soapAction, elemInfo.getActionReferenceId());
        // Подписываем сообщение
        GostSoapSignature.sign(message, privateKey, signAlgorithmType);
    }

    /**
     * Подписывает SOAP-запрос для сервиса ИПС
     *
     * @param message            сообщение
     * @param soapService        адрес сервиса в ИПС
     * @param soapAction         действие сервиса
     * @param clientEntityId     идентификатор системы
     * @param encodedCertificate сертификат в формате PEM
     * @param encodedPrivateKey  закрытый ключ в формате PEM
     * @throws SOAPException                 ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException      ошибка подписи
     * @throws TransformerException          ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException     ошибка каноникализации сообщения
     * @throws IOException                   ошибка ввода-вывода
     */
    @Deprecated
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId,
                                      String encodedCertificate, String encodedPrivateKey) throws
            SOAPException, GeneralSecurityException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, IOException {

        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate x509Certificate = converter.getCertificateFromPEMEncoded(encodedCertificate);
        PrivateKey privateKey = converter.getPKFromPEMEncoded(SignAlgorithmType.findByCertificate(x509Certificate), encodedPrivateKey);
        signIpsRequest(message, soapService, soapAction, clientEntityId, privateKey, x509Certificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса ИПС
     *
     * @param message        сообщение
     * @param soapService    адрес сервиса в ИПС
     * @param soapAction     действие сервиса
     * @param clientEntityId идентификатор системы
     * @param certificate    сертификат в формате
     * @param privateKey     закрытый ключ в формате {@link java.security.PrivateKey}
     * @throws SOAPException                 ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException      ошибка подписи
     * @throws TransformerException          ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException     ошибка каноникализации сообщения
     * @throws IOException                   ошибка ввода-вывода
     */
    @Deprecated
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId,
                                      PrivateKey privateKey, X509Certificate certificate) throws
            SOAPException, GeneralSecurityException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, IOException {
        // Добавляем требуемые пространства имен
        addNamespaceDeclaration(message);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", "body");

        SOAPHeader soapHeader = getSoapHeader(message);

        // Добавляем элемент transportHeader
        addTransportHeader(soapHeader, clientEntityId);
        // Добавляем элемент MessageID
        addHeaderChildElement(soapHeader, MESSAGE_ID_LOCAL_NAME, UUID.randomUUID().toString(), null);
        // Добавляем элемент Action
        addHeaderChildElement(soapHeader, ACTION_LOCAL_NAME, soapAction, null);
        // Добавляем элемент To
        addHeaderChildElement(soapHeader, TO_LOCAL_NAME, soapService, null);
        // Добавляем элемент Security
        GostSoapSignature.addSecurityElement(message, certificate, null);
        // Подписываем сообщение
        GostSoapSignature.sign(message, privateKey, SignAlgorithmType.findByAlgorithmName(certificate.getSigAlgName()));
    }

    /**
     * Подписывает SOAP-ответ для сервиса ИПС
     *
     * @param message сообщение
     * @param encodedCertificate сертификат в формате PEM
     * @param encodedKey закрытый ключ в формате PEM
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException ошибка каноникализации сообщения
     * @throws IOException ошибка ввода-вывода
     */
    public static void signIpsResponse(SOAPMessage message, String encodedCertificate, String encodedKey) throws SOAPException,
            TransformerException, GeneralSecurityException, InvalidCanonicalizerException, CanonicalizationException, IOException {
        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate certificate = converter.getCertificateFromPEMEncoded(encodedCertificate);
        signIpsResponse(message, converter.getPKFromPEMEncoded(SignAlgorithmType.findByCertificate(certificate), encodedKey), certificate);
    }

    /**
     * Подписывает SOAP-ответ для сервиса ИПС
     *
     * @param message сообщение
     * @param privateKey закрытый ключ в формате PEM
     * @param certificate сертификат в формате PEM
     * @throws SOAPException ошибка обработки SOAP-пакета
     * @throws GeneralSecurityException ошибка подписи
     * @throws TransformerException ошибка трансформации сообщения
     * @throws InvalidCanonicalizerException не найден необходимый каноникалайзер
     * @throws CanonicalizationException ошибка каноникализации сообщения
     * @throws IOException ошибка ввода-вывода
     */
    public static void signIpsResponse(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate) throws SOAPException,
            TransformerException, GeneralSecurityException, InvalidCanonicalizerException, CanonicalizationException, IOException {
        // Добавляем требуемые пространства имен
        addNamespaceDeclaration(message);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", "body");

        SOAPHeader soapHeader = getSoapHeader(message);
        // Добавляем элементы MessageID
        addHeaderChildElement(soapHeader, MESSAGE_ID_LOCAL_NAME, UUID.randomUUID().toString(), null);
        // Добавляем элемент Security
        GostSoapSignature.addSecurityElement(message, certificate, null);
        // Подписываем сообщение
        GostSoapSignature.sign(message, privateKey, SignAlgorithmType.findByCertificate(certificate));
    }

    private static SOAPHeader getSoapHeader(SOAPMessage message) throws SOAPException {
        SOAPHeader soapHeader = message.getSOAPHeader();
        if (soapHeader == null) {
            soapHeader = message.getSOAPPart().getEnvelope().addHeader();
        }
        return soapHeader;
    }

    private static void addHeaderChildElement(SOAPHeader soapHeader, final String localName,
                                              final String textNode, final String referenceId) throws TransformerException, SOAPException {
        SOAPElement actionElem = (SOAPElement)XPathAPI.selectSingleNode(soapHeader, "//*[local-name()='"+ localName +"']");
        if (actionElem == null) {
            actionElem = soapHeader.addChildElement(localName, "wsa");
            actionElem.addTextNode(textNode);
        }
        if(referenceId != null)
            actionElem.setAttribute("wsu:Id", referenceId);
    }

    private static void addNamespaceDeclaration(SOAPMessage message) throws SOAPException {
        message.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS)
                .addNamespaceDeclaration("wsa", WSA_NS);
    }

    private static void addTransportHeader(SOAPHeader soapHeader, String clientEntityId) throws TransformerException, SOAPException {
        Node transportHeader = XPathAPI.selectSingleNode(soapHeader,
                "//*[local-name()='transportHeader']/*[local-name()='authInfo']/*[local-name()='clientEntityId']");
        if (transportHeader == null) {
            soapHeader.addChildElement(new QName(EGISZ_NS, "transportHeader", EGISZ_PREFIX))
                    .addChildElement("authInfo", EGISZ_PREFIX)
                    .addChildElement("clientEntityId", EGISZ_PREFIX)
                    .addTextNode(clientEntityId);
        }
    }

    private static void addReplyTo(SOAPHeader soapHeader, SecurityElementInfo elemInfo) throws TransformerException, SOAPException {
        SOAPElement replyToElem = (SOAPElement)XPathAPI.selectSingleNode(soapHeader, "//*[local-name()='"+ REPLY_TO_LOCAL_NAME +"']");
        if (replyToElem == null) {
            replyToElem = soapHeader.addChildElement(REPLY_TO_LOCAL_NAME, "wsa");
            replyToElem.addChildElement("Address", "wsa").setTextContent(WSA_ANONYMOUS);
        }
        replyToElem.setAttribute("wsu:Id", elemInfo.getReplyToReferenceId());
    }

    private static SecurityElementInfo createSecurityElementInfo(SOAPMessage message, X509Certificate certificate, ZonedDateTime expireDateTime, SignAlgorithmType signAlgorithmType) {
        SecurityElementInfo elemInfo = new SecurityElementInfo();
        elemInfo.setMessage(message);
        elemInfo.setCertificate(certificate);
        elemInfo.setSignAlgorithmType(signAlgorithmType);
        elemInfo.setExpireDateTime(expireDateTime);
        elemInfo.setMessageIdReferenceId("id-"+ UUID.randomUUID().toString());
        elemInfo.setReplyToReferenceId("id-"+ UUID.randomUUID().toString());
        elemInfo.setToReferenceId("id-"+ UUID.randomUUID().toString());
        elemInfo.setActionReferenceId("id-"+ UUID.randomUUID().toString());
        elemInfo.setBodyReferenceId(GostSoapSignature.BODY_REFERENCE_ID);
        return elemInfo;
    }
}
