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

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.smev3.enums.Smev3ConvertEnum;
import ru.i_novus.common.sign.util.*;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static ru.i_novus.common.sign.smev3.Smev3Util.getTransformedXml;
import static ru.i_novus.common.sign.soap.GostSoapSignature.DS_NS;

public final class Smev3RequestSigner {

    public static final String CALLER_INFORM_SYSTEM_SIGNATURE_ELEMENT_NAME = "CallerInformationSystemSignature";
    public static final String REFERENCE_URI_ATTRIBUTE_NAME = "Id";
    private static final String SMEV3_MESSAGE_EXCH_TYPES_NAMESPACE_PREFIX = "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/";

    private Smev3RequestSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param message          SOAP-сообщение
     * @param pfxEncoded       двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param keystorePassword пароль к закрытому ключу
     * @throws IOException
     * @throws XMLSecurityException
     * @throws SOAPException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws ParserConfigurationException
     */
    public static void signSmev3RequestWithPkcs12(SOAPMessage message, String pfxEncoded, String keystorePassword) throws IOException, XMLSecurityException, SOAPException, GeneralSecurityException, TransformerException, ParserConfigurationException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            KeyStore keyStore = cryptoIO.getPkcs12KeyStore(inputStream, keystorePassword);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(keyStore, keystorePassword);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(keyStore);

            sign(message, privateKey, x509Certificate);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param message               сообщение
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @param pemEncodedPrivateKey  закрытый ключ в формате PEM
     * @throws XMLSecurityException
     * @throws SOAPException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws IOException
     * @throws ParserConfigurationException
     */
    public static void signSmev3Request(SOAPMessage message, String pemEncodedCertificate, String pemEncodedPrivateKey) throws XMLSecurityException, SOAPException, GeneralSecurityException, TransformerException, IOException, ParserConfigurationException {

        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate certificate = converter.getCertificateFromPEMEncoded(pemEncodedCertificate);
        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);
        PrivateKey pk = converter.getPKFromPEMEncoded(signAlgorithmType, pemEncodedPrivateKey);

        sign(message, pk, certificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param contentElement        подписываемый объект элемента
     * @param pemEncodedPrivateKey  закрытый ключ в формате PEM
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @return блок XML с данными подписи
     * @throws XMLSecurityException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws IOException
     * @throws ParserConfigurationException
     */
    public static Element signSmev3Request(Element contentElement, final String pemEncodedPrivateKey, final String pemEncodedCertificate) throws XMLSecurityException, GeneralSecurityException, TransformerException, IOException, ParserConfigurationException {
        CryptoFormatConverter cryptoFormatConverter = CryptoFormatConverter.getInstance();

        X509Certificate x509Certificate = cryptoFormatConverter.getCertificateFromPEMEncoded(pemEncodedCertificate);

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByAlgorithmName(x509Certificate.getSigAlgName());

        PrivateKey privateKey = cryptoFormatConverter.getPKFromPEMEncoded(signAlgorithmType, pemEncodedPrivateKey);

        final String contentElementId = contentElement.getAttribute(REFERENCE_URI_ATTRIBUTE_NAME);

        return sign(contentElement.getOwnerDocument(), contentElementId, privateKey, x509Certificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param contentElement   подписываемый объект элемента
     * @param pfxEncoded       двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param keystorePassword пароль к закрытому ключу
     * @return блок XML с элементами подписи
     * @throws IOException
     * @throws XMLSecurityException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws ParserConfigurationException
     */
    public static Element signSmev3RequestWithPkcs12(Element contentElement, String pfxEncoded, String keystorePassword) throws IOException, XMLSecurityException, GeneralSecurityException, TransformerException, ParserConfigurationException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            KeyStore keyStore = cryptoIO.getPkcs12KeyStore(inputStream, keystorePassword);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(keyStore, keystorePassword);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(keyStore);

            return sign(contentElement, privateKey, x509Certificate);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param message     SOAP-сообщение
     * @param privateKey  закрытый ключ ЭП
     * @param certificate сертификат ЭП
     * @throws SOAPException
     * @throws GeneralSecurityException
     * @throws XMLSecurityException
     * @throws TransformerException
     * @throws IOException
     * @throws ParserConfigurationException
     */
    public static void sign(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate) throws SOAPException, GeneralSecurityException, XMLSecurityException, TransformerException, IOException, ParserConfigurationException {

        SOAPEnvelope envelope = message.getSOAPPart().getEnvelope();
        SOAPBody soapBody = envelope.getBody();
        Node actionNode = getActionNode(soapBody);

        Element callerInformationSignature = soapBody.getOwnerDocument().createElementNS(actionNode.getNamespaceURI(), CALLER_INFORM_SYSTEM_SIGNATURE_ELEMENT_NAME);
        Node callerSigElement = actionNode.appendChild(callerInformationSignature);
        callerSigElement.setPrefix("ns2");

        final String contentElementId = getContentId(actionNode);

        final Element signatureElement = sign(soapBody.getOwnerDocument(), contentElementId, privateKey, certificate);

        // Добавляем элемент CallerInformationSystemSignature
        callerSigElement.appendChild(soapBody.getOwnerDocument().importNode(signatureElement, true));
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param contentElement  подписываемый объект элемента
     * @param privateKey      закрытый ключ ЭП
     * @param x509Certificate сертификат ЭП
     * @return блок XML с элементами подписи
     * @throws XMLSecurityException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws IOException
     * @throws ParserConfigurationException
     */
    public static Element sign(Element contentElement, PrivateKey privateKey, X509Certificate x509Certificate) throws XMLSecurityException, GeneralSecurityException, TransformerException, IOException, ParserConfigurationException {

        final String contentElementId = contentElement.getAttribute(REFERENCE_URI_ATTRIBUTE_NAME);

        return sign(contentElement.getOwnerDocument(), contentElementId, privateKey, x509Certificate);
    }

    /**
     * Создаёт блок элементов ds:Signature для указания ЭП
     *
     * @param referenceUriId        идентификатор подписываемого элемента
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @param signAlgorithmType     тип алгоритма ЭП
     * @return блок элементов ds:Signature для указания ЭП
     * @throws ParserConfigurationException
     * @throws IllegalArgumentException
     */
    public static Element createSignatureElements(final String referenceUriId, final String pemEncodedCertificate, SignAlgorithmType signAlgorithmType) throws ParserConfigurationException {

        Document document = DomUtil.newDocument();

        Element signatureElem = document.createElementNS(DS_NS, "ds:Signature");

        document.appendChild(signatureElem);

        signatureElem.setAttribute("xmlns:ds", DS_NS);

        Element signedInfoElem = (Element) signatureElem.appendChild(document.createElementNS(DS_NS, "ds:SignedInfo"));

        Element canonicalizationMethodElem = (Element) signedInfoElem.appendChild(document.createElementNS(DS_NS, "ds:CanonicalizationMethod"));

        canonicalizationMethodElem.setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        Element signatureMethodElem = (Element) signedInfoElem.appendChild(document.createElementNS(DS_NS, "ds:SignatureMethod"));

        signatureMethodElem.setAttribute("Algorithm", getSignatureMethodAlgorithm(signAlgorithmType));

        Element referenceElem = (Element) signedInfoElem.appendChild(document.createElementNS(DS_NS, "ds:Reference"));

        referenceElem.setAttribute("URI", "#" + referenceUriId);

        Element transformsElem = (Element) referenceElem.appendChild(document.createElementNS(DS_NS, "ds:Transforms"));

        ((Element) transformsElem.appendChild(document.createElementNS(DS_NS, "ds:Transform"))).setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        ((Element) transformsElem.appendChild(document.createElementNS(DS_NS, "ds:Transform"))).setAttribute("Algorithm", SmevTransformSpi.ALGORITHM_URN);

        Element digestMethodElem = (Element) referenceElem.appendChild(document.createElementNS(DS_NS, "ds:DigestMethod"));

        digestMethodElem.setAttribute("Algorithm", getDigestMethodAlgorithm(signAlgorithmType));

        referenceElem.appendChild(document.createElementNS(DS_NS, "ds:DigestValue"));

        signatureElem.appendChild(document.createElementNS(DS_NS, "ds:SignatureValue"));

        Element keyInfoElem = (Element) signatureElem.appendChild(document.createElementNS(DS_NS, "ds:KeyInfo"));

        Element x509DataElem = (Element) keyInfoElem.appendChild(document.createElementNS(DS_NS, "ds:X509Data"));

        Element x509CertificateElem = (Element) x509DataElem.appendChild(document.createElementNS(DS_NS, "ds:X509Certificate"));

        x509CertificateElem.setTextContent(pemEncodedCertificate);

        return document.getDocumentElement();
    }

    private static Node getActionNode(Element element)  {

        Node node = DomUtil.getNodeFirstChild(element);

        if (node != null && Smev3ConvertEnum.fromValue(node.getLocalName()) != null) {

            final String smevConvertNamespaceURI = node.getNamespaceURI();

            if (smevConvertNamespaceURI.startsWith(SMEV3_MESSAGE_EXCH_TYPES_NAMESPACE_PREFIX)) {
                return node;
            } else
                throw new IllegalArgumentException("Некорректный NamespaceURI корневого элемента СМЭВ-конверта");
        }

        throw new IllegalArgumentException("Не найден корневой элемент СМЭВ-конверта");
    }

    private static String getContentId(Node actionNode) {
        String id = null;
        NodeList nodes = actionNode.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element) {
                Element element = (Element) node;
                String attributeValue = element.getAttribute(REFERENCE_URI_ATTRIBUTE_NAME);
                if (!StringUtils.isEmpty(attributeValue)) {
                    id = attributeValue;
                    break;
                }
            }
        }

        return id;
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param document        объект документа
     * @param referenceUriId  идентификатор подписываемого элемента
     * @param privateKey      закрытый ключ ЭП
     * @param x509Certificate сертификат ЭП
     * @return
     * @throws XMLSecurityException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws IOException
     * @throws ParserConfigurationException
     */
    private static Element sign(Document document, final String referenceUriId, PrivateKey privateKey, X509Certificate x509Certificate) throws XMLSecurityException, GeneralSecurityException, TransformerException, IOException, ParserConfigurationException {

        String pemEncodedCertificate = CryptoFormatConverter.getInstance().getPEMEncodedCertificate(x509Certificate);

        return sign(document, referenceUriId, privateKey, x509Certificate, pemEncodedCertificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param document              объект документа
     * @param referenceUriId        идентификатор подписываемого элемента
     * @param privateKey            закрытый ключ ЭП
     * @param x509Certificate       сертификат ЭП
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @return
     * @throws XMLSecurityException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws ParserConfigurationException
     * @throws IOException
     */
    private static Element sign(Document document, final String referenceUriId, PrivateKey privateKey, X509Certificate x509Certificate, final String pemEncodedCertificate) throws XMLSecurityException, GeneralSecurityException, TransformerException, ParserConfigurationException, IOException {

        Element contentElement = (Element) XPathAPI.selectSingleNode(document, "//*[attribute::*[contains(local-name(), '" + REFERENCE_URI_ATTRIBUTE_NAME + "')]]");

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

        Element signatureElem = createSignatureElements(referenceUriId, pemEncodedCertificate, signAlgorithmType);

        //вычисление значения DigestValue
        genericDigestValue(contentElement, signatureElem, signAlgorithmType);

        signDigestValue(privateKey, signAlgorithmType, signatureElem);

        return signatureElem;
    }

    /**
     * Cчитывает подпись после всех манипуляций с SignedInfo
     *
     * @param privateKey        объект закрытого ключа
     * @param signAlgorithmType алгоритм ЭП
     * @param signatureElem     объект элемента Signature
     * @throws XMLSecurityException
     * @throws GeneralSecurityException
     * @throws TransformerException
     */
    private static void signDigestValue(PrivateKey privateKey, SignAlgorithmType signAlgorithmType, Element signatureElem) throws XMLSecurityException, GeneralSecurityException, TransformerException {

        Node signedInfoNode = XPathAPI.selectSingleNode(signatureElem, "ds:SignedInfo");

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        //считаем подпись после всех манипуляций с SignedInfo
        Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalizeSubtree(signedInfoNode, buffer);
        byte[] signatureBytes = CryptoUtil.getSignature(buffer.toByteArray(), privateKey, signAlgorithmType);

        final String base64Signature = new String(Base64Util.getBase64Encoded(signatureBytes));

        XPathAPI.selectSingleNode(signatureElem, "ds:SignatureValue").setTextContent(base64Signature);
    }

    /**
     * Получает URI алгоритма формирования подписи
     *
     * @param signAlgorithmType тип алгоритма подписи
     * @return URI алгоритма формирования подписи
     * @throws IllegalArgumentException
     */
    public static String getSignatureMethodAlgorithm(SignAlgorithmType signAlgorithmType) {

        String result;

        switch (signAlgorithmType) {
            case ECGOST3410:
                result = signAlgorithmType.getSignUri();
                break;
            case ECGOST3410_2012_256:
            case ECGOST3410_2012_512:
                result = signAlgorithmType.getSignUrn();
                break;
            default:
                throw new IllegalArgumentException("Signature algorithm type " + signAlgorithmType + " is not supported.");
        }

        return result;
    }

    /**
     * Получает URI алгоритма расчета хеш-суммы
     *
     * @param signAlgorithmType тип алгоритма подписи
     * @return URI алгоритма расчета хеш-суммы
     * @throws IllegalArgumentException
     */
    public static String getDigestMethodAlgorithm(SignAlgorithmType signAlgorithmType) {

        String result;

        switch (signAlgorithmType) {
            case ECGOST3410:
                result = signAlgorithmType.getDigestUri();
                break;
            case ECGOST3410_2012_256:
            case ECGOST3410_2012_512:
                result = signAlgorithmType.getDigestUrn();
                break;
            default:
                throw new IllegalArgumentException("Signature algorithm type " + signAlgorithmType + " is not supported.");
        }

        return result;
    }

    /**
     * Проставляет в элемент DigestValue рассчитанную хеш-сумму блока с бизнес-данными запроса
     *
     * @param content2sign      объект элемента, значение которого подвергается подписанию
     * @param signatureElem     объект элемента Signature
     * @param signAlgorithmType тип алгоритма ЭП
     * @throws TransformerException
     * @throws IOException
     * @throws TransformationException
     */
    private static void genericDigestValue(final Element content2sign, final Element signatureElem, SignAlgorithmType signAlgorithmType) throws TransformerException, IOException, TransformationException {

        /* получение строки трансформированного XML-элемента, в соответствии с требованиями методических рекомендаций СМЭВ */
        byte[] transformedRootElementBytes = getTransformedXml(content2sign);

        byte[] digestBytes = CryptoUtil.getDigest(transformedRootElementBytes, signAlgorithmType);

        final String base64Digest = new String(Base64Util.getBase64Encoded(digestBytes));

        XPathAPI.selectSingleNode(signatureElem, "ds:SignedInfo/ds:Reference/ds:DigestValue").setTextContent(base64Digest);
    }
}
