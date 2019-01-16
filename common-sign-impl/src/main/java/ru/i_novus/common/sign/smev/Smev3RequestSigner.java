package ru.i_novus.common.sign.smev;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.exception.CommonSignFailureException;
import ru.i_novus.common.sign.exception.InvalidSiginigObjectException;
import ru.i_novus.common.sign.smev.enums.Smev3ConvertEnum;
import ru.i_novus.common.sign.util.*;

import javax.xml.soap.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static ru.i_novus.common.sign.GostXmlSignature.DS_NS;

public final class Smev3RequestSigner {

    public static final String NODE_CALLER_INFORMATION_SYSTEM_SIGNATURE = "CallerInformationSystemSignature";
    private static final String URN_SMEV3_MESSAGE_EXCHANGE_TYPES = "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/";
    private static final String REFERENCE_URI_ID = "Id";

    private Smev3RequestSigner() {
        throw new InstantiationError("Must not instantiate this class");
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param message    SOAP-сообщение
     * @param pfxEncoded двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param password   пароль к закрытому ключу
     * @throws CommonSignFailureException
     * @throws InvalidSiginigObjectException
     */
    public static void signWithPFX(SOAPMessage message, String pfxEncoded, String password) throws CommonSignFailureException, InvalidSiginigObjectException {
        try {

            CryptoIO cryptoIO = CryptoIO.getInstance();

            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

                PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(inputStream, password);

                X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(inputStream, password);

                sign(message, privateKey, x509Certificate);
            }

        } catch (IOException | RuntimeException ex) {
            throw new CommonSignFailureException(ex);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param message               сообщение
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @param pemEncodedPrivateKey  закрытый ключ в формате PEM
     * @throws CommonSignFailureException
     * @throws InvalidSiginigObjectException
     */
    public static void signWithPEM(SOAPMessage message, String pemEncodedCertificate, String pemEncodedPrivateKey) throws CommonSignFailureException, InvalidSiginigObjectException {
        try {

            CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
            X509Certificate certificate = converter.getCertificateFromPEMEncoded(pemEncodedCertificate);
            SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);
            PrivateKey pk = converter.getPKFromPEMEncoded(signAlgorithmType, pemEncodedPrivateKey);

            sign(message, pk, certificate);

        } catch (RuntimeException ex) {
            throw new CommonSignFailureException(ex);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param contentElement        подписываемый объект элемента
     * @param pemEncodedPrivateKey  сертификат ЭП в формате PEM
     * @param pemEncodedCertificate закрытый ключ в формате PEM
     * @return
     * @throws CommonSignFailureException
     */
    public static Element signWithPEM(Element contentElement, final String pemEncodedPrivateKey, final String pemEncodedCertificate) throws CommonSignFailureException {
        CryptoFormatConverter cryptoFormatConverter = CryptoFormatConverter.getInstance();

        X509Certificate x509Certificate = cryptoFormatConverter.getCertificateFromPEMEncoded(pemEncodedCertificate);

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByAlgorithmName(x509Certificate.getSigAlgName());

        PrivateKey privateKey = cryptoFormatConverter.getPKFromPEMEncoded(signAlgorithmType, pemEncodedPrivateKey);

        final String contentElementId = contentElement.getAttribute(REFERENCE_URI_ID);

        return sign(contentElement.getOwnerDocument(), contentElementId, privateKey, x509Certificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param contentElement подписываемый объект элемента
     * @param pfxEncoded     двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param password       пароль к закрытому ключу
     * @return
     * @throws CommonSignFailureException
     */
    public static Element signWithPFX(Element contentElement, String pfxEncoded, String password) throws CommonSignFailureException {

        try {

            CryptoIO cryptoIO = CryptoIO.getInstance();

            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

                PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(inputStream, password);

                X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12(inputStream, password);

                return sign(contentElement, privateKey, x509Certificate);
            }

        } catch (IOException | RuntimeException ex) {
            throw new CommonSignFailureException(ex);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param message     SOAP-сообщение
     * @param privateKey  закрытый ключ ЭП
     * @param certificate сертификат ЭП
     * @throws InvalidSiginigObjectException
     * @throws CommonSignFailureException
     */
    public static void sign(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate) throws InvalidSiginigObjectException, CommonSignFailureException {

        try {
            SOAPEnvelope envelope = message.getSOAPPart().getEnvelope();
            SOAPBody soapBody = envelope.getBody();
            Node actionNode = getActionNode(soapBody);

            Element callerInformationSignature = soapBody.getOwnerDocument().createElementNS(actionNode.getNamespaceURI(), NODE_CALLER_INFORMATION_SYSTEM_SIGNATURE);
            Node callerSigElement = actionNode.appendChild(callerInformationSignature);
            callerSigElement.setPrefix("ns2");

            final String contentElementId = getContentId(actionNode);

            final Element signatureElement = sign(soapBody.getOwnerDocument(), contentElementId, privateKey, certificate);

            // Добавляем элемент CallerInformationSystemSignature
            callerSigElement.appendChild(soapBody.getOwnerDocument().importNode(signatureElement, true));

        } catch (SOAPException | RuntimeException ex) {
            throw new CommonSignFailureException(ex);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     *
     * @param contentElement  подписываемый объект элемента
     * @param privateKey      закрытый ключ ЭП
     * @param x509Certificate сертификат ЭП
     * @return
     * @throws CommonSignFailureException
     */
    public static Element sign(Element contentElement, PrivateKey privateKey, X509Certificate x509Certificate) throws CommonSignFailureException {

        final String contentElementId = contentElement.getAttribute(REFERENCE_URI_ID);

        return sign(contentElement.getOwnerDocument(), contentElementId, privateKey, x509Certificate);
    }

    private static Node getActionNode(Element element) throws InvalidSiginigObjectException {

        Node node = DomUtil.getNodeFirstChild(element);

        if (node != null
                && Smev3ConvertEnum.fromValue(node.getLocalName()) != null
                && node.getNamespaceURI() != null
                && node.getNamespaceURI().startsWith(URN_SMEV3_MESSAGE_EXCHANGE_TYPES)) {
            return node;
        }

        if (node != null && Smev3ConvertEnum.fromValue(node.getLocalName()) != null) {

            final String smevConvertNamespaceURI = node.getNamespaceURI();

            if (smevConvertNamespaceURI != null && smevConvertNamespaceURI.startsWith(URN_SMEV3_MESSAGE_EXCHANGE_TYPES)) {
                return node;
            } else
                throw new InvalidSiginigObjectException("Некорректный NamespaceURI корневого элемента СМЭВ-конверта");
        }

        throw new InvalidSiginigObjectException("Не найден корневой элемент СМЭВ-конверта");
    }

    private static String getContentId(Node actionNode) {
        String id = null;
        NodeList nodes = actionNode.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element) {
                Element element = (Element) node;
                String attributeValue = element.getAttribute(REFERENCE_URI_ID);
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
     * @param document         объект документа
     * @param referenceUriId   идентификатор подписываемого элемента
     * @param privateKey       закрытый ключ ЭП
     * @param x509Certificate  сертификат ЭП
     * @return
     * @throws CommonSignFailureException
     */
    private static Element sign(Document document, final String referenceUriId, PrivateKey privateKey, X509Certificate x509Certificate) throws CommonSignFailureException {

        String pemEncodedCertificate = CryptoFormatConverter.getInstance().getPEMEncodedCertificate(x509Certificate);

        return sign(document, referenceUriId, privateKey, x509Certificate, pemEncodedCertificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 3
     * @param document               объект документа
     * @param referenceUriId         идентификатор подписываемого элемента
     * @param privateKey             закрытый ключ ЭП
     * @param x509Certificate        сертификат ЭП
     * @param pemEncodedCertificate  сертификат ЭП в формате PEM
     * @return
     * @throws CommonSignFailureException
     */
    private static Element sign(Document document, final String referenceUriId, PrivateKey privateKey, X509Certificate x509Certificate, final String pemEncodedCertificate) throws CommonSignFailureException {
        try {
            Element contentElement = (Element) XPathUtil.selectSingleNode(document, "//*[attribute::*[contains(local-name(), '" + REFERENCE_URI_ID + "') and starts-with(., 'SIGNED_BY_')]]");

            SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

            Element signatureElem = createSignatureElements(referenceUriId, pemEncodedCertificate, signAlgorithmType);

            //вычисление значения DigestValue
            genericDigestValue(contentElement, signatureElem, signAlgorithmType);

            signDigestValue(privateKey, signAlgorithmType, signatureElem);

            return signatureElem;
        } catch (XMLSecurityException | GeneralSecurityException | RuntimeException ex) {
            throw new CommonSignFailureException(ex);
        }
    }

    /**
     * Cчитывает подпись после всех манипуляций с SignedInfo
     *
     * @param privateKey        объект закрытого ключа
     * @param signAlgorithmType алгоритм ЭП
     * @param signatureElem     объект элемента Signature
     * @throws InvalidCanonicalizerException
     * @throws CanonicalizationException
     * @throws GeneralSecurityException
     */
    private static void signDigestValue(PrivateKey privateKey, SignAlgorithmType signAlgorithmType, Element signatureElem) throws InvalidCanonicalizerException, CanonicalizationException, GeneralSecurityException {

        Node signedInfoNode = XPathUtil.selectSingleNode(signatureElem, "ds:SignedInfo");

        //считаем подпись после всех манипуляций с SignedInfo
        byte[] signatureBytes = CryptoUtil.getSignature(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                .canonicalizeSubtree(signedInfoNode), privateKey, signAlgorithmType);

        final String base64Signature = new String(Base64Util.getBase64Encoded(signatureBytes));

        XPathUtil.selectSingleNode(signatureElem, "ds:SignatureValue").setTextContent(base64Signature);
    }

    /**
     * Создаёт блок элементов ds:Signature для указания ЭП
     *
     * @param referenceUriId        идентификатор подписываемого элемента
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @param signAlgorithmType     тип алгоритма ЭП
     * @return
     * @throws RuntimeException
     */
    private static Element createSignatureElements(final String referenceUriId, final String pemEncodedCertificate, SignAlgorithmType signAlgorithmType) {

        Document document = DomUtil.newDocument();

        Element signatureElem = document.createElementNS(DS_NS, "ds:Signature");

        document.appendChild(signatureElem);

        signatureElem.setAttribute("xmlns:ds", DS_NS);

        Element signedInfoElem = (Element) signatureElem.appendChild(document.createElementNS(DS_NS, "ds:SignedInfo"));

        Element canonicalizationMethodElem = (Element) signedInfoElem.appendChild(document.createElementNS(DS_NS, "ds:CanonicalizationMethod"));

        canonicalizationMethodElem.setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        Element signatureMethodElem = (Element) signedInfoElem.appendChild(document.createElementNS(DS_NS, "ds:SignatureMethod"));

        signatureMethodElem.setAttribute("Algorithm", signAlgorithmType.getSignUri());

        Element referenceElem = (Element) signedInfoElem.appendChild(document.createElementNS(DS_NS, "ds:Reference"));

        referenceElem.setAttribute("URI", "#" + referenceUriId);

        Element transformsElem = (Element) referenceElem.appendChild(document.createElementNS(DS_NS, "ds:Transforms"));

        ((Element) transformsElem.appendChild(document.createElementNS(DS_NS, "ds:Transform"))).setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        ((Element) transformsElem.appendChild(document.createElementNS(DS_NS, "ds:Transform"))).setAttribute("Algorithm", SmevTransformSpi.ALGORITHM_URN);

        Element digestMethodElem = (Element) referenceElem.appendChild(document.createElementNS(DS_NS, "ds:DigestMethod"));

        digestMethodElem.setAttribute("Algorithm", signAlgorithmType.getDigestUri());

        referenceElem.appendChild(document.createElementNS(DS_NS, "ds:DigestValue"));

        signatureElem.appendChild(document.createElementNS(DS_NS, "ds:SignatureValue"));

        Element keyInfoElem = (Element) signatureElem.appendChild(document.createElementNS(DS_NS, "ds:KeyInfo"));

        Element x509DataElem = (Element) keyInfoElem.appendChild(document.createElementNS(DS_NS, "ds:X509Data"));

        Element x509CertificateElem = (Element) x509DataElem.appendChild(document.createElementNS(DS_NS, "ds:X509Certificate"));

        x509CertificateElem.setTextContent(pemEncodedCertificate);

        return document.getDocumentElement();
    }

    /**
     * Проставляет в элемент DigestValue рассчитанную хеш-сумму блока с бизнес-данными запроса
     *
     * @param content2sign      объект элемента, значение которого подвергается подписанию
     * @param signatureElem     объект элемента Signature
     * @param signAlgorithmType тип алгоритма ЭП
     */
    private static void genericDigestValue(final Element content2sign, final Element signatureElem, SignAlgorithmType signAlgorithmType) {

        /* получение строки трансформированного XML-элемента, в соответствии с требованиями методических рекомендаций СМЭВ */
        byte[] transformedRootElementBytes = DomUtil.getTransformedXml(content2sign);

        byte[] digestBytes = CryptoUtil.getDigest(transformedRootElementBytes, signAlgorithmType);

        final String base64Digest = new String(Base64Util.getBase64Encoded(digestBytes));

        XPathUtil.selectSingleNode(signatureElem, "ds:SignedInfo/ds:Reference/ds:DigestValue").setTextContent(base64Digest);
    }
}
