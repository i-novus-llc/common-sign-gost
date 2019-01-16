package ru.i_novus.common.sign.ips;

import org.apache.xpath.XPathAPI;
import org.w3c.dom.Node;
import ru.i_novus.common.sign.GostXmlSignature;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.exception.CommonSignFailureException;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.XPathUtil;

import javax.xml.namespace.QName;
import javax.xml.soap.*;
import javax.xml.transform.TransformerException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

import static ru.i_novus.common.sign.GostXmlSignature.DS_NS;
import static ru.i_novus.common.sign.GostXmlSignature.WSSE_NS;
import static ru.i_novus.common.sign.GostXmlSignature.WSU_NS;

public final class IpsRequestSigner {
    private static final String WSA_NS = "http://www.w3.org/2005/08/addressing";
    private static final String EGISZ_NS = "http://egisz.rosminzdrav.ru";
    private static final String EGISZ_PREFIX = "egisz";

    private IpsRequestSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
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
     * @throws CommonSignFailureException
     */
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId,
                                      String encodedCertificate, String encodedPrivateKey) throws CommonSignFailureException {

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
     * @throws CommonSignFailureException
     */
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId, PrivateKey privateKey, X509Certificate certificate) throws CommonSignFailureException {

        try {

            // Добавляем требуемые пространства имен
            addNamespaceDeclaration(message.getSOAPPart().getEnvelope());

            // Проставляем идентификатор для элемента Body
            setBodyIdAttribute(message.getSOAPBody());

            SOAPHeader soapHeader = message.getSOAPHeader();

            // Добавляем элементы transportHeader, authInfo и clientEntityId
            addTransportHeaderElem(soapHeader, clientEntityId);

            // Добавляем элементы MessageID, Action и To
            addMessageIdElem(soapHeader);

            addActionElem(soapHeader, soapAction);

            addToElem(message, soapService);

            SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByAlgorithmName(certificate.getSigAlgName());
            // Добавляем элемент Security
            GostXmlSignature.addSecurityElement(message, certificate, null);
            // Подписываем сообщение
            GostXmlSignature.sign(message, privateKey, signAlgorithmType);

        } catch (SOAPException | TransformerException | RuntimeException e) {
            throw new CommonSignFailureException(e);
        }
    }

    /**
     * Подписывает SOAP-ответ для сервиса ИПС
     *
     * @param message            сообщение
     * @param encodedCertificate сертификат в формате PEM
     * @param encodedKey         закрытый ключ в формате PEM
     * @throws CommonSignFailureException
     */
    public static void signIpsResponse(SOAPMessage message, String encodedCertificate, String encodedKey) throws CommonSignFailureException {
        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate certificate = converter.getCertificateFromPEMEncoded(encodedCertificate);
        signIpsResponse(message, converter.getPKFromPEMEncoded(SignAlgorithmType.findByCertificate(certificate), encodedKey), certificate);
    }

    /**
     * Подписывает SOAP-ответ для сервиса ИПС
     *
     * @param message     сообщение
     * @param privateKey  закрытый ключ в формате PEM
     * @param certificate сертификат в формате PEM
     * @throws CommonSignFailureException
     */
    public static void signIpsResponse(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate) throws CommonSignFailureException {

        try {
            // Добавляем требуемые пространства имен
            addNamespaceDeclaration(message.getSOAPPart().getEnvelope());

            // Проставляем идентификатор для элемента Body
            setBodyIdAttribute(message.getSOAPBody());

            // Добавляем элемент MessageID
            addMessageIdElem(message.getSOAPHeader());

            // Добавляем элемент Security
            GostXmlSignature.addSecurityElement(message, certificate, null);
            // Подписываем сообщение
            GostXmlSignature.sign(message, privateKey, SignAlgorithmType.findByCertificate(certificate));

        } catch (SOAPException | TransformerException | RuntimeException e) {
            throw new CommonSignFailureException(e);
        }
    }

    private static void addMessageIdElem(SOAPHeader soapHeader) throws TransformerException, SOAPException {
        Node messageId = XPathAPI.selectSingleNode(soapHeader, "//*[local-name()='MessageID']");
        if (messageId == null)
            soapHeader.addChildElement("MessageID", "wsa").addTextNode(UUID.randomUUID().toString());
    }

    private static void addTransportHeaderElem(SOAPHeader soapHeader, final String clientEntityId) throws TransformerException, SOAPException {

        Node transportHeader = XPathUtil.selectSingleNode(soapHeader,
                "//*[local-name()='transportHeader']/*[local-name()='authInfo']/*[local-name()='clientEntityId']");

        if (transportHeader == null)
            soapHeader.addChildElement(new QName(EGISZ_NS, "transportHeader", EGISZ_PREFIX))
                    .addChildElement("authInfo", EGISZ_PREFIX)
                    .addChildElement("clientEntityId", EGISZ_PREFIX)
                    .addTextNode(clientEntityId);
    }

    private static void addActionElem(SOAPHeader soapHeader, final String soapAction) throws TransformerException, SOAPException {
        Node action = XPathUtil.selectSingleNode(soapHeader, "//*[local-name()='Action']");
        if (action == null)
            soapHeader.addChildElement("Action", "wsa").addTextNode(soapAction);
    }

    private static void addToElem(SOAPMessage message, String soapService) throws SOAPException {
        Node to = XPathUtil.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='To']");
        if (to == null)
            message.getSOAPHeader().addChildElement("To", "wsa").addTextNode(soapService);
    }

    private static void setBodyIdAttribute(SOAPBody soapBody) {
        soapBody.setAttribute("wsu:Id", "body");
    }

    private static void addNamespaceDeclaration(SOAPEnvelope soapEnvelope) throws SOAPException {
        soapEnvelope.addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS)
                .addNamespaceDeclaration("wsa", WSA_NS);
    }
}
