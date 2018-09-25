package ru.i_novus.common.sign.ips;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Node;
import ru.i_novus.common.sign.GostXmlSignature;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.util.SignAlgorithmType;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.GeneralSecurityException;
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
     * @param message сообщение
     * @param soapService адрес сервиса в ИПС
     * @param soapAction действие сервиса
     * @param clientEntityId идентификатор системы
     * @param encodedCertificate сертификат
     * @param privateKey закрытый ключ
     */
    public static void signIpsRequest(SOAPMessage message, String soapService, String soapAction, String clientEntityId,
                                      String encodedCertificate, String privateKey) throws XMLSignatureException, AlgorithmAlreadyRegisteredException,
            ClassNotFoundException, SOAPException, GeneralSecurityException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, IOException {
        // Инициализируем библиотеку XML-security
        Init.init();
        // Добавляем требуемые пространства имен
        message.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS)
                .addNamespaceDeclaration("wsa", WSA_NS);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", "body");
        // Добавляем элементы transportHeader, authInfo и clientEntityId
        Node transportHeader = XPathAPI.selectSingleNode(message.getSOAPHeader(),
                "//*[local-name()='transportHeader']/*[local-name()='authInfo']/*[local-name()='clientEntityId']");
        if (transportHeader == null) {
            message.getSOAPHeader().addChildElement(new QName(EGISZ_NS, "transportHeader", EGISZ_PREFIX))
                    .addChildElement("authInfo", EGISZ_PREFIX)
                    .addChildElement("clientEntityId", EGISZ_PREFIX)
                    .addTextNode(clientEntityId);
        }
        // Добавляем элементы MessageID, Action и To
        Node messageId = XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='MessageID']");
        if (messageId == null) {
            message.getSOAPHeader().addChildElement("MessageID", "wsa").addTextNode(UUID.randomUUID().toString());
        }
        Node action = XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='Action']");
        if (action == null) {
            message.getSOAPHeader().addChildElement("Action", "wsa").addTextNode(soapAction);
        }
        Node to = XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='To']");
        if (to == null) {
            message.getSOAPHeader().addChildElement("To", "wsa").addTextNode(soapService);
        }
        SignAlgorithmType signAlgorithmType = GostXmlSignature.getSignAlgorithmType(encodedCertificate);
        // Добавляем элемент Security
        GostXmlSignature.addSecurityElement(message, encodedCertificate, null, signAlgorithmType);
        // Подписываем сообщение
        GostXmlSignature.sign(message, privateKey, signAlgorithmType);
    }

    /**
     * Подписывает SOAP-ответ для сервиса ИПС
     *
     * @param message сообщение
     * @param encodedCertificate сертификат
     * @param privateKey закрытый ключ
     */
    public static void signIpsResponse(SOAPMessage message, String encodedCertificate, String privateKey) throws SOAPException,
            XMLSignatureException, AlgorithmAlreadyRegisteredException, ClassNotFoundException, TransformerException,
            GeneralSecurityException, InvalidCanonicalizerException, CanonicalizationException, IOException {
        // Инициализируем библиотеку XML-security
        Init.init();
        // Добавляем требуемые пространства имен
        message.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS)
                .addNamespaceDeclaration("wsa", WSA_NS);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", "body");
        // Добавляем элементы MessageID
        Node messageId = XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='MessageID']");
        if (messageId == null) {
            message.getSOAPHeader().addChildElement("MessageID", "wsa").addTextNode(UUID.randomUUID().toString());
        }
        SignAlgorithmType signAlgorithmType = GostXmlSignature.getSignAlgorithmType(encodedCertificate);
        // Добавляем элемент Security
        GostXmlSignature.addSecurityElement(message, encodedCertificate, null, signAlgorithmType);
        // Подписываем сообщение
        GostXmlSignature.sign(message, privateKey, signAlgorithmType);
    }
}
