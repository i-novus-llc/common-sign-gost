package ru.i_novus.common.sign.smev;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.signature.XMLSignatureException;
import ru.i_novus.common.sign.GostXmlSignature;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.util.SignAlgorithmType;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static ru.i_novus.common.sign.GostXmlSignature.DS_NS;
import static ru.i_novus.common.sign.GostXmlSignature.WSSE_NS;
import static ru.i_novus.common.sign.GostXmlSignature.WSU_NS;

public final class Smev2RequestSigner {
    private Smev2RequestSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message сообщение
     * @param encodedCertificate сертификат
     * @param privateKey закрытый ключ
     */
    public static void signSmevRequest(SOAPMessage message, String encodedCertificate, String privateKey) throws SOAPException,
            InvalidCanonicalizerException, GeneralSecurityException, TransformerException, CanonicalizationException, IOException,
            XMLSignatureException, AlgorithmAlreadyRegisteredException, ClassNotFoundException {
        // Инициализируем библиотеку XML-security
        Init.init();
        // Добавляем требуемые пространства имен
        message.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS);
        // Проставляем идентификатор для элемента Body
        message.getSOAPBody().setAttribute("wsu:Id", "body");
        SignAlgorithmType signAlgorithmType = GostXmlSignature.getSignAlgorithmType(encodedCertificate);
        // Добавляем элемент Security
        GostXmlSignature.addSecurityElement(message, encodedCertificate, "http://smev.gosuslugi.ru/actors/smev", signAlgorithmType);
        // Подписываем сообщение
        GostXmlSignature.sign(message, privateKey, signAlgorithmType);
    }
}
