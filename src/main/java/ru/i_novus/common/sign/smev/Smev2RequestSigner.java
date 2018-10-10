package ru.i_novus.common.sign.smev;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import ru.i_novus.common.sign.GostXmlSignature;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.SignAlgorithmType;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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
     * @param encodedKey закрытый ключ в формате PEM
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
     * @param message сообщение
     * @param privateKey закрытый ключ в формате {@link PrivateKey}
     * @param certificate сертификат в формате {@link X509Certificate}
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
        GostXmlSignature.addSecurityElement(message, CryptoFormatConverter.getInstance().getPEMEncodedCertificate(certificate),
                "http://smev.gosuslugi.ru/actors/smev", signAlgorithmType);
        // Подписываем сообщение
        GostXmlSignature.sign(message, privateKey, signAlgorithmType);
    }
}
