package ru.i_novus.common.sign.smev;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import ru.i_novus.common.sign.GostXmlSignature;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.util.Base64Util;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoIO;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
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
     * @throws SOAPException
     * @throws InvalidCanonicalizerException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws CanonicalizationException
     * @throws IOException
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
     * @param pfxEncoded       двоичные данные файла файла PKCS#12 закодированный в Base64
     * @param keystorePassword пароль к закрытому ключу
     * @throws IOException
     * @throws XMLSecurityException
     * @throws SOAPException
     * @throws GeneralSecurityException
     * @throws TransformerException
     */
    public static void signSmev3RequestWithPkcs12(SOAPMessage message, String pfxEncoded, String keystorePassword) throws IOException, XMLSecurityException, SOAPException, GeneralSecurityException, TransformerException {

        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64Util.getBase64Decoded(pfxEncoded))) {

            KeyStore $ex = cryptoIO.getPkcs12KeyStore(inputStream, keystorePassword);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12($ex, keystorePassword);

            X509Certificate x509Certificate = cryptoIO.readCertificateFromPKCS12($ex);

            signSmevRequest(message, privateKey, x509Certificate);
        }
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message сообщение
     * @param privateKey закрытый ключ в формате {@link PrivateKey}
     * @param certificate сертификат в формате {@link X509Certificate}
     * @throws SOAPException
     * @throws InvalidCanonicalizerException
     * @throws GeneralSecurityException
     * @throws TransformerException
     * @throws CanonicalizationException
     * @throws IOException
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