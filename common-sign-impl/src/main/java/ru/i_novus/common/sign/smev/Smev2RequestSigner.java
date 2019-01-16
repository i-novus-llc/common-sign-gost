package ru.i_novus.common.sign.smev;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import ru.i_novus.common.sign.GostXmlSignature;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.exception.CommonSignFailureException;
import ru.i_novus.common.sign.exception.InvalidSiginigObjectException;
import ru.i_novus.common.sign.util.Base64Util;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoIO;

import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
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
     * @param message               сообщение
     * @param pemEncodedCertificate сертификат ЭП в формате PEM
     * @param pemEncodedPrivateKey  закрытый ключ в формате PEM
     * @throws CommonSignFailureException
     */
    public static void signWithPEM(SOAPMessage message, String pemEncodedCertificate, String pemEncodedPrivateKey) throws CommonSignFailureException {
        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate certificate = converter.getCertificateFromPEMEncoded(pemEncodedCertificate);
        PrivateKey privateKey = converter.getPKFromPEMEncoded(SignAlgorithmType.findByCertificate(certificate), pemEncodedPrivateKey);
        sign(message, privateKey, certificate);
    }

    /**
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message    сообщение
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
     * Подписывает SOAP-запрос для сервиса СМЭВ 2
     *
     * @param message     сообщение
     * @param privateKey  закрытый ключ в формате {@link PrivateKey}
     * @param certificate сертификат в формате {@link X509Certificate}
     * @throws CommonSignFailureException
     */
    public static void sign(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate) throws CommonSignFailureException {

        try {
            // Добавляем требуемые пространства имен
            addNamespaceDeclaration(message.getSOAPPart().getEnvelope());

            // Проставляем идентификатор для элемента Body
            setBodyIdAttribute(message.getSOAPBody());

            SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);

            // Добавляем элемент Security
            GostXmlSignature.addSecurityElement(message, CryptoFormatConverter.getInstance().getPEMEncodedCertificate(certificate),
                    "http://smev.gosuslugi.ru/actors/smev", signAlgorithmType);
            // Подписываем сообщение
            GostXmlSignature.sign(message, privateKey, signAlgorithmType);

        } catch (SOAPException | RuntimeException e) {
            throw new CommonSignFailureException(e);
        }

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
    @Deprecated
    public static void signSmevRequest(SOAPMessage message, String encodedCertificate, String encodedKey) throws SOAPException,
            InvalidCanonicalizerException, GeneralSecurityException, TransformerException, CanonicalizationException, IOException {
        try {
            signWithPEM(message, encodedCertificate, encodedKey);
        } catch (CommonSignFailureException e) {
            throw new RuntimeException(e);
        }
    }

    private static void addNamespaceDeclaration(SOAPEnvelope soapEnvelope) throws SOAPException {
        soapEnvelope.addNamespaceDeclaration("wsse", WSSE_NS)
                .addNamespaceDeclaration("wsu", WSU_NS)
                .addNamespaceDeclaration("ds", DS_NS);
    }

    private static void setBodyIdAttribute(SOAPBody soapBody) {
        soapBody.setAttribute("wsu:Id", "body");
    }
}
