package ru.i_novus.common.sign;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xpath.XPathAPI;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.SignAlgorithmType;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class GostXmlSignature {

    public static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String BASE64_ENCODING = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    public static final String X509_V3_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

    private GostXmlSignature() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    /**
     * Определение алгоритма подписи по сертификату
     *
     * @param encodedCertificate сертификат в формате PEM
     * @return алгоритм подписи
     */
    public static SignAlgorithmType getSignAlgorithmType(String encodedCertificate) throws CertificateException, NoSuchProviderException, XMLSignatureException, AlgorithmAlreadyRegisteredException, ClassNotFoundException {
        Init.init();
        //Определяем алгоритм подписи
        ByteArrayInputStream certStream = new ByteArrayInputStream(Base64.getDecoder().decode(
                encodedCertificate.replaceAll("[\r\n]", "")));
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509","BC").generateCertificate(certStream);
        return SignAlgorithmType.valueOf(certificate.getPublicKey());
    }

    public static void addSecurityElement(SOAPMessage message, String certificate, String actor, SignAlgorithmType signAlgorithmType) throws SOAPException {
        // Добавляем элемент Security
        SOAPElement security;
        if (StringUtils.isBlank(actor)) {
            security = message.getSOAPHeader().addChildElement("Security", "wsse");
        } else {
            security = message.getSOAPHeader().addHeaderElement(new QName(WSSE_NS, "Security", "wsse"));
            ((SOAPHeaderElement) security).setActor(actor);
        }
        // Добавляем элемент Signature
        SOAPElement signature = security.addChildElement("Signature", "ds");
        // Добавляем элемент SignedInfo
        SOAPElement signedInfo = signature.addChildElement("SignedInfo", "ds");
        // Добавляем элемент CanonicalizationMethod
        signedInfo.addChildElement("CanonicalizationMethod", "ds")
                .setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        // Добавляем элемент SignatureMethod
        signedInfo.addChildElement("SignatureMethod", "ds")
                .setAttribute("Algorithm", signAlgorithmType.signUri());
        // Добавляем элемент Reference
        SOAPElement referenceSignedInfo = signedInfo.addChildElement("Reference", "ds")
                .addAttribute(new QName("URI"), "#body");
        // Добавляем элементы Transforms и Transform
        referenceSignedInfo.addChildElement("Transforms", "ds")
                .addChildElement("Transform", "ds")
                .setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        // Добавляем элемент DigestMethod
        referenceSignedInfo.addChildElement("DigestMethod", "ds")
                .setAttribute("Algorithm", signAlgorithmType.digestUri());
        // Добавляем элемент DigestValue (значение хэша считаем позже)
        referenceSignedInfo.addChildElement("DigestValue", "ds");
        // Добавляем элемент SignatureValue (значение ЭЦП считаем позже)
        signature.addChildElement("SignatureValue", "ds");
        // Добавляем элементы KeyInfo, SecurityTokenReference и Reference
        signature.addChildElement("KeyInfo", "ds")
                .addChildElement("SecurityTokenReference", "wsse")
                .addChildElement("Reference", "wsse")
                .addAttribute(new QName("URI"), "#CertId")
                .addAttribute(new QName("ValueType"), X509_V3_TYPE);
        // Добавляем элемент BinarySecurityToken
        security.addChildElement("BinarySecurityToken", "wsse")
                .addAttribute(new QName("EncodingType"), BASE64_ENCODING)
                .addAttribute(new QName("ValueType"), X509_V3_TYPE)
                .addAttribute(new QName("wsu:Id"), "CertId")
                .addTextNode(certificate);
    }

    public static void sign(SOAPMessage message, String privateKey, SignAlgorithmType signAlgorithmType) throws IOException,
            SOAPException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, GeneralSecurityException {
        // Сохраняем изменения
        message.saveChanges();
        // Делаем такое преобразование, чтобы не поломался в последующем хэш для Body
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            message.writeTo(outputStream);
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray())) {
                message.getSOAPPart().setContent(new StreamSource(inputStream));
            }
        }
        //  ВАЖНО: Считаем хэш после всех манипуляций с Body
        ((SOAPElement) XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='DigestValue']"))
                .addTextNode(CryptoUtil.getBase64Digest(
                        new String(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                                .canonicalizeSubtree(message.getSOAPBody())), signAlgorithmType));
        // ВАЖНО: Считаем подпись после всех манипуляций с SignedInfo
        ((SOAPElement) XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='SignatureValue']"))
                .addTextNode(CryptoUtil.getBase64Signature(
                        new String(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                                .canonicalizeSubtree(XPathAPI.selectSingleNode(message.getSOAPHeader(),
                                        "//*[local-name()='SignedInfo']"))),
                        privateKey, signAlgorithmType));
    }
}
