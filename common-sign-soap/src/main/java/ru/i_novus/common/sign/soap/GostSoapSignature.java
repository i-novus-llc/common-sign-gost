package ru.i_novus.common.sign.soap;

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

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.soap.dto.SecurityElementInfo;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.DomUtil;

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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import static ru.i_novus.common.sign.util.Base64Util.getBase64EncodedString;

public class GostSoapSignature {

    public static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String BASE64_ENCODING = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    public static final String X509_V3_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    public static final String BODY_REFERENCE_ID = "body";
    public static final String DIGEST_VALUE_LOCAL_NAME = "DigestValue";
    public static final String CERT_ID_LOCAL_NAME = "CertId";
    public static final String REFERENCE_LIST_XPATH = "//*[@wsu:Id[namespace-uri()='" + WSU_NS + "'] and not(local-name()='BinarySecurityToken') and not(local-name()='RelatesTo')]";

    private GostSoapSignature() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static void addSecurityElement(SecurityElementInfo securityElemInfo) throws SOAPException {

        final String actor = securityElemInfo.getActor();
        final SOAPMessage message = securityElemInfo.getMessage();
        final SignAlgorithmType signAlgorithmType = securityElemInfo.getSignAlgorithmType();

        // Добавляем элемент Security
        SOAPElement securityElem;
        if (StringUtils.isBlank(actor)) {
            securityElem = message.getSOAPHeader().addChildElement("Security", "wsse");
        } else {
            securityElem = message.getSOAPHeader().addHeaderElement(new QName(WSSE_NS, "Security", "wsse"));
            ((SOAPHeaderElement) securityElem).setActor(actor);
        }

        final String x509ReferenceId ="X509-"+ UUID.randomUUID().toString();
        final String encodedCertificate = CryptoFormatConverter.getInstance().getPEMEncodedCertificate(securityElemInfo.getCertificate());

        // Добавляем элемент BinarySecurityToken
        addBinarySecurityTokenElement(securityElem, x509ReferenceId, encodedCertificate);
        // Добавляем элемент Signature
        SOAPElement signature = securityElem.addChildElement("Signature", "ds");
        signature.setAttribute("Id", "SIG-" + UUID.randomUUID().toString());
        // Добавляем элемент SignedInfo
        SOAPElement signedInfo = signature.addChildElement("SignedInfo", "ds");
        // Добавляем элемент CanonicalizationMethod
        signedInfo.addChildElement("CanonicalizationMethod", "ds")
                .setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        // Добавляем элемент SignatureMethod
        signedInfo.addChildElement("SignatureMethod", "ds")
                .setAttribute("Algorithm", securityElemInfo.getSignAlgorithmType().getSignUri());
        // Добавляем элемент Reference для //Body
        addReferenceElement(signAlgorithmType, signedInfo, securityElemInfo.getBodyReferenceId());

        final String timestampReferenceId = "TS-" + UUID.randomUUID().toString();
        // Добавляем элемент Reference для //Timestamp
        addReferenceElement(signAlgorithmType, signedInfo, timestampReferenceId);
        // Добавляем элемент Reference для //MessageId
        addReferenceElement(signAlgorithmType, signedInfo, securityElemInfo.getMessageIdReferenceId());
        // Добавляем элемент Reference для //ReplyTo
        addReferenceElement(signAlgorithmType, signedInfo, securityElemInfo.getReplyToReferenceId());
        // Добавляем элемент Reference для //To
        addReferenceElement(signAlgorithmType, signedInfo, securityElemInfo.getToReferenceId());
        // Добавляем элемент Reference для //Action
        addReferenceElement(signAlgorithmType, signedInfo, securityElemInfo.getActionReferenceId());
        // Добавляем элемент SignatureValue (значение ЭЦП считаем позже)
        signature.addChildElement("SignatureValue", "ds");
        // Добавляем элементы KeyInfo, SecurityTokenReference и Reference
        addKeyInfoElementWithId(signature, x509ReferenceId);
        //Добавляем элемент Timestamp
        addTimestampElement(securityElem, securityElemInfo.getExpireDateTime(), timestampReferenceId);
    }

    public static void addSecurityElement(SOAPMessage message, String encodedCertificate, String actor, SignAlgorithmType signAlgorithmType) throws SOAPException {
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
                .setAttribute("Algorithm", signAlgorithmType.getSignUri());
        // Добавляем элемент Reference
        addReferenceElement(signAlgorithmType, signedInfo, BODY_REFERENCE_ID);
        // Добавляем элемент SignatureValue (значение ЭЦП считаем позже)
        signature.addChildElement("SignatureValue", "ds");
        // Добавляем элементы KeyInfo, SecurityTokenReference и Reference
        addKeyInfoElement(signature, CERT_ID_LOCAL_NAME);
        // Добавляем элемент BinarySecurityToken
        addBinarySecurityTokenElement(security, CERT_ID_LOCAL_NAME, encodedCertificate);
    }

    public static void addSecurityElement(SOAPMessage message, X509Certificate certificate, String actor)
            throws SOAPException {
        addSecurityElement(message, CryptoFormatConverter.getInstance().getPEMEncodedCertificate(certificate), actor, SignAlgorithmType.findByCertificate(certificate));
    }

    public static void sign(SOAPMessage message, String encodedPrivateKey, SignAlgorithmType signAlgorithmType) throws IOException,
            SOAPException, TransformerException, InvalidCanonicalizerException, CanonicalizationException, GeneralSecurityException {

        PrivateKey privateKey = CryptoFormatConverter.getInstance().getPKFromPEMEncoded(signAlgorithmType, encodedPrivateKey);
        sign(message, privateKey, signAlgorithmType);
    }

    public static void sign(SOAPMessage message, PrivateKey privateKey, SignAlgorithmType signAlgorithmType) throws IOException,
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

        NodeList referenceNodeList = XPathAPI.selectNodeList(message.getSOAPHeader(), REFERENCE_LIST_XPATH);

        try (ByteArrayOutputStream tempBuffer = new ByteArrayOutputStream()) {

            for (Node node : DomUtil.iterable(referenceNodeList)) {
                addDigestValue(message, signAlgorithmType, tempBuffer, node);
            }

            tempBuffer.reset();

            signSignedInfo(message, privateKey, signAlgorithmType, tempBuffer);
        }
    }

    private static void signSignedInfo(SOAPMessage message, PrivateKey privateKey, SignAlgorithmType signAlgorithmType, ByteArrayOutputStream tempBuffer) throws CanonicalizationException, InvalidCanonicalizerException, TransformerException, SOAPException, GeneralSecurityException {
        Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                .canonicalizeSubtree(XPathAPI.selectSingleNode(message.getSOAPHeader(),
                        "//*[local-name()='SignedInfo']"), tempBuffer);
        byte[] signature = CryptoUtil.getSignature(tempBuffer.toByteArray(), privateKey, signAlgorithmType);

        ((SOAPElement) XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='SignatureValue']"))
                .addTextNode(getBase64EncodedString(signature));
    }

    private static void addDigestValue(SOAPMessage message, SignAlgorithmType signAlgorithmType, ByteArrayOutputStream tempBuffer, Node node) throws TransformerException, SOAPException, CanonicalizationException, InvalidCanonicalizerException {

        final String id = node.getAttributes().getNamedItem("wsu:Id").getNodeValue();

        Node referenceNode = XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='Reference' and @URI='#" + id + "']");

        if (referenceNode != null) {

            Node digestValueNode = referenceNode.getLastChild();

            if (digestValueNode != null && DIGEST_VALUE_LOCAL_NAME.equals(digestValueNode.getLocalName())) {

                tempBuffer.reset();

                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalizeSubtree(node, tempBuffer);
                final String digestValue = CryptoUtil.getBase64Digest(new String(tempBuffer.toByteArray()), signAlgorithmType);
                ((SOAPElement) digestValueNode).addTextNode(digestValue);
            }
        }
    }

    private static void addReferenceElement(SignAlgorithmType signAlgorithmType, SOAPElement signedInfo, final String referenceURI) throws SOAPException {
        // Добавляем элемент Reference для body
        SOAPElement referenceElem = signedInfo.addChildElement("Reference", "ds")
                .addAttribute(new QName("URI"), "#" + referenceURI);
        // Добавляем элементы Transforms и Transform
        referenceElem.addChildElement("Transforms", "ds")
                .addChildElement("Transform", "ds")
                .setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        // Добавляем элемент DigestMethod
        referenceElem.addChildElement("DigestMethod", "ds")
                .setAttribute("Algorithm", signAlgorithmType.getDigestUri());
        // Добавляем элемент DigestValue (значение хэша считаем позже)
        referenceElem.addChildElement("DigestValue", "ds");
    }

    private static void addTimestampElement(SOAPElement securityElem, final ZonedDateTime expireDateTime, final String timestampReferenceId) throws SOAPException {
        SOAPElement timestampElem = securityElem.addChildElement(new QName(WSU_NS, "Timestamp", "wsu"));
        timestampElem.setAttribute("wsu:Id", timestampReferenceId);
        timestampElem.addChildElement(new QName(WSU_NS, "Created", "wsu"))
                .setTextContent(ZonedDateTime.now().format(DATE_TIME_FORMATTER));
        timestampElem.addChildElement(new QName(WSU_NS, "Expires", "wsu"))
                .setTextContent(expireDateTime.format(DATE_TIME_FORMATTER));
    }

    private static void addBinarySecurityTokenElement(SOAPElement security, final String x509ReferenceId, final String encodedCertificate) throws SOAPException {
        security.addChildElement("BinarySecurityToken", "wsse")
                .addAttribute(new QName("EncodingType"), BASE64_ENCODING)
                .addAttribute(new QName("ValueType"), X509_V3_TYPE)
                .addAttribute(new QName("wsu:Id"), x509ReferenceId)
                .addTextNode(encodedCertificate);
    }

    private static void addKeyInfoElement(SOAPElement signature, final String x509ReferenceId) throws SOAPException {
        signature.addChildElement("KeyInfo", "ds")
                .addChildElement("SecurityTokenReference", "wsse")
                .addChildElement("Reference", "wsse")
                .addAttribute(new QName("URI"), "#" + x509ReferenceId)
                .addAttribute(new QName("ValueType"), X509_V3_TYPE);
    }

    private static void addKeyInfoElementWithId(SOAPElement signature, final String x509ReferenceId) throws SOAPException {
        SOAPElement keyInfoElem = signature.addChildElement("KeyInfo", "ds");
        keyInfoElem.setAttribute("Id", "KI-" + UUID.randomUUID().toString());

        SOAPElement securityTokenReferenceElem = keyInfoElem.addChildElement("SecurityTokenReference", "wsse");
        securityTokenReferenceElem.setAttribute("wsu:Id", "STR-" + UUID.randomUUID().toString());

        securityTokenReferenceElem.addChildElement("Reference", "wsse")
                .addAttribute(new QName("URI"), "#" + x509ReferenceId)
                .addAttribute(new QName("ValueType"), X509_V3_TYPE);
    }
}
