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

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xpath.XPathAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.context.DSNamespaceContext;
import ru.i_novus.common.sign.util.*;

import jakarta.xml.soap.SOAPBody;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Smev3Verifier {
    private static final Logger logger = LoggerFactory.getLogger(Smev3Verifier.class);

    private Smev3Verifier() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static boolean verifyDigest(SOAPBody soapBody, final String referenceUriAttributeName, final String digestMethodAlgorithmURI) throws TransformerException, XPathExpressionException, IOException, TransformationException {
        DSNamespaceContext dsNamespaceContext = new DSNamespaceContext();
        Element signatureElem = (Element) XPathUtil.evaluate("//*[local-name() = 'Signature']", soapBody, dsNamespaceContext);
        Element contentElem = (Element) XPathAPI.selectSingleNode(soapBody, "//*[attribute::*[contains(local-name(), '" + referenceUriAttributeName + "' )]]");
        return verifyDigest(contentElem, signatureElem, digestMethodAlgorithmURI);
    }

    public static boolean verifyDigest(Element contentElem, Element signatureElem, final String digestMethodAlgorithmURI) throws XPathExpressionException, TransformationException, TransformerException, IOException {

        final String digestValue = XPathUtil.evaluateString("ds:SignedInfo/ds:Reference/ds:DigestValue/text()", signatureElem, new DSNamespaceContext());

        final String pemEncodedCertificate = XPathUtil.evaluateString("ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()", signatureElem, new DSNamespaceContext());

        X509Certificate x509Certificate = CryptoFormatConverter.getInstance().getCertificateFromPEMEncoded(pemEncodedCertificate);

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

        final String digestMethodAlgorithm = XPathUtil.evaluateString("ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm", signatureElem, new DSNamespaceContext());

        if (!digestMethodAlgorithmURI.equals(digestMethodAlgorithm)) {
            return false;
        }

        byte[] transformedRootElementBytes = Smev3Util.getTransformedXml(contentElem);

        byte[] transformedDocument = CryptoUtil.getDigest(transformedRootElementBytes, signAlgorithmType);

        final String encodedDigestedDocumentCanonicalized = new String(Base64.getEncoder().encode(transformedDocument));

        return encodedDigestedDocumentCanonicalized.equals(digestValue);
    }

    public static boolean verifySignature(X509Certificate x509Certificate, SOAPBody soapBody, final String signatureMethodAlgorithmURI) throws XMLSecurityException, GeneralSecurityException, XPathExpressionException {
        DSNamespaceContext dsNamespaceContext = new DSNamespaceContext();
        Element signatureElem = (Element) XPathUtil.evaluate("//*[local-name() = 'Signature']", soapBody, dsNamespaceContext);
        return verifySignature(x509Certificate, signatureElem, signatureMethodAlgorithmURI);
    }

    public static boolean verifySignature(X509Certificate x509Certificate, final Element signatureElement, final String signatureMethodAlgorithmURI) throws XMLSecurityException, GeneralSecurityException, XPathExpressionException {

        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(x509Certificate);

        Element signedInfoElement = (Element) XPathUtil.evaluate("//*[local-name() = 'SignedInfo']", signatureElement, new DSNamespaceContext());

        Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        canonicalizer.canonicalizeSubtree(signedInfoElement, buffer);
        byte[] canonicalizedSignedInfo = buffer.toByteArray();

        String encodedSignatureValue = XPathUtil.evaluateString("ds:SignatureValue/text()", signatureElement, new DSNamespaceContext());

        if (encodedSignatureValue == null) {
            throw new RuntimeException("retrieving encoded signature value");
        }

        byte[] decodedSignatureValue = Base64Util.getBase64Decoded(encodedSignatureValue.trim());

        final String signatureMethodAlgorithm = XPathUtil.evaluateString("ds:SignatureMethod/@Algorithm", signedInfoElement, new DSNamespaceContext());

        if (signatureMethodAlgorithm == null) {
            throw new RuntimeException("retrieving signature method algorithm");
        }

        if (!signatureMethodAlgorithmURI.equals(signatureMethodAlgorithm)) {
            return false;
        }

        Signature signatureEngine = CryptoUtil.getSignatureInstance(signAlgorithmType);

        signatureEngine.initVerify(x509Certificate);

        signatureEngine.update(canonicalizedSignedInfo);

        return signatureEngine.verify(decodedSignatureValue);
    }

}
