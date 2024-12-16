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
package ru.i_novus.common.sign.test.smev3;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Node;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.smev3.Smev3Init;
import ru.i_novus.common.sign.smev3.Smev3RequestSigner;
import ru.i_novus.common.sign.smev3.Smev3Verifier;
import ru.i_novus.common.sign.soap.SoapUtil;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;

import jakarta.xml.soap.SOAPBody;
import jakarta.xml.soap.SOAPConstants;
import jakarta.xml.soap.SOAPMessage;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Slf4j
public class Smev3SignTest {
    private static final String TEST_CERTIFICATE_CN = "CN=I-Novus Employee, O=I-Novus LLC, E=office@i-novus.ru, L=Kazan, C=RU, STREET=Kachalova 75";

    @BeforeClass
    public static void init() {
        Smev3Init.init();
    }

    @Test
    public void testSignAckRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getAckRequest(), SignAlgorithmType.ECGOST3410, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getGetRequestRequest(), SignAlgorithmType.ECGOST3410, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getGetResponseRequest(), SignAlgorithmType.ECGOST3410, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getSendRequestRequest(), SignAlgorithmType.ECGOST3410, "SendRequestRequest");
    }

    @Test
    public void testSignSendResponseRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getSendResponseRequest(), SignAlgorithmType.ECGOST3410, "SendResponseRequest");
    }

    @Test
    public void testSignAckRequestGost2012_256() throws Exception {
        signAndSimpleCheckMessage(getAckRequest(), SignAlgorithmType.ECGOST3410_2012_256, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2012_256() throws Exception {
        signAndSimpleCheckMessage(getGetRequestRequest(), SignAlgorithmType.ECGOST3410_2012_256, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2012_256() throws Exception {
        signAndSimpleCheckMessage(getGetResponseRequest(), SignAlgorithmType.ECGOST3410_2012_256, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2012_256() throws Exception {
        signAndSimpleCheckMessage(getSendRequestRequest(), SignAlgorithmType.ECGOST3410_2012_256, "SendRequestRequest");
    }

    @Test
    public void testSignSendResponseRequestGost2012_256() throws Exception {
        signAndSimpleCheckMessage(getSendResponseRequest(), SignAlgorithmType.ECGOST3410_2012_256, "SendResponseRequest");
    }

    @Test
    public void testSignAckRequestGost2012_512() throws Exception {
        signAndSimpleCheckMessage(getAckRequest(), SignAlgorithmType.ECGOST3410_2012_512, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2012_512() throws Exception {
        signAndSimpleCheckMessage(getGetRequestRequest(), SignAlgorithmType.ECGOST3410_2012_512, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2012_512() throws Exception {
        signAndSimpleCheckMessage(getGetResponseRequest(), SignAlgorithmType.ECGOST3410_2012_512, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2012_512() throws Exception {
        signAndSimpleCheckMessage(getSendRequestRequest(), SignAlgorithmType.ECGOST3410_2012_512, "SendRequestRequest");
    }

    @Test
    public void testSignSendResponseRequestGost2012_512() throws Exception {
        signAndSimpleCheckMessage(getSendResponseRequest(), SignAlgorithmType.ECGOST3410_2012_512, "SendResponseRequest");
    }

    private void signAndSimpleCheckMessage(SOAPMessage message, SignAlgorithmType algorithm, String action) throws Exception {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            signAndSimpleCheckMessage(message, keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder), action, algorithm);
        }
    }

    private void signAndSimpleCheckMessage(SOAPMessage message, PrivateKey privateKey, X509Certificate x509Certificate, String action, SignAlgorithmType signAlgorithmType) throws Exception {

        assertNotNull(message);

        logger.info("SMEV3 {} message before {} signature: {}", action, x509Certificate.getSigAlgName(), SoapUtil.getSoapMessageContent(message));
        Smev3RequestSigner.sign(message, privateKey, x509Certificate);
        logger.info("SMEV3 {} message after {} signature: {}", action, x509Certificate.getSigAlgName(), SoapUtil.getSoapMessageContent(message));

        SOAPBody soapBody = message.getSOAPBody();

        checkSignedMessage(soapBody, x509Certificate, Smev3RequestSigner.REFERENCE_URI_ATTRIBUTE_NAME, signAlgorithmType);

        Node callerInformationSystemSignatureNode = XPathAPI.selectSingleNode(soapBody, "//*[local-name() = '" + Smev3RequestSigner.CALLER_INFORM_SYSTEM_SIGNATURE_ELEMENT_NAME + "']");
        callerInformationSystemSignatureNode.getParentNode().removeChild(callerInformationSystemSignatureNode);
    }

    private void checkSignedMessage(SOAPBody soapBody, X509Certificate x509Certificate, final String referenceUriAttributeName, SignAlgorithmType signAlgorithmType)  throws Exception {

        assertNotNull(soapBody);

        assertTrue(Smev3Verifier.verifyDigest(soapBody, referenceUriAttributeName, Smev3RequestSigner.getDigestMethodAlgorithm(signAlgorithmType)));

        assertTrue(Smev3Verifier.verifySignature(x509Certificate, soapBody, Smev3RequestSigner.getSignatureMethodAlgorithm(signAlgorithmType)));
    }

    private SOAPMessage getAckRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev3/ackRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getGetRequestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev3/getRequestRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getGetResponseRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev3/getResponseRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getSendRequestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev3/sendRequestRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getSendResponseRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev3/sendResponseRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }
}
