package ru.i_novus.common.sign.test;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Node;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.smev.Smev3RequestSigner;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.SoapVerifier;

import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPMessage;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static ru.i_novus.common.sign.test.SoapUtil.getSoapMessageContent;

@Slf4j
public class Smev3SignTest {
    @BeforeClass
    public static void init() {
        Init.init();
    }

    @Test
    public void testSignAckRequestGost2001() {
        signAndSimpleCheckMessage(getAckRequest(), SignAlgorithmType.ECGOST3410, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2001() {
        signAndSimpleCheckMessage(getGetRequestRequest(), SignAlgorithmType.ECGOST3410, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2001() {
        signAndSimpleCheckMessage(getGetResponseRequest(), SignAlgorithmType.ECGOST3410, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2001() {
        signAndSimpleCheckMessage(getSendRequestRequest(), SignAlgorithmType.ECGOST3410, "SendRequestRequest");
    }

    @Test
    public void testSignSendResponseRequestGost2001() {
        signAndSimpleCheckMessage(getSendResponseRequest(), SignAlgorithmType.ECGOST3410, "SendResponseRequest");
    }

    @Test
    public void testSignAckRequestGost2012_256() {
        signAndSimpleCheckMessage(getAckRequest(), SignAlgorithmType.ECGOST3410_2012_256, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2012_256() {
        signAndSimpleCheckMessage(getGetRequestRequest(), SignAlgorithmType.ECGOST3410_2012_256, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2012_256() {
        signAndSimpleCheckMessage(getGetResponseRequest(), SignAlgorithmType.ECGOST3410_2012_256, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2012_256() {
        signAndSimpleCheckMessage(getSendRequestRequest(), SignAlgorithmType.ECGOST3410_2012_256, "SendRequestRequest");
    }

    @Test
    public void testSignSendResponseRequestGost2012_256() {
        signAndSimpleCheckMessage(getSendResponseRequest(), SignAlgorithmType.ECGOST3410_2012_256, "SendResponseRequest");
    }

    @Test
    public void testSignAckRequestGost2012_512() {
        signAndSimpleCheckMessage(getAckRequest(), SignAlgorithmType.ECGOST3410_2012_512, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2012_512() {
        signAndSimpleCheckMessage(getGetRequestRequest(), SignAlgorithmType.ECGOST3410_2012_512, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2012_512() {
        signAndSimpleCheckMessage(getGetResponseRequest(), SignAlgorithmType.ECGOST3410_2012_512, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2012_512() {
        signAndSimpleCheckMessage(getSendRequestRequest(), SignAlgorithmType.ECGOST3410_2012_512, "SendRequestRequest");
    }

    @Test
    public void testSignSendResponseRequestGost2012_512() {
        signAndSimpleCheckMessage(getSendResponseRequest(), SignAlgorithmType.ECGOST3410_2012_512, "SendResponseRequest");
    }

    @SneakyThrows
    private void signAndSimpleCheckMessage(SOAPMessage message, SignAlgorithmType algorithm, String action) {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(CryptoTest.TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            signAndSimpleCheckMessage(message, keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder), action);
        }
    }

    @SneakyThrows
    private void signAndSimpleCheckMessage(SOAPMessage message, PrivateKey privateKey, X509Certificate x509Certificate, String action) {

        assertNotNull(message);

        logger.info("SMEV3 {} message before {} signature: {}", action, x509Certificate.getSigAlgName(), getSoapMessageContent(message));
        Smev3RequestSigner.sign(message, privateKey, x509Certificate);
        logger.info("SMEV3 {} message after {} signature: {}", action, x509Certificate.getSigAlgName(), getSoapMessageContent(message));

        SOAPBody soapBody = message.getSOAPBody();

        checkSignedMessage(soapBody, x509Certificate, Smev3RequestSigner.REFERENCE_URI_ATTRIBUTE_NAME);

        Node callerInformationSystemSignatureNode = XPathAPI.selectSingleNode(soapBody, "//*[local-name() = '" + Smev3RequestSigner.CALLER_INFORM_SYSTEM_SIGNATURE_ELEMENT_NAME + "']");
        callerInformationSystemSignatureNode.getParentNode().removeChild(callerInformationSystemSignatureNode);
    }

    @SneakyThrows
    private void checkSignedMessage(SOAPBody soapBody, X509Certificate x509Certificate, final String referenceUriAttributeName) {

        assertNotNull(soapBody);

        assertTrue(SoapVerifier.verifyDigest(soapBody, referenceUriAttributeName));

        assertTrue(SoapVerifier.verifySignature(x509Certificate, soapBody));
    }

    private SOAPMessage getAckRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/ackRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getGetRequestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/getRequestRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getGetResponseRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/getResponseRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getSendRequestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/sendRequestRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getSendResponseRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/sendResponseRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }
}
