package ru.i_novus.common.sign.test;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.ips.IpsRequestSigner;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.SignAlgorithmType;

import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;
import static ru.i_novus.common.sign.test.SoapUtil.getSoapMessageContent;

@Slf4j
public class IpsSignTest {
    @BeforeClass
    public static void init() {
        Init.init();
    }

    @Test
    public void testSignIpsRequestGost2001() {
        testSignIpsRequest(SignAlgorithmType.ECGOST3410);
    }

    @Test
    public void testSignIpsResponseGost2001() {
        testSignIpsResponse(SignAlgorithmType.ECGOST3410);
    }

    @Test
    public void testSignIpsRequestGost2012_256() {
        testSignIpsRequest(SignAlgorithmType.ECGOST3410_2012_256);
    }

    @Test
    public void testSignIpsResponseGost2012_256() {
        testSignIpsResponse(SignAlgorithmType.ECGOST3410_2012_256);
    }

    @Test
    public void testSignIpsRequestGost2012_512() {
        testSignIpsRequest(SignAlgorithmType.ECGOST3410_2012_512);
    }

    @Test
    public void testSignIpsResponseGost2012_512() {
        testSignIpsResponse(SignAlgorithmType.ECGOST3410_2012_512);
    }

    private void testSignIpsRequest(SignAlgorithmType algorithm) {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(CryptoTest.TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            testSignIpsRequest(keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder));
        }
    }

    @SneakyThrows
    private void testSignIpsRequest(PrivateKey privateKey, X509Certificate certificate) {
        logger.info("Prepare IPS Request signature for algorithm {}", certificate.getSigAlgName());

        SOAPMessage message = getIpsTestRequest();
        logger.info("IPS Request message before signature: {}", getSoapMessageContent(message));

        IpsRequestSigner.signIpsRequest(message, "https://ips-test.rosminzdrav.ru/57ad868a70751",
                "urn:hl7-org:v3:PRPA_IN201301", "6cf8d269-e067-41a6-85fa-e35c40c44bb6", privateKey, certificate);

        logger.info("IPS Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    private void testSignIpsResponse(SignAlgorithmType algorithm) {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(CryptoTest.TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            testSignIpsResponse(keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder));
        }
    }

    @SneakyThrows
    private void testSignIpsResponse(PrivateKey privateKey, X509Certificate certificate) {
        logger.info("Prepare IPS Response signature for algorithm {}", certificate.getSigAlgName());
        SOAPMessage message = getIpsTestResponse();
        logger.info("IPS Response message before signature: {}", getSoapMessageContent(message));
        IpsRequestSigner.signIpsResponse(message, privateKey, certificate);

        logger.info("IPS Response message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    private SOAPMessage getIpsTestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/ips/request.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_2_PROTOCOL);
    }

    private SOAPMessage getIpsTestResponse() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/ips/response.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_2_PROTOCOL);
    }

    private void checkSignedMessage(SOAPMessage message) throws SOAPException {
        assertNotNull(message);
        NodeList nodes = message.getSOAPHeader().getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "BinarySecurityToken");
        assertTrue(nodes.getLength() > 0);
    }
}
