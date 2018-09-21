package ru.rt.eu.arm.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;
import ru.rt.eu.arm.common.sign.smev.Smev3RequestSigner;

import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertNotNull;
import static ru.rt.eu.arm.common.sign.test.SoapUtil.getSoapMessageContent;

@Slf4j
public class Smev3SignTest {
    @Test
    public void testSignAckRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getAckRequest(), TestKeyData.GOST_2001, "AckRequestRequest");
    }

    @Test
    public void testSignGetRequestRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getGetRequestRequest(), TestKeyData.GOST_2001, "GetRequestRequest");
    }

    @Test
    public void testSignGetResponseRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getGetResponseRequest(), TestKeyData.GOST_2001, "GetResponseRequest");
    }

    @Test
    public void testSignSendRequestRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getSendRequestRequest(), TestKeyData.GOST_2001, "SendRequestRequest");
    }
    @Test
    public void testSignSendResponseRequestGost2001() throws Exception {
        signAndSimpleCheckMessage(getSendResponseRequest(), TestKeyData.GOST_2001, "SendResponseRequest");
    }

    private void signAndSimpleCheckMessage(SOAPMessage message, TestKeyData keyData, String action) throws CertificateException, InvalidKeySpecException,
            NoSuchAlgorithmException, SOAPException, ClassNotFoundException, NoSuchProviderException, XMLSecurityException {

        logger.info("SMEV3 {} message before {} signature: {}", action, keyData.name(), getSoapMessageContent(message));
        Smev3RequestSigner.signSmev3Request(message, keyData.getCertificate(), keyData.getKey());
        logger.info("SMEV3 {} message after {} signature: {}", action, keyData.name(), getSoapMessageContent(message));

        checkSignedMessage(message);
    }

    private void checkSignedMessage(SOAPMessage message) {
        assertNotNull(message);
    }

    private SOAPMessage getAckRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/smev/ackRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getGetRequestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/smev/getRequestRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getGetResponseRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/smev/getResponseRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getSendRequestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/smev/sendRequestRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private SOAPMessage getSendResponseRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/smev/sendResponseRequest.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }
}
