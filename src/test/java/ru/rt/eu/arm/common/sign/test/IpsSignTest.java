package ru.rt.eu.arm.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.w3c.dom.NodeList;
import ru.rt.eu.arm.common.sign.ips.IpsRequestSigner;

import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.InputStream;

import static org.junit.Assert.*;
import static ru.rt.eu.arm.common.sign.test.SoapUtil.getSoapMessageContent;

@Slf4j
public class IpsSignTest {
    @Test
    public void testSignIpsRequestGost2001() throws Exception {
        SOAPMessage message = getIpsTestRequest();
        logger.info("IPS Request message before signature: {}", getSoapMessageContent(message));

        IpsRequestSigner.signIpsRequest(message, "https://ips-test.rosminzdrav.ru/57ad868a70751",
                    "urn:hl7-org:v3:PRPA_IN201301", "6cf8d269-e067-41a6-85fa-e35c40c44bb6",
                    TestKeyData.GOST_2001.getCertificate(), TestKeyData.GOST_2001.getKey());

        logger.info("IPS Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    @Test
    public void testSignIpsResponseGost2001() throws Exception {
        SOAPMessage message = getIpsTestResponse();
        logger.info("IPS Response message before signature: {}", getSoapMessageContent(message));
        IpsRequestSigner.signIpsResponse(message, TestKeyData.GOST_2001.getCertificate(), TestKeyData.GOST_2001.getKey());

        logger.info("IPS Response message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    @Test
    public void testSignIpsRequestGost2012_256() throws Exception {
       /* SOAPMessage message = getIpsTestRequest();
        logger.info("IPS Request message before signature: {}", getSoapMessageContent(message));

        IpsRequestSigner.signIpsRequest(message, "https://ips-test.rosminzdrav.ru/57ad868a70751",
                "urn:hl7-org:v3:PRPA_IN201301", "6cf8d269-e067-41a6-85fa-e35c40c44bb6",
                TestKeyData.GOST_2012_256.getCertificate(), TestKeyData.GOST_2012_256.getKey());

        logger.info("IPS Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);*/
    }

    @Test
    public void testSignIpsResponseGost2012_256() throws Exception {
        /*SOAPMessage message = getIpsTestResponse();
        logger.info("IPS Response message before signature: {}", getSoapMessageContent(message));
        IpsRequestSigner.signIpsResponse(message, TestKeyData.GOST_2012_256.getCertificate(), TestKeyData.GOST_2012_256.getKey());

        logger.info("IPS Response message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);*/
    }

    @Test
    public void testSignIpsRequestGost2012_512() throws Exception {
        /*SOAPMessage message = getIpsTestRequest();
        logger.info("IPS Request message before signature: {}", getSoapMessageContent(message));

        IpsRequestSigner.signIpsRequest(message, "https://ips-test.rosminzdrav.ru/57ad868a70751",
                "urn:hl7-org:v3:PRPA_IN201301", "6cf8d269-e067-41a6-85fa-e35c40c44bb6",
                TestKeyData.GOST_2012_512.getCertificate(), TestKeyData.GOST_2012_512.getKey());

        logger.info("IPS Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);*/
    }

    @Test
    public void testSignIpsResponseGost2012_512() throws Exception {
/*        SOAPMessage message = getIpsTestResponse();
        logger.info("IPS Response message before signature: {}", getSoapMessageContent(message));
        IpsRequestSigner.signIpsResponse(message, TestKeyData.GOST_2012_512.getCertificate(), TestKeyData.GOST_2012_512.getKey());

        logger.info("IPS Response message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);*/
    }

    private SOAPMessage getIpsTestRequest() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/ips/request.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_2_PROTOCOL);
    }

    private SOAPMessage getIpsTestResponse() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/ips/response.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_2_PROTOCOL);
    }

    private void checkSignedMessage(SOAPMessage message) throws SOAPException {
        assertNotNull(message);
        NodeList nodes = message.getSOAPHeader().getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "BinarySecurityToken");
        assertTrue(nodes.getLength() > 0);
    }
}
