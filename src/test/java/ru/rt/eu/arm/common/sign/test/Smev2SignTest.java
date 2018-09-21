package ru.rt.eu.arm.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.w3c.dom.NodeList;
import ru.rt.eu.arm.common.sign.ips.IpsRequestSigner;

import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.InputStream;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static ru.rt.eu.arm.common.sign.test.SoapUtil.getSoapMessageContent;

@Slf4j
public class Smev2SignTest {
    @Test
    public void testSignSmev2Request2001() throws Exception {
        SOAPMessage message = getSmev2Request();
        logger.info("SMEV2 Request message before signature: {}", getSoapMessageContent(message));
        IpsRequestSigner.signIpsResponse(message, TestKeyData.GOST_2001.getCertificate(), TestKeyData.GOST_2001.getKey());

        logger.info("MEV2 Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    private SOAPMessage getSmev2Request() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/rt/eu/arm/common/sign/test/smev/smev2Request.xml");
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }

    private void checkSignedMessage(SOAPMessage message) throws SOAPException {
        assertNotNull(message);
        NodeList nodes = message.getSOAPHeader().getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                "BinarySecurityToken");
        assertTrue(nodes.getLength() > 0);
    }
}
