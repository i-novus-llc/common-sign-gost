package ru.i_novus.common.sign.service;

import lombok.extern.slf4j.Slf4j;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.StreamUtils;
import ru.i_novus.common.sign.service.api.model.IpsRequestToSign;
import ru.i_novus.common.sign.service.api.model.SignatureResult;
import ru.i_novus.common.sign.service.api.rest.IpsRest;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Base64;

import static org.junit.Assert.*;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootApplication
@TestPropertySource
public class IpsRequestTest {
    private static final String CERTIFICATE_SERIAL_NUMBER = "128445721360035597840071096363783644395";

    @Autowired
    private IpsRest ipsRest;

    @BeforeClass
    public static void init() {
        System.setProperty("javax.xml.soap.SAAJMetaFactory", "com.sun.xml.messaging.saaj.soap.SAAJMetaFactoryImpl");
    }

    @Test
    public void testSignRequest() throws IOException {

        IpsRequestToSign requestToSign = new IpsRequestToSign();
        requestToSign.setClientEntityId("76c8o99n-i9si-2q3k-cagt-j");
        requestToSign.setSoapAction("sendDocument");
        requestToSign.setSoapService("https://ips.rosminzdrav.ru/57406573a4083");
        requestToSign.setSerialNumber(new BigInteger(CERTIFICATE_SERIAL_NUMBER));

        InputStream requestStream = getTestDocumentContent("fullRequest.xml");
        byte[] requestContentBytes = StreamUtils.copyToByteArray(requestStream);

        requestToSign.setDocContent(Base64.getEncoder().encodeToString(requestContentBytes));

        SignatureResult result = ipsRest.signIpsRequest(requestToSign);
        assertNotNull(result);
        assertNotNull(result.getSignedData());
        assertNull(result.getError());
        assertNull(result.getMessage());
    }

    private InputStream getTestDocumentContent(String docName) {
        return Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/service/test/request/" + docName);
    }
}
