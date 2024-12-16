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

package ru.i_novus.common.sign.test.ips;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.ips.IpsRequestSigner;
import ru.i_novus.common.sign.soap.SoapUtil;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;

import jakarta.xml.soap.SOAPConstants;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import static org.junit.Assert.*;
import static ru.i_novus.common.sign.soap.SoapUtil.getSoapMessageContent;

@Slf4j
public class IpsSignTest {
    private static final String TEST_CERTIFICATE_CN = "CN=I-Novus Employee, O=I-Novus LLC, E=office@i-novus.ru, L=Kazan, C=RU, STREET=Sechenova 19B";

    @BeforeClass
    public static void init() {
        Init.init();
    }

    @Test
    public void testSignIpsRequestGost2001() throws Exception {
        testSignIpsRequest(SignAlgorithmType.ECGOST3410);
    }

    @Test
    public void testSignIpsResponseGost2001() throws Exception {
        testSignIpsResponse(SignAlgorithmType.ECGOST3410);
    }

    @Test
    public void testSignIpsRequestGost2012_256() throws Exception {
        testSignIpsRequest(SignAlgorithmType.ECGOST3410_2012_256);
    }

    @Test
    public void testSignIpsResponseGost2012_256() throws Exception {
        testSignIpsResponse(SignAlgorithmType.ECGOST3410_2012_256);
    }

    @Test
    public void testSignIpsRequestGost2012_512() throws Exception {
        testSignIpsRequest(SignAlgorithmType.ECGOST3410_2012_512);
    }

    @Test
    public void testSignIpsResponseGost2012_512() throws Exception {
        testSignIpsResponse(SignAlgorithmType.ECGOST3410_2012_512);
    }

    private void testSignIpsRequest(SignAlgorithmType algorithm) throws Exception {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            X509Certificate certificate = CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder);
            testSignIpsRequest(keyPair.getPrivate(), certificate);
            testSignIpsRequest_withTimestampExpires(keyPair.getPrivate(), certificate);
        }
    }

    private void testSignIpsRequest(PrivateKey privateKey, X509Certificate certificate) throws Exception {
        logger.info("Prepare IPS Request signature for algorithm {}", certificate.getSigAlgName());

        SOAPMessage message = getIpsTestRequest();
        logger.info("IPS Request message before signature: {}", getSoapMessageContent(message));

        IpsRequestSigner.signIpsRequest(message, "https://ips-test.rosminzdrav.ru/57ad868a70751",
                "urn:hl7-org:v3:PRPA_IN201301", "6cf8d269-e067-41a6-85fa-e35c40c44bb6", privateKey, certificate);

        logger.info("IPS Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    private void testSignIpsRequest_withTimestampExpires(PrivateKey privateKey, X509Certificate certificate) throws Exception {
        logger.info("Prepare IPS Request signature for algorithm {}", certificate.getSigAlgName());

        SOAPMessage message = getIpsTestRequest();
        logger.info("IPS Request message before signature: {}", getSoapMessageContent(message));

        IpsRequestSigner.signIpsRequest(message, "https://ips-test.rosminzdrav.ru/57ad868a70751",
                "urn:hl7-org:v3:PRPA_IN201301", "6cf8d269-e067-41a6-85fa-e35c40c44bb6", privateKey, certificate, ZonedDateTime.now());

        logger.info("IPS Request message after signature: {}", getSoapMessageContent(message));
        checkSignedMessage(message);
    }

    private void testSignIpsResponse(SignAlgorithmType algorithm) throws Exception {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            testSignIpsResponse(keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder));
        }
    }

    private void testSignIpsResponse(PrivateKey privateKey, X509Certificate certificate) throws Exception {
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
