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

import jakarta.activation.DataHandler;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import ru.i_novus.common.sign.activation.ByteArrayDataSource;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.datatypes.FileSignatureInfo;
import ru.i_novus.common.sign.smev3.Smev3AttachmentSigner;
import ru.i_novus.common.sign.smev3.Smev3Init;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.FileSignatureVerifier;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Slf4j
public class Smev3AttachmentSignTest {
    private static final String TEST_CERTIFICATE_CN = "CN=I-Novus Employee, O=I-Novus LLC, E=office@i-novus.ru, L=Kazan, C=RU, STREET=Sechenova 19B";

    @BeforeClass
    public static void init() {
        Smev3Init.init();
    }

    @Test
    public void testSignAttachmentGost2001() throws Exception {
        signAndSimpleCheckAttachment(getDataHandler(), SignAlgorithmType.ECGOST3410);
    }

    @Test
    public void testSignAttachmentGost2012_256() throws Exception {
        signAndSimpleCheckAttachment(getDataHandler(), SignAlgorithmType.ECGOST3410_2012_256);
    }

    @Test
    public void testSignAttachmentGost2012_512() throws Exception {
        signAndSimpleCheckAttachment(getDataHandler(), SignAlgorithmType.ECGOST3410_2012_512);
    }

    private void signAndSimpleCheckAttachment(DataHandler dataHandler, SignAlgorithmType algorithm) throws Exception {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            signAndSimpleCheckAttachment(dataHandler, keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder));
        }
    }

    private void signAndSimpleCheckAttachment(DataHandler dataHandler, PrivateKey privateKey, X509Certificate x509Certificate) throws Exception {

        assertNotNull(dataHandler);

        FileSignatureInfo fileSignatureInfo = Smev3AttachmentSigner.signSmev3Attachment(dataHandler, x509Certificate, privateKey);

        byte[] signedDataByteArray = fileSignatureInfo.getSignaturePKCS7();

        assertTrue(FileSignatureVerifier.verifyDigest(dataHandler, signedDataByteArray));

        assertTrue(FileSignatureVerifier.verifyPKCS7Signature(signedDataByteArray));
    }

    private DataHandler getDataHandler() throws IOException, URISyntaxException {

        Path path = Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/smev3/attachment.txt").toURI());

        final String fileName = "attachment.txt";
        final String mimeType = "text/plain";

        byte[] fileBytes = Files.readAllBytes(path);

        return new DataHandler(new ByteArrayDataSource(fileName, mimeType, fileBytes));
    }
}
