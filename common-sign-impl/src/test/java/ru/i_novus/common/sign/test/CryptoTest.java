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
package ru.i_novus.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.BeforeClass;
import org.junit.Test;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.util.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.*;
import static ru.i_novus.common.sign.util.Base64Util.getBase64EncodedString;

@Slf4j
public class CryptoTest {
    static final String TEST_CERTIFICATE_CN = "CN=I-Novus Employee, O=I-Novus LLC, E=office@i-novus.ru, L=Kazan, C=RU, STREET=Sechenova 19B";
    private static final byte[] TEST_DATA_TO_SIGN = getTestData();

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testAllAlgorithms() throws IOException, GeneralSecurityException {
        String basePath = Files.createTempDirectory("keys").toString();
        try {
            for (SignAlgorithmType signAlgorithm : SignAlgorithmType.values()) {
                if (signAlgorithm.getAvailableParameterSpecificationNames().isEmpty()) {
                    testOneAlgorithm(signAlgorithm, null, basePath);
                } else {
                    for (String parameterSpecName : signAlgorithm.getAvailableParameterSpecificationNames()) {
                        testOneAlgorithm(signAlgorithm, parameterSpecName, basePath);
                    }
                }
            }
        } finally {
            Files.deleteIfExists(Paths.get(basePath));
        }
    }

    private void testOneAlgorithm(final SignAlgorithmType signAlgorithm, final String parameterSpecName, final String basePath) throws IOException, GeneralSecurityException {
        KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm, parameterSpecName);
        checkKeyPair(keyPair);

        String keyPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".key";
        String crtPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".crt";
        X509CertificateHolder certificateHolder = selfSignedCertificate(keyPair, signAlgorithm);
        if (certificateHolder == null)
            throw new IllegalArgumentException("Signature algorithm '" + signAlgorithm.name() + "' is not supported");

        CryptoIO cryptoIO = CryptoIO.getInstance();
        keyPath = cryptoIO.writePKToPKCS8File(keyPair, Paths.get(basePath, keyPath));
        logger.info("Path to key: {}, algorithm {}", keyPath, signAlgorithm);
        crtPath = cryptoIO.writeCertToDERFile(certificateHolder, Paths.get(basePath, crtPath));
        logger.info("Path to certificate: {}, algorithm {}", crtPath, signAlgorithm);

        try {
            certificateHolder = cryptoIO.readCertFromDER(crtPath);
            PKCS8EncodedKeySpec keySpec = cryptoIO.readPkFromPKCS8(keyPath);
            X509Certificate certificate = CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder);

            SignAlgorithmType algorithmType = SignAlgorithmType.findByAlgorithmName(certificate.getSigAlgName());
            if (TEST_DATA_TO_SIGN != null) {
                CryptoUtil.getBase64Signature(new String(TEST_DATA_TO_SIGN), getBase64EncodedString(keySpec.getEncoded()),
                        algorithmType);
            }

            logger.info("Path to certificates and keys: {}", basePath);
        } finally {
            Files.deleteIfExists(Paths.get(keyPath));
            Files.deleteIfExists(Paths.get(crtPath));
        }
    }

    @Test
    public void testGeneratePKCS12_GOST2012_256() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        SignAlgorithmType signAlgorithmType = SignAlgorithmType.ECGOST3410_2012_256;

        KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithmType, signAlgorithmType.getAvailableParameterSpecificationNames().get(0));
        checkKeyPair(keyPair);

        CryptoIO cryptoIO = CryptoIO.getInstance();

        X509CertificateHolder certificateHolder = selfSignedCertificate(keyPair, signAlgorithmType);
        if (certificateHolder == null)
            throw new IllegalArgumentException("Signature algorithm '" + signAlgorithmType.name() + "' is not supported");

        X509Certificate certificate = CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder);

        String basePath = Files.createTempDirectory("keys").toString();
        Path fullPath = Paths.get(basePath, "PKCS12_GOST2012_256.pfx");
        try {
            cryptoIO.createPkcs12File(fullPath, "12345678", keyPair.getPrivate(), new X509Certificate[]{certificate});
            logger.info("Full path: {}", fullPath);
        } finally {
            Files.deleteIfExists(fullPath);
            Files.deleteIfExists(Paths.get(basePath));
        }
    }

    private void checkKeyPair(KeyPair keyPair) {
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    static X509CertificateHolder selfSignedCertificate(KeyPair keyPair, SignAlgorithmType signAlgorithm) {
        return CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, signAlgorithm, null, null);
    }

    private static byte[] getTestData() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/xml/sample.xml");
        return CryptoIO.getInstance().inputStreamToByteArray(inputStream);
    }

    @Test
    public void testSignVerify() throws URISyntaxException, IOException, CertificateException, CMSException, OperatorCreationException {
        Verifier verifier = Verifier.getInstance();
        byte[] fileToCheck = Files.readAllBytes(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/check/valid.pdf").toURI()));
        byte[] signature = Files.readAllBytes(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/check/valid.pdf.sig").toURI()));
        byte[] mimeDecoded = Base64.getMimeDecoder().decode(signature);
        boolean result = verifier.verifyCmsSignature(fileToCheck, mimeDecoded);
        assertTrue(result);
    }

    @Test(expected = CMSSignerDigestMismatchException.class)
    public void testSignVerifyInvalid() throws URISyntaxException, IOException, CertificateException, CMSException, OperatorCreationException {
        Verifier verifier = Verifier.getInstance();
        byte[] fileToCheck = Files.readAllBytes(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/check/not_valid.pdf").toURI()));
        byte[] signature = Files.readAllBytes(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/check/not_valid.pdf.sig").toURI()));
        byte[] mimeDecoded = Base64.getMimeDecoder().decode(signature);
        boolean result = verifier.verifyCmsSignature(fileToCheck, mimeDecoded);
        assertFalse(result);
    }
}
