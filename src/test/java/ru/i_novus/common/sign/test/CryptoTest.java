package ru.i_novus.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.BeforeClass;
import org.junit.Test;
import ru.i_novus.common.sign.util.CryptoIO;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.SignAlgorithmType;
import ru.i_novus.common.sign.util.Verifier;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static ru.i_novus.common.sign.util.CryptoIO.inputStreamToByteArray;

@Slf4j
public class CryptoTest {
    private static final String TEST_CERTIFICATE_CN = "CN=Белов Александр, O=Общество с ограниченной ответственностью \"Ай-Новус\", E=abelov@i-novus.ru, L=Казань, C=RU, STREET=ул. Сеченова 19Б";
    private static final byte[] TEST_DATA_TO_SIGN = getTestData();

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testAllAlgorithms() throws Exception {
        String basePath = Files.createTempDirectory("keys").toString();
        for (SignAlgorithmType signAlgorithm : SignAlgorithmType.values()) {
            if (signAlgorithm.getAvailableParameterSpecificationNames().isEmpty()) {
                testOneAlgorithm(signAlgorithm, null, basePath);
            } else {
                for (String parameterSpecName : signAlgorithm.getAvailableParameterSpecificationNames()) {
                    testOneAlgorithm(signAlgorithm, parameterSpecName, basePath);
                }
            }
        }
    }

    private void testOneAlgorithm(final SignAlgorithmType signAlgorithm, final String parameterSpecName, final String basePath) throws IOException,
            GeneralSecurityException, OperatorCreationException {
        KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm, parameterSpecName);
        checkKeyPair(keyPair);

        String keyPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".key";
        String crtPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".crt";
        X509CertificateHolder certificateHolder = selfSignedCertificate(keyPair, signAlgorithm);
        if (certificateHolder == null)
            throw new IllegalArgumentException("Signature algorithm '" + signAlgorithm.name() + "' is not supported");

        keyPath = CryptoIO.writePKToFile(keyPair, Paths.get(basePath, keyPath));
        logger.info("Path to key: {}", keyPath);
        crtPath = CryptoIO.writeCertToFile(certificateHolder, Paths.get(basePath, crtPath));
        logger.info("Path to certificate: {}", crtPath);

        try {
            certificateHolder = CryptoIO.readCertFromDer(crtPath);
            PKCS8EncodedKeySpec keySpec = CryptoIO.readPkFromDer(keyPath);

            JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();
            jcaConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate certificate = jcaConverter.getCertificate(certificateHolder);

            SignAlgorithmType algorithmType = SignAlgorithmType.findByAlgorithmName(certificate.getSigAlgName());
            if (TEST_DATA_TO_SIGN != null) {
                String signature = CryptoUtil.getBase64Signature(new String(TEST_DATA_TO_SIGN), new String(Base64.getEncoder().encode(keySpec.getEncoded())),
                        algorithmType);
            }

            logger.info("Path to certificates and keys: {}", basePath);
        } finally {
            Files.delete(Paths.get(keyPath));
            Files.delete(Paths.get(crtPath));
        }
    }

    private void checkKeyPair(KeyPair keyPair) {
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    private X509CertificateHolder selfSignedCertificate(KeyPair keyPair, SignAlgorithmType signAlgorithm)
            throws IOException, OperatorCreationException {
        return CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, signAlgorithm, null, null);
    }

    @Test
    public void testReadFromPkcs() throws Exception {
        testByKeysInPKCS12("ru/i_novus/common/sign/test/cryptopro/gost2012_256.pfx", "12345678");
        testByKeysInPKCS12("ru/i_novus/common/sign/test/cryptopro/gost2012_512.pfx", "12345678");
        testByKeysInPKCS12("ru/i_novus/common/sign/test/cryptopro/gost2012_512_emdr.pfx", "12345678");
    }

    private void testByKeysInPKCS12(String path, String password) throws IOException, CMSException, GeneralSecurityException, OperatorCreationException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(path);
        assertNotNull(url);
        PrivateKey privateKey = CryptoIO.readPrivateKeyFromPKCS12(url.openStream(), password);
        X509Certificate certificate = CryptoIO.readCertificateFromPKCS12(url.openStream(), password);

        byte[] signResult = CryptoUtil.getCMSSignature(getTestData(), privateKey, certificate);
        Path file = Files.createTempFile("signature", ".sig");
        try {
            Files.write(file, signResult);
            logger.info("file name: {}", file.toString());

            Verifier verifier = Verifier.getInstance();
            boolean valid = verifier.verifyCmsSignature(getTestData(), inputStreamToByteArray(new FileInputStream(file.toFile())));
            assertTrue(valid);
        } finally {
            Files.delete(file);
        }
    }

    private static byte[] getTestData() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/getRequestRequest.xml");
        try {
            return inputStreamToByteArray(inputStream);
        } catch (IOException e) {
            logger.error("Cannot get test data", e);
            return null;
        }
    }
}
