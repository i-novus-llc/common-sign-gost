package ru.rt.eu.arm.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import ru.rt.eu.arm.common.sign.util.CryptoIO;
import ru.rt.eu.arm.common.sign.util.CryptoUtil;
import ru.rt.eu.arm.common.sign.util.SignAlgorithmType;

import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;

@Slf4j
public class CryptoTest {
    private static final String TEST_CERTIFICATE_CN = "CN=Белов Александр, O=Общество с ограниченной ответственностью \"Ай-Новус\", E=abelov@i-novus.ru, L=Казань, C=RU, STREET=ул. Сеченова 19Б";
    private static final String TEST_DATA_TO_SIGN = "Test data. Необходимо проверить подпись на разных языках";

    @Test
    public void testGenerateAndUse() throws Exception {
        String basePath = Files.createTempDirectory("keys").toString();
        for (SignAlgorithmType signAlgorithm : SignAlgorithmType.values()) {
            if (signAlgorithm.getAvailableParameterSpecificationNames().isEmpty()) {
                generateTemplate(signAlgorithm, null, basePath);
            } else {
                for (String parameterSpecName : signAlgorithm.getAvailableParameterSpecificationNames()) {
                    generateTemplate(signAlgorithm, parameterSpecName, basePath);
                }
            }
        }
    }

    private void generateTemplate(final SignAlgorithmType signAlgorithm, final String parameterSpecName, final String basePath) throws IOException,
            GeneralSecurityException, OperatorCreationException {
        KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm, parameterSpecName);
        checkKeyPair(keyPair);

        String keyPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".key";
        String crtPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".crt";
        X509CertificateHolder certificateHolder = selfSignedCertificate(keyPair, signAlgorithm);
        if (certificateHolder == null)
            throw new IllegalArgumentException("Signature algorithm '" + signAlgorithm.name() + "' is not supported");

        keyPath = CryptoIO.writePKToFile(keyPair, Paths.get(basePath, keyPath));
        crtPath = CryptoIO.writeCertToFile(certificateHolder, Paths.get(basePath, crtPath));

        certificateHolder = CryptoIO.readCertFromFile(crtPath);
        PKCS8EncodedKeySpec keySpec = CryptoIO.readPkFromFile(keyPath);

        JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();
        jcaConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate certificate = jcaConverter.getCertificate(certificateHolder);

        DefaultSignatureAlgorithmIdentifierFinder algorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        algorithmIdentifierFinder.find(certificate.getSigAlgName());

        String signature = CryptoUtil.getBase64Signature(TEST_DATA_TO_SIGN,
                new String(Base64.getEncoder().encode(keySpec.getEncoded())), SignAlgorithmType.findByAlgorithmName(certificate.getSigAlgName()));

        logger.info("Path to certificates and keys: {}", basePath);
    }

    private void checkKeyPair(KeyPair keyPair) {
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    private X509CertificateHolder selfSignedCertificate(KeyPair keyPair, SignAlgorithmType signAlgorithm)
            throws IOException, OperatorCreationException {
        return CryptoUtil.selfSignedCertificate(TEST_CERTIFICATE_CN, keyPair, signAlgorithm, null, null);
    }
}
