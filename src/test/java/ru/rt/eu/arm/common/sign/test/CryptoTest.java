package ru.rt.eu.arm.common.sign.test;

import com.sun.istack.internal.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import ru.rt.eu.arm.common.sign.util.CryptoUtil;
import ru.rt.eu.arm.common.sign.util.SignAlgorithmType;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertNotNull;

@Slf4j
public class CryptoTest {
    private static final String TEST_CERTIFICATE_CN = "CN=Белов Александр, O=Общество с ограниченной ответственностью \"Ай-Новус\", E=abelov@i-novus.ru, L=Казань, C=RU, STREET=ул. Сеченова 19Б";

    @Test
    public void testGenerateKeyPairs() throws Exception {
        for (SignAlgorithmType signAlgorithm : SignAlgorithmType.values()) {
            if (signAlgorithm.getAvailableParameterSpecificationNames().isEmpty()) {
                KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm, null);
                checkKeyPair(keyPair);
            } else {
                for (String parameterSpecName : signAlgorithm.getAvailableParameterSpecificationNames()) {
                    KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm, parameterSpecName);
                    checkKeyPair(keyPair);
                }
            }
        }
    }

    @Test
    public void generateTemplates() throws Exception {
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

    private void generateTemplate(final SignAlgorithmType signAlgorithm, @Nullable final String parameterSpecName, final String basePath) throws IOException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm, parameterSpecName);
        checkKeyPair(keyPair);
        String keyPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".key";
        String crtPath = signAlgorithm.name() + (parameterSpecName == null ? "" : "_" + parameterSpecName) + ".crt";

        X509CertificateHolder certificateHolder = selfSignedCertificate(keyPair, signAlgorithm);
        if (certificateHolder == null)
            throw new IllegalArgumentException("Signature algorithm '" + signAlgorithm.name() + "' is not supported");

        writePKToFile(keyPair, Paths.get(basePath, keyPath));
        writeCertToFile(certificateHolder, Paths.get(basePath, crtPath));
        //todo read private key and certificate, sign data, check it
    }

    private void writeCertToFile(X509CertificateHolder certificateHolder, Path path) throws IOException {
        if (Files.exists(path)) {
            Files.delete(path);
        }
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            fos.write(certificateHolder.getEncoded());
            logger.info("File {} is written", path);
        }
    }

    private void writePKToFile(KeyPair keyPair, Path path) throws IOException {
        if (Files.exists(path)) {
            Files.delete(path);
        }
        try (OutputStream fos = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            fos.write(pkcs8EncodedKeySpec.getEncoded());
            logger.info("File {} is written", path);
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
}
