package ru.i_novus.common.sign.test;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import ru.i_novus.common.sign.Init;
import ru.i_novus.common.sign.activation.ByteArrayDataSource;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.smev.Smev3AttachmentSigner;
import ru.i_novus.common.sign.util.CryptoFormatConverter;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.FileSignatureVerifier;

import javax.activation.DataHandler;
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

    @BeforeClass
    public static void init() {
        Init.init();
    }

    @Test
    public void testSignAttachmentGost2001() throws IOException, URISyntaxException {
        signAndSimpleCheckAttachment(getDataHandler(), SignAlgorithmType.ECGOST3410);
    }

    @Test
    public void testSignAttachmentGost2012_256() throws IOException, URISyntaxException {
        signAndSimpleCheckAttachment(getDataHandler(), SignAlgorithmType.ECGOST3410_2012_256);
    }

    @Test
    public void testSignAttachmentGost2012_512() throws IOException, URISyntaxException {
        signAndSimpleCheckAttachment(getDataHandler(), SignAlgorithmType.ECGOST3410_2012_512);
    }

    @SneakyThrows
    private void signAndSimpleCheckAttachment(DataHandler dataHandler, SignAlgorithmType algorithm) {
        for (String specName : algorithm.getAvailableParameterSpecificationNames()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(algorithm, specName);
            X509CertificateHolder certificateHolder = CryptoUtil.selfSignedCertificate(CryptoTest.TEST_CERTIFICATE_CN, keyPair, algorithm, null, null);
            signAndSimpleCheckAttachment(dataHandler, keyPair.getPrivate(), CryptoFormatConverter.getInstance().getCertificateFromHolder(certificateHolder));
        }
    }

    @SneakyThrows
    private void signAndSimpleCheckAttachment(DataHandler dataHandler, PrivateKey privateKey, X509Certificate x509Certificate) {

        assertNotNull(dataHandler);

        byte[] signedDataByteArray = Smev3AttachmentSigner.signSmev3Attachment(dataHandler, x509Certificate, privateKey);

        assertTrue(FileSignatureVerifier.verifyDigest(dataHandler, signedDataByteArray));

        assertTrue(FileSignatureVerifier.verifyPKCS7Signature(signedDataByteArray));
    }

    private DataHandler getDataHandler() throws IOException, URISyntaxException {

        Path path = Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/attachment/attachment.txt").toURI());

        final String fileName = "attachment.txt";
        final String mimeType = "text/plain";

        byte[] fileBytes = Files.readAllBytes(path);

        return new DataHandler(new ByteArrayDataSource(fileName, mimeType, fileBytes));
    }
}
