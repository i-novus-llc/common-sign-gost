package ru.i_novus.common.sign.test;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.util.CryptoIO;
import ru.i_novus.common.sign.util.CryptoUtil;
import ru.i_novus.common.sign.util.Verifier;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

@Slf4j
public class ConverterTest {
    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @SneakyThrows
    public void testReadPKCS12() {
        testKeysInPKCS12(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/cryptopro/gost2012_256.pfx").toURI()), "12345678");
        testKeysInPKCS12(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/cryptopro/gost2012_512.pfx").toURI()), "12345678");
        testKeysInPKCS12(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/cryptopro/gost2012_512_emdr.pfx").toURI()), "12345678");
    }

    @SneakyThrows
    private void testKeysInPKCS12(Path path, String password) {
        CryptoIO cryptoIO = CryptoIO.getInstance();

        try (InputStream fileInputStream = Files.newInputStream(path)) {

            KeyStore keyStore = cryptoIO.getPkcs12KeyStore(fileInputStream, password);

            PrivateKey privateKey = cryptoIO.readPrivateKeyFromPKCS12(keyStore, password);
            X509Certificate certificate = cryptoIO.readCertificateFromPKCS12(keyStore);

            byte[] signResult = CryptoUtil.getCMSSignature(getTestData(), privateKey, certificate);

            Path file = Files.createTempFile("signature", ".sig");

            try (InputStream inputStream = new FileInputStream(file.toFile())) {

                Files.write(file, signResult);
                logger.info("file name: {}", file.toString());

                Verifier verifier = Verifier.getInstance();
                boolean valid = verifier.verifyCmsSignature(getTestData(), cryptoIO.inputStreamToByteArray(inputStream));
                assertTrue(valid);
            } finally {
                Files.delete(file);
            }
        }
    }

    @Test
    @SneakyThrows
    public void testCreatePKCS12() {
        CryptoIO cryptoIO = CryptoIO.getInstance();

        X509Certificate certificate = cryptoIO.readCertFromPEM(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/raw/gost2001_crt.pem").toURI()));
        PrivateKey privateKey = cryptoIO.readPkFromPEM(Paths.get(Thread.currentThread().getContextClassLoader().getResource("ru/i_novus/common/sign/test/raw/gost2001_pk.pem").toURI()), SignAlgorithmType.findByCertificate(certificate));

        Path temporaryFile = Files.createTempFile("gost2001_", ".pfx");
        try {
            String password = "12345678";
            cryptoIO.createPkcs12File(temporaryFile, password, privateKey, new X509Certificate[]{certificate});
            logger.info("Generated PKCS file: {}", temporaryFile.toString());
            testKeysInPKCS12(temporaryFile, password);
        } finally {
            Files.delete(temporaryFile);
        }
    }

    private byte[] getTestData() {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/i_novus/common/sign/test/smev/sendResponseRequest.xml");
        return CryptoIO.getInstance().inputStreamToByteArray(inputStream);
    }
}
