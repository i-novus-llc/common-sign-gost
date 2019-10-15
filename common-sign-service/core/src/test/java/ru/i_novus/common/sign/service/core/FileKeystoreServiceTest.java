package ru.i_novus.common.sign.service.core;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import ru.i_novus.common.sign.service.core.api.KeystoreService;
import ru.i_novus.common.sign.service.core.config.CryptoConfig;
import ru.i_novus.common.sign.service.core.config.ServiceConfig;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Slf4j
@SpringBootApplication
@SpringBootTest(classes = { ServiceConfig.class, CryptoConfig.class })
@RunWith(SpringRunner.class)
@TestPropertySource
public class FileKeystoreServiceTest {
    private static final BigInteger VALID_CERT_SERIAL_NUMBER_1 = new BigInteger("10694833484591657457279214011643035576");
    private static final BigInteger VALID_CERT_SERIAL_NUMBER_2 = new BigInteger("128445721360035597840071096363783644395");


    @Autowired
    private KeystoreService keystoreService;

    @Test
    public void testGetCertificate() {
        Optional<X509Certificate> certificateOptional = keystoreService.getCertificate(VALID_CERT_SERIAL_NUMBER_1);
        assertTrue(certificateOptional.isPresent());
        X509Certificate certificate = certificateOptional.orElseThrow(() -> new IllegalStateException("Valid certificate is not presented"));
        assertEquals(VALID_CERT_SERIAL_NUMBER_1, certificate.getSerialNumber());

        certificateOptional = keystoreService.getCertificate(VALID_CERT_SERIAL_NUMBER_2);
        assertEquals(VALID_CERT_SERIAL_NUMBER_2, certificateOptional.get().getSerialNumber());
    }

    @Test
    public void testGetKey() {
        Optional<PrivateKey> privateKeyOptional = keystoreService.getPrivateKey(VALID_CERT_SERIAL_NUMBER_1);
        assertTrue(privateKeyOptional.isPresent());

        assertTrue(keystoreService.getPrivateKey(VALID_CERT_SERIAL_NUMBER_2).isPresent());
    }
}
