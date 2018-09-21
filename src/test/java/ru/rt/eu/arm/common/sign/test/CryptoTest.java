package ru.rt.eu.arm.common.sign.test;

import org.junit.Test;
import ru.rt.eu.arm.common.sign.util.CryptoUtil;
import ru.rt.eu.arm.common.sign.util.SignAlgorithmType;

import java.security.KeyPair;

import static org.junit.Assert.assertNotNull;

public class CryptoTest {

//    @BeforeClass
//    public static void initTestCase() throws XMLSignatureException, AlgorithmAlreadyRegisteredException, ClassNotFoundException {
//        Init.init();
//    }

    @Test
    public void generateKeypairs() throws Exception {
        for (SignAlgorithmType signAlgorithm : SignAlgorithmType.values()) {
            KeyPair keyPair = CryptoUtil.generateKeyPair(signAlgorithm);
            assertNotNull(keyPair.getPrivate());
            assertNotNull(keyPair.getPublic());
        }
    }
}
