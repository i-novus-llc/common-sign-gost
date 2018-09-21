package ru.rt.eu.arm.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import ru.rt.eu.arm.common.sign.util.CryptoUtil;
import ru.rt.eu.arm.common.sign.util.SignAlgorithmType;

import java.security.KeyPair;

import static org.junit.Assert.assertNotNull;

@Slf4j
public class CryptoTest {
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

    private void checkKeyPair(KeyPair keyPair) {
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }
}
