package ru.i_novus.common.sign.smev3;

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.Transform;

@Slf4j
public class Smev3Init {
    private static boolean initialized = false;

    private Smev3Init() {
    }

    public synchronized static void init() {

        if (initialized) {
            return;
        }
        ru.i_novus.common.sign.Init.init();

        try {
            Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class);
        } catch (AlgorithmAlreadyRegisteredException e) {
            logger.warn("Agorithm '" + SmevTransformSpi.ALGORITHM_URN + " already registered");
        }
        initialized = true;
    }
}
