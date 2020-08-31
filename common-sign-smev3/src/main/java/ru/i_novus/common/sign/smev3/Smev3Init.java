package ru.i_novus.common.sign.smev3;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;

@Slf4j
@NoArgsConstructor (access = AccessLevel.PRIVATE)
public class Smev3Init {
    private static boolean initialized = false;

    public static synchronized void init() {

        if (initialized) {
            return;
        }
        ru.i_novus.common.sign.Init.init();

        try {
            Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class);
        } catch (AlgorithmAlreadyRegisteredException e) {
            logger.warn("Algorithm '" + SmevTransformSpi.ALGORITHM_URN + " is already registered");
        } catch (InvalidTransformException e) {
            logger.error("Cannot register transformation " + SmevTransformSpi.ALGORITHM_URN, e);
        }
        initialized = true;
    }
}
