package ru.i_novus.common.sign;

import lombok.SneakyThrows;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ru.i_novus.common.sign.api.GostIds;
import ru.i_novus.common.sign.smev.SmevTransformSpi;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public final class Init {

    private static boolean initialized = false;

    private Init() {
    }

    @SneakyThrows
    public synchronized static void init() {
        if (initialized) {
            return;
        }

        apacheXmlSecurityInitialize();

        Security.removeProvider("ApacheXMLDSig");
        Security.addProvider(new XMLDSigRI());
        Security.addProvider(new BouncyCastleProvider());

        // GOST-3411
        JCEMapper.Algorithm digest = new JCEMapper.Algorithm("", "GOST3411", "MessageDigest");
        JCEMapper.register(GostIds.GOST3411_URI, digest);
        JCEMapper.register(GostIds.GOST3411_URN, digest);
        // GOST-3410-2001
        JCEMapper.Algorithm signature = new JCEMapper.Algorithm("", "GOST3411withECGOST3410", "Signature");
        JCEMapper.register(GostIds.GOST3410_2001_URI, signature);
        JCEMapper.register(GostIds.GOST3410_2001_URN, signature);
        // GOST-3411-2012-256
        digest = new JCEMapper.Algorithm("", "GOST3411-2012-256", "MessageDigest");
        JCEMapper.register(GostIds.GOST3411_2012_256_URI, digest);
        JCEMapper.register(GostIds.GOST3411_2012_256_URN, digest);
        // GOST-3410-2012-256
        signature = new JCEMapper.Algorithm("", "GOST3411-2012-256withECGOST3410-2012-256", "Signature");
        JCEMapper.register(GostIds.GOST3410_2012_256_URI, signature);
        JCEMapper.register(GostIds.GOST3410_2012_256_URN, signature);
        // GOST-3411-2012-512
        digest = new JCEMapper.Algorithm("", "GOST3411-2012-512", "MessageDigest");
        JCEMapper.register(GostIds.GOST3411_2012_512_URI, digest);
        JCEMapper.register(GostIds.GOST3411_2012_512_URN, digest);
        // GOST-3410-2012-512
        signature = new JCEMapper.Algorithm("", "GOST3411-2012-512withECGOST3410-2012-512", "Signature");
        JCEMapper.register(GostIds.GOST3410_2012_512_URI, signature);
        JCEMapper.register(GostIds.GOST3410_2012_512_URN, signature);

        // GOST3410-2001
        SignatureAlgorithm.register(GostIds.GOST3410_2001_URI, SignatureGost.Gost3410_2001_Uri.class);
        SignatureAlgorithm.register(GostIds.GOST3410_2001_URN, SignatureGost.Gost3410_2001_Urn.class);
        // GOST-3410-2012-256
        SignatureAlgorithm.register(GostIds.GOST3410_2012_256_URI, SignatureGost.Gost3410_2012_256_Uri.class);
        SignatureAlgorithm.register(GostIds.GOST3410_2012_256_URN, SignatureGost.Gost3410_2012_256_Urn.class);
        // GOST-3410-2012-512
        SignatureAlgorithm.register(GostIds.GOST3410_2012_512_URI, SignatureGost.Gost3410_2012_512_Uri.class);
        SignatureAlgorithm.register(GostIds.GOST3410_2012_512_URN, SignatureGost.Gost3410_2012_512_Urn.class);

        Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class);


        setFileEncoding(StandardCharsets.UTF_8);

        initialized = true;
    }

    /**
     * Инициализация библиотеки XML Security
     */
    private static void apacheXmlSecurityInitialize() {

        if (!org.apache.xml.security.Init.isInitialized()) {

            System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
            org.apache.xml.security.Init.init();

            try {

                Field f = XMLUtils.class.getDeclaredField("ignoreLineBreaks");

                f.setAccessible(true);

            } catch (NoSuchFieldException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static void setFileEncoding(Charset fileEncoding){

        System.setProperty("file.encoding", fileEncoding.name());

        try {
            Field charset = Charset.class.getDeclaredField("defaultCharset");
            charset.setAccessible(true);
            charset.set(null, null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Не удалось настроить кодировку "+ fileEncoding, e);
        }
    }
}
