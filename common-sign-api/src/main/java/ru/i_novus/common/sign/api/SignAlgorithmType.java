package ru.i_novus.common.sign.api;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.*;

public enum SignAlgorithmType {
    RSA,
    ECGOST3410,
    ECGOST3410_2012_256,
    ECGOST3410_2012_512;

    private static final Map<String, String> bcNames;
    private static final Map<String, String> digestUris;
    private static final Map<String, String> digestUrns;
    private static final Map<String, String> signUris;
    private static final Map<String, String> signUrns;
    private static final Map<String, List<String>> parameterSpecNames;
    private static final Map<String, String> signatureAlgorithmNames;

    private static final String ECGOST3410_2012 = "ECGOST3410-2012";

    static {
        bcNames = new HashMap<>();
        bcNames.put(RSA.name(), RSA.name());
        bcNames.put(ECGOST3410.name(), ECGOST3410.name());
        bcNames.put(ECGOST3410_2012_256.name(), ECGOST3410_2012);
        bcNames.put(ECGOST3410_2012_512.name(), ECGOST3410_2012);

        //Без RSA!
        digestUris = new HashMap<>();
        digestUris.put(ECGOST3410.name(), GostIds.GOST3411_URI);
        digestUris.put(ECGOST3410_2012_256.name(), GostIds.GOST3411_2012_256_URI);
        digestUris.put(ECGOST3410_2012_512.name(), GostIds.GOST3411_2012_512_URI);

        digestUrns = new HashMap<>();
        digestUrns.put(ECGOST3410.name(), GostIds.GOST3411_URN);
        digestUrns.put(ECGOST3410_2012_256.name(), GostIds.GOST3411_2012_256_URN);
        digestUrns.put(ECGOST3410_2012_512.name(), GostIds.GOST3411_2012_512_URN);

        signUris = new HashMap<>();
        signUris.put(ECGOST3410.name(), GostIds.GOST3410_2001_URI);
        signUris.put(ECGOST3410_2012_256.name(), GostIds.GOST3410_2012_256_URI);
        signUris.put(ECGOST3410_2012_512.name(), GostIds.GOST3410_2012_512_URI);

        signUrns = new HashMap<>();
        signUrns.put(ECGOST3410.name(), GostIds.GOST3410_2001_URN);
        signUrns.put(ECGOST3410_2012_256.name(), GostIds.GOST3410_2012_256_URN);
        signUrns.put(ECGOST3410_2012_512.name(), GostIds.GOST3410_2012_512_URN);

        parameterSpecNames = new HashMap<>();
        parameterSpecNames.put(RSA.name(), Collections.emptyList());
        parameterSpecNames.put(ECGOST3410.name(), Arrays.asList("GostR3410-2001-CryptoPro-A", "GostR3410-2001-CryptoPro-B",
                "GostR3410-2001-CryptoPro-C", "GostR3410-2001-CryptoPro-XchA", "GostR3410-2001-CryptoPro-XchB"));
        parameterSpecNames.put(ECGOST3410_2012_256.name(), Collections.singletonList("Tc26-Gost-3410-12-256-paramSetA")); // must be 3 more param sets, according to https://cpdn.cryptopro.ru/content/csp40/html/group___pro_c_s_p_ex_CP_PARAM_OIDS.html
        parameterSpecNames.put(ECGOST3410_2012_512.name(), Arrays.asList("Tc26-Gost-3410-12-512-paramSetA",
                "Tc26-Gost-3410-12-512-paramSetB", "Tc26-Gost-3410-12-512-paramSetC"));

        signatureAlgorithmNames = new HashMap<>();
        signatureAlgorithmNames.put(RSA.name(), "SHA1WITHRSA");
        signatureAlgorithmNames.put(ECGOST3410.name(), "GOST3411WITHECGOST3410");
        signatureAlgorithmNames.put(ECGOST3410_2012_256.name(), "GOST3411-2012-256WITHECGOST3410-2012-256");
        signatureAlgorithmNames.put(ECGOST3410_2012_512.name(), "GOST3411-2012-512WITHECGOST3410-2012-512");
    }

    public static SignAlgorithmType valueOf(PublicKey publicKey) {
        String algorithm = publicKey.getAlgorithm();
        if (RSA.name().equals(algorithm)) {
            return RSA;
        } else if (ECGOST3410.name().equals(algorithm)) {
            return ECGOST3410;
        } else if (ECGOST3410_2012.equals(algorithm) && publicKey instanceof ECPublicKey) {
            if (((ECPublicKey) publicKey).getParams().getOrder().bitLength() <= 256) {
                return ECGOST3410_2012_256;
            }
            return ECGOST3410_2012_512;
        }
        throw new IllegalArgumentException("Unsupported public key algorithm: " + algorithm);
    }

    public static SignAlgorithmType findByAlgorithmName(String algorithmName) {
        SignAlgorithmType algorithm = null;
        for (SignAlgorithmType algorithmType : SignAlgorithmType.values()) {
            if (algorithmName.endsWith(algorithmType.getBouncySignatureAlgorithmName())) {
                algorithm = algorithmType;
                break;
            }
        }
        if (algorithm == null)
            throw new IllegalArgumentException("Unsupported public key algorithm: " + algorithmName);
        return algorithm;
    }

    public static SignAlgorithmType findByCertificate(X509Certificate certificate) {
        return SignAlgorithmType.findByAlgorithmName(certificate.getSigAlgName());
    }

    public String getBouncyKeyAlgorithmName() {
        return bcNames.get(name());
    }

    public String getBouncySignatureAlgorithmName() {
        return name().replaceAll("_", "-");
    }

    public String getDigestUrn() {
        return digestUrns.get(name());
    }

    public String getDigestUri() {
        return digestUris.get(name());
    }

    public String getSignUrn() {
        return signUrns.get(name());
    }

    public String getSignUri() {
        return signUris.get(name());
    }

    public String getSignatureAlgorithmName() {
        return signatureAlgorithmNames.get(name());
    }

    public List<String> getAvailableParameterSpecificationNames() {
        return Collections.unmodifiableList(parameterSpecNames.get(name()));
    }
}