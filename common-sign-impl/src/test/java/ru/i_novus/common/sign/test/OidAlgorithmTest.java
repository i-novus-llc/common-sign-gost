package ru.i_novus.common.sign.test;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.BeforeClass;
import org.junit.Test;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

@Slf4j
public class OidAlgorithmTest {
    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void findHashAlgorithmByOid() throws CertificateException, OperatorCreationException, InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {

        assertEquals(SignAlgorithmType.findByOid(prepareCert("GostR3410-2001-CryptoPro-A",
                "GOST3411withECGOST3410", "ECGOST3410").getSigAlgOID()), (SignAlgorithmType.ECGOST3410));
        assertEquals(SignAlgorithmType.findByOid(prepareCert("Tc26-Gost-3410-12-256-paramSetA",
                "GOST3411-2012-256WITHECGOST3410-2012-256", "ECGOST3410-2012").getSigAlgOID()), (SignAlgorithmType.ECGOST3410_2012_256));
        assertEquals(SignAlgorithmType.findByOid(prepareCert("Tc26-Gost-3410-12-512-paramSetA",
                "GOST3411-2012-512WITHECGOST3410-2012-512", "ECGOST3410-2012").getSigAlgOID()), (SignAlgorithmType.ECGOST3410_2012_512));

    }

    private X509Certificate prepareCert(String stdName, String signatureAlgorithm, String algorithm) throws CertificateException, OperatorCreationException, InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec(stdName));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=i-novus");
        org.bouncycastle.asn1.x500.X500Name issuer = subject;
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));

        org.bouncycastle.cert.X509v3CertificateBuilder certificateBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                issuer, serial,
                notBefore, notAfter,
                subject, keyPair.getPublic()
        );
        org.bouncycastle.cert.X509CertificateHolder certificateHolder = certificateBuilder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(signatureAlgorithm)
                        .build(keyPair.getPrivate())
        );
        org.bouncycastle.cert.jcajce.JcaX509CertificateConverter certificateConverter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter();

        return certificateConverter.getCertificate(certificateHolder);
    }
}
