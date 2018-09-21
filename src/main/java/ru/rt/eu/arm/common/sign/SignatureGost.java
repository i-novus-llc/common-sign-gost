package ru.rt.eu.arm.common.sign;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignatureException;
import ru.rt.eu.arm.common.sign.util.GostIds;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public abstract class SignatureGost extends SignatureAlgorithmSpi {

    private Signature signatureAlgorithm;

    private SignatureGost() throws XMLSignatureException {
        String algorithmID = JCEMapper.translateURItoJCEID(engineGetURI());
        String provider = JCEMapper.getProviderId();
        try {
            if (provider == null) {
                signatureAlgorithm = Signature.getInstance(algorithmID);
            } else {
                signatureAlgorithm = Signature.getInstance(algorithmID, provider);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            Object[] exArgs = {algorithmID, e.getLocalizedMessage()};
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected abstract String engineGetURI();

    /**
     * @inheritDoc
     */
    @Override
    protected String engineGetJCEAlgorithmString() {
        return signatureAlgorithm.getAlgorithm();
    }

    /**
     * @inheritDoc
     */
    @Override
    protected String engineGetJCEProviderName() {
        return signatureAlgorithm.getProvider().getName();
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            signatureAlgorithm.update(input);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            signatureAlgorithm.update(input);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            signatureAlgorithm.update(buf, offset, len);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineInitSign(Key signingKey) throws XMLSignatureException {
        engineInitSign(signingKey, (SecureRandom) null);
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineInitSign(Key signingKey, SecureRandom secureRandom) throws XMLSignatureException {
        if (!(signingKey instanceof PrivateKey)) {
            String supplied = null;
            if (signingKey != null) {
                supplied = signingKey.getClass().getName();
            }
            String needed = PrivateKey.class.getName();
            Object[] exArgs = {supplied, needed};
            throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
        }
        try {
            if (secureRandom == null) {
                signatureAlgorithm.initSign((PrivateKey) signingKey);
            } else {
                signatureAlgorithm.initSign((PrivateKey) signingKey, secureRandom);
            }
        } catch (InvalidKeyException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineInitSign(Key signingKey,
                                  AlgorithmParameterSpec algorithmParameterSpec) throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnDSA");
    }

    /**
     * @inheritDoc
     */
    @Override
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            return signatureAlgorithm.sign();
        } catch (SignatureException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineInitVerify(Key verificationKey) throws XMLSignatureException {
        if (!(verificationKey instanceof PublicKey)) {
            String supplied = null;
            if (verificationKey != null) {
                supplied = verificationKey.getClass().getName();
            }
            String needed = PublicKey.class.getName();
            Object[] exArgs = {supplied, needed};
            throw new XMLSignatureException("algorithms.WrongKeyForThisOperation", exArgs);
        }
        try {
            signatureAlgorithm.initVerify((PublicKey) verificationKey);
        } catch (InvalidKeyException e) {
            // reinstantiate Signature object to work around bug in JDK
            // see: http://bugs.sun.com/view_bug.do?bug_id=4953555
            Signature sig = signatureAlgorithm;
            try {
                signatureAlgorithm = Signature.getInstance(signatureAlgorithm.getAlgorithm());
            } catch (Exception ex) {
                // this shouldn't occur, but if it does, restore previous
                // Signature
                signatureAlgorithm = sig;
            }
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
        try {
            return signatureAlgorithm.verify(signature);
        } catch (SignatureException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws XMLSignatureException {
        try {
            signatureAlgorithm.setParameter(params);
        } catch (InvalidAlgorithmParameterException e) {
            throw new XMLSignatureException(e.toString());
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    protected void engineSetHMACOutputLength(int hmacOutputLength) throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
    }

    public static class Gost3410_2001_Uri extends SignatureGost {

        public Gost3410_2001_Uri() throws XMLSignatureException {
        }

        @Override
        protected String engineGetURI() {
            return GostIds.GOST3410_2001_URI;
        }
    }

    public static class Gost3410_2001_Urn extends SignatureGost {

        public Gost3410_2001_Urn() throws XMLSignatureException {
        }

        @Override
        protected String engineGetURI() {
            return GostIds.GOST3410_2001_URN;
        }
    }

    public static class Gost3410_2012_256_Uri extends SignatureGost {

        public Gost3410_2012_256_Uri() throws XMLSignatureException {
        }

        @Override
        protected String engineGetURI() {
            return GostIds.GOST3410_2012_256_URI;
        }
    }

    public static class Gost3410_2012_256_Urn extends SignatureGost {

        public Gost3410_2012_256_Urn() throws XMLSignatureException {
        }

        @Override
        protected String engineGetURI() {
            return GostIds.GOST3410_2012_256_URN;
        }
    }

    public static class Gost3410_2012_512_Uri extends SignatureGost {

        public Gost3410_2012_512_Uri() throws XMLSignatureException {
        }

        @Override
        protected String engineGetURI() {
            return GostIds.GOST3410_2012_512_URI;
        }
    }

    public static class Gost3410_2012_512_Urn extends SignatureGost {

        public Gost3410_2012_512_Urn() throws XMLSignatureException {
        }

        @Override
        protected String engineGetURI() {
            return GostIds.GOST3410_2012_512_URN;
        }
    }
}
