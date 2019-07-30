package org.apache.jcp.xml.dsig.internal.dom;

/*-
 * -----------------------------------------------------------------
 * common-sign-gost
 * -----------------------------------------------------------------
 * Copyright (C) 2018 - 2019 I-Novus LLC
 * -----------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------
 */

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;

import lombok.extern.slf4j.Slf4j;
import org.apache.jcp.xml.dsig.internal.SignerOutputStream;
import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Element;
import ru.i_novus.common.sign.api.GostIds;

/**
 * DOM-based abstract implementation of SignatureMethod.
 *
 * @author Sean Mullan
 */
@Slf4j
public abstract class DOMSignatureMethod extends AbstractDOMSignatureMethod {

    private SignatureMethodParameterSpec params;
    private Signature signature;

    // see RFC 4051 for these algorithm definitions
    static final String RSA_SHA224 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
    static final String RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    static final String RSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    static final String RSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    static final String RSA_RIPEMD160 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
    static final String ECDSA_SHA1 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    static final String ECDSA_SHA224 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
    static final String ECDSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    static final String ECDSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    static final String ECDSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    static final String DSA_SHA256 =
            "http://www.w3.org/2009/xmldsig11#dsa-sha256";

    // see RFC 6931 for these algorithm definitions
    static final String ECDSA_RIPEMD160 =
            "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160";
    static final String RSA_SHA1_MGF1 =
            "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1";
    static final String RSA_SHA224_MGF1 =
            "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1";
    static final String RSA_SHA256_MGF1 =
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    static final String RSA_SHA384_MGF1 =
            "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
    static final String RSA_SHA512_MGF1 =
            "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
    static final String RSA_RIPEMD160_MGF1 =
            "http://www.w3.org/2007/05/xmldsig-more#ripemd160-rsa-MGF1";

    static final List<String> GOST3410_GOST3411 = Arrays.asList(
            GostIds.GOST3410_2001_URI,
            GostIds.GOST3410_2001_URN);
    static final List<String> GOST3410_2012_GOST3411_2012_256 = Arrays.asList(
            GostIds.GOST3410_2012_256_URI,
            GostIds.GOST3410_2012_256_URN);
    static final List<String> GOST3410_2012_GOST3411_2012_512 = Arrays.asList(
            GostIds.GOST3410_2012_512_URI,
            GostIds.GOST3410_2012_512_URN);

    /**
     * Creates a <code>DOMSignatureMethod</code>.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this signature method
     */
    DOMSignatureMethod(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
    {
        if (params != null &&
                !(params instanceof SignatureMethodParameterSpec)) {
            throw new InvalidAlgorithmParameterException
                    ("params must be of type SignatureMethodParameterSpec");
        }
        checkParams((SignatureMethodParameterSpec)params);
        this.params = (SignatureMethodParameterSpec)params;
    }

    /**
     * Creates a <code>DOMSignatureMethod</code> from an element. This ctor
     * invokes the {@link #unmarshalParams unmarshalParams} method to
     * unmarshal any algorithm-specific input parameters.
     *
     * @param smElem a SignatureMethod element
     */
    DOMSignatureMethod(Element smElem) throws MarshalException {
        Element paramsElem = DOMUtils.getFirstChildElement(smElem);
        if (paramsElem != null) {
            params = unmarshalParams(paramsElem);
        }
        try {
            checkParams(params);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new MarshalException(iape);
        }
    }

    static SignatureMethod unmarshal(Element smElem) throws MarshalException {
        String alg = DOMUtils.getAttributeValue(smElem, "Algorithm");
        if (alg.equals(SignatureMethod.RSA_SHA1)) {
            return new SHA1withRSA(smElem);
        } else if (alg.equals(RSA_SHA224)) {
            return new SHA224withRSA(smElem);
        } else if (alg.equals(RSA_SHA256)) {
            return new SHA256withRSA(smElem);
        } else if (alg.equals(RSA_SHA384)) {
            return new SHA384withRSA(smElem);
        } else if (alg.equals(RSA_SHA512)) {
            return new SHA512withRSA(smElem);
        } else if (alg.equals(RSA_RIPEMD160)) {
            return new RIPEMD160withRSA(smElem);
        } else if (alg.equals(RSA_SHA1_MGF1)) {
            return new SHA1withRSAandMGF1(smElem);
        } else if (alg.equals(RSA_SHA224_MGF1)) {
            return new SHA224withRSAandMGF1(smElem);
        } else if (alg.equals(RSA_SHA256_MGF1)) {
            return new SHA256withRSAandMGF1(smElem);
        } else if (alg.equals(RSA_SHA384_MGF1)) {
            return new SHA384withRSAandMGF1(smElem);
        } else if (alg.equals(RSA_SHA512_MGF1)) {
            return new SHA512withRSAandMGF1(smElem);
        } else if (alg.equals(RSA_RIPEMD160_MGF1)) {
            return new RIPEMD160withRSAandMGF1(smElem);
        } else if (alg.equals(SignatureMethod.DSA_SHA1)) {
            return new SHA1withDSA(smElem);
        } else if (alg.equals(DSA_SHA256)) {
            return new SHA256withDSA(smElem);
        } else if (alg.equals(ECDSA_SHA1)) {
            return new SHA1withECDSA(smElem);
        } else if (alg.equals(ECDSA_SHA224)) {
            return new SHA224withECDSA(smElem);
        } else if (alg.equals(ECDSA_SHA256)) {
            return new SHA256withECDSA(smElem);
        } else if (alg.equals(ECDSA_SHA384)) {
            return new SHA384withECDSA(smElem);
        } else if (alg.equals(ECDSA_SHA512)) {
            return new SHA512withECDSA(smElem);
        } else if (alg.equals(ECDSA_RIPEMD160)) {
            return new RIPEMD160withECDSA(smElem);
        } else if (alg.equals(SignatureMethod.HMAC_SHA1)) {
            return new DOMHMACSignatureMethod.SHA1(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA224)) {
            return new DOMHMACSignatureMethod.SHA224(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA256)) {
            return new DOMHMACSignatureMethod.SHA256(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA384)) {
            return new DOMHMACSignatureMethod.SHA384(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA512)) {
            return new DOMHMACSignatureMethod.SHA512(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_RIPEMD160)) {
            return new DOMHMACSignatureMethod.RIPEMD160(smElem);
        } else if (GOST3410_GOST3411.contains(alg)) {
            return new GOST3411withECGOST3410(smElem, alg);
        } else if (GOST3410_2012_GOST3411_2012_256.contains(alg)) {
            return new GOST34112012256withECGOST34102012(smElem, alg);
        } else if (GOST3410_2012_GOST3411_2012_512.contains(alg)) {
            return new GOST34112012512withECGOST34102012(smElem, alg);
        } else {
            throw new MarshalException
                    ("unsupported SignatureMethod algorithm: " + alg);
        }
    }

    @Override
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }

    @Override
    boolean verify(Key key, SignedInfo si, byte[] sig,
                   XMLValidateContext context)
            throws InvalidKeyException, SignatureException, XMLSignatureException
    {
        if (key == null || si == null || sig == null) {
            throw new NullPointerException();
        }

        if (!(key instanceof PublicKey)) {
            throw new InvalidKeyException("key must be PublicKey");
        }
        if (signature == null) {
            try {
                Provider p = (Provider)context.getProperty
                        ("org.jcp.xml.dsig.internal.dom.SignatureProvider");
                signature = (p == null)
                        ? Signature.getInstance(getJCAAlgorithm())
                        : Signature.getInstance(getJCAAlgorithm(), p);
            } catch (NoSuchAlgorithmException nsae) {
                throw new XMLSignatureException(nsae);
            }
        }
        signature.initVerify((PublicKey)key);
        if (logger.isDebugEnabled()) {
            logger.debug("Signature provider: {}", signature.getProvider());
            logger.debug("Verifying with key: {}", key);
            logger.debug("JCA Algorithm: {}", getJCAAlgorithm());
            logger.debug("Signature Bytes length: {}", sig.length);
        }

        try (SignerOutputStream outputStream = new SignerOutputStream(signature)) {
            ((DOMSignedInfo)si).canonicalize(context, outputStream);

            Type type = getAlgorithmType();
            if (type == Type.DSA) {
                int size = ((DSAKey)key).getParams().getQ().bitLength();
                return signature.verify(JavaUtils.convertDsaXMLDSIGtoASN1(sig,
                        size/8));
            } else if (type == Type.ECDSA) {
                return signature.verify(SignatureECDSA.convertXMLDSIGtoASN1(sig));
            } else {
                return signature.verify(sig);
            }
        } catch (IOException ioe) {
            throw new XMLSignatureException(ioe);
        }
    }

    byte[] sign(Key key, SignedInfo si, XMLSignContext context)
            throws InvalidKeyException, XMLSignatureException
    {
        if (key == null || si == null) {
            throw new NullPointerException();
        }

        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("key must be PrivateKey");
        }
        if (signature == null) {
            try {
                Provider p = (Provider)context.getProperty
                        ("org.jcp.xml.dsig.internal.dom.SignatureProvider");
                signature = (p == null)
                        ? Signature.getInstance(getJCAAlgorithm())
                        : Signature.getInstance(getJCAAlgorithm(), p);
            } catch (NoSuchAlgorithmException nsae) {
                throw new XMLSignatureException(nsae);
            }
        }
        signature.initSign((PrivateKey)key);
        if (logger.isDebugEnabled()) {
            logger.debug("Signature provider: {}", signature.getProvider());
            logger.debug("Signing with key: {}", key);
            logger.debug("JCA Algorithm: {}", getJCAAlgorithm());
        }

        try (SignerOutputStream outputStream = new SignerOutputStream(signature)) {
            ((DOMSignedInfo)si).canonicalize(context, outputStream);

            Type type = getAlgorithmType();
            if (type == Type.DSA) {
                int size = ((DSAKey)key).getParams().getQ().bitLength();
                return JavaUtils.convertDsaASN1toXMLDSIG(signature.sign(),
                        size/8);
            } else if (type == Type.ECDSA) {
                return SignatureECDSA.convertASN1toXMLDSIG(signature.sign());
            } else {
                return signature.sign();
            }
        } catch (SignatureException | IOException se) {
            throw new XMLSignatureException(se);
        }
    }

    static final class SHA1withRSA extends DOMSignatureMethod {
        SHA1withRSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SignatureMethod.RSA_SHA1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA1withRSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA224withRSA extends DOMSignatureMethod {
        SHA224withRSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA224withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA224;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA224withRSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA256withRSA extends DOMSignatureMethod {
        SHA256withRSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA256;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA256withRSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA384withRSA extends DOMSignatureMethod {
        SHA384withRSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA384withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA384;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA384withRSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA512withRSA extends DOMSignatureMethod {
        SHA512withRSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA512withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA512;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA512withRSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class RIPEMD160withRSA extends DOMSignatureMethod {
        RIPEMD160withRSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        RIPEMD160withRSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_RIPEMD160;
        }
        @Override
        String getJCAAlgorithm() {
            return "RIPEMD160withRSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA1withRSAandMGF1 extends DOMSignatureMethod {
        SHA1withRSAandMGF1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1withRSAandMGF1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA1_MGF1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA1withRSAandMGF1";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA224withRSAandMGF1 extends DOMSignatureMethod {
        SHA224withRSAandMGF1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA224withRSAandMGF1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA224_MGF1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA224withRSAandMGF1";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA256withRSAandMGF1 extends DOMSignatureMethod {
        SHA256withRSAandMGF1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256withRSAandMGF1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA256_MGF1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA256withRSAandMGF1";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA384withRSAandMGF1 extends DOMSignatureMethod {
        SHA384withRSAandMGF1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA384withRSAandMGF1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA384_MGF1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA384withRSAandMGF1";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA512withRSAandMGF1 extends DOMSignatureMethod {
        SHA512withRSAandMGF1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA512withRSAandMGF1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_SHA512_MGF1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA512withRSAandMGF1";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class RIPEMD160withRSAandMGF1 extends DOMSignatureMethod {
        RIPEMD160withRSAandMGF1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        RIPEMD160withRSAandMGF1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return RSA_RIPEMD160_MGF1;
        }
        @Override
        String getJCAAlgorithm() {
            return "RIPEMD160withRSAandMGF1";
        }
        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    static final class SHA1withDSA extends DOMSignatureMethod {
        SHA1withDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1withDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SignatureMethod.DSA_SHA1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA1withDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.DSA;
        }
    }

    static final class SHA256withDSA extends DOMSignatureMethod {
        SHA256withDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256withDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        public String getAlgorithm() {
            return DSA_SHA256;
        }
        String getJCAAlgorithm() {
            return "SHA256withDSA";
        }
        Type getAlgorithmType() {
            return Type.DSA;
        }
    }

    static final class SHA1withECDSA extends DOMSignatureMethod {
        SHA1withECDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1withECDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return ECDSA_SHA1;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA1withECDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    static final class SHA224withECDSA extends DOMSignatureMethod {
        SHA224withECDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA224withECDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return ECDSA_SHA224;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA224withECDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    static final class SHA256withECDSA extends DOMSignatureMethod {
        SHA256withECDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256withECDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return ECDSA_SHA256;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA256withECDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    static final class SHA384withECDSA extends DOMSignatureMethod {
        SHA384withECDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA384withECDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return ECDSA_SHA384;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA384withECDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    static final class SHA512withECDSA extends DOMSignatureMethod {
        SHA512withECDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA512withECDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return ECDSA_SHA512;
        }
        @Override
        String getJCAAlgorithm() {
            return "SHA512withECDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    static final class RIPEMD160withECDSA extends DOMSignatureMethod {
        RIPEMD160withECDSA(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        RIPEMD160withECDSA(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return ECDSA_RIPEMD160;
        }
        @Override
        String getJCAAlgorithm() {
            return "RIPEMD160withECDSA";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    static final class GOST3411withECGOST3410 extends DOMSignatureMethod {
        private final String algorithm;
        GOST3411withECGOST3410(AlgorithmParameterSpec params, String algorithm)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithm = algorithm;
        }
        GOST3411withECGOST3410(Element dmElem, String algorithm) throws MarshalException {
            super(dmElem);
            this.algorithm = algorithm;
        }
        @Override
        public String getAlgorithm() {
            return algorithm;
        }
        @Override
        String getJCAAlgorithm() {
            return "GOST3411withECGOST3410";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECGOST3410;
        }
    }

    static final class GOST34112012256withECGOST34102012 extends DOMSignatureMethod {
        private final String algorithm;
        GOST34112012256withECGOST34102012(AlgorithmParameterSpec params, String algorithm)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithm = algorithm;
        }
        GOST34112012256withECGOST34102012(Element dmElem, String algorithm) throws MarshalException {
            super(dmElem);
            this.algorithm = algorithm;
        }
        @Override
        public String getAlgorithm() {
            return algorithm;
        }
        @Override
        String getJCAAlgorithm() {
            return "GOST3411-2012-256withECGOST3410-2012-256";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECGOST3410_2012;
        }
    }

    static final class GOST34112012512withECGOST34102012 extends DOMSignatureMethod {
        private final String algorithm;
        GOST34112012512withECGOST34102012(AlgorithmParameterSpec params, String algorithm)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithm = algorithm;
        }
        GOST34112012512withECGOST34102012(Element dmElem, String algorithm) throws MarshalException {
            super(dmElem);
            this.algorithm = algorithm;
        }
        @Override
        public String getAlgorithm() {
            return algorithm;
        }
        @Override
        String getJCAAlgorithm() {
            return "GOST3411-2012-512withECGOST3410-2012-512";
        }
        @Override
        Type getAlgorithmType() {
            return Type.ECGOST3410_2012;
        }
    }
}
