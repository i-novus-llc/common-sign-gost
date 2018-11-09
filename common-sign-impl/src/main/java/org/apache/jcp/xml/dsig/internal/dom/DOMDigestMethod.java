package org.apache.jcp.xml.dsig.internal.dom;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import org.w3c.dom.Element;
import ru.i_novus.common.sign.api.GostIds;


/**
 * DOM-based abstract implementation of DigestMethod.
 *
 * @author Sean Mullan
 */
public abstract class DOMDigestMethod extends BaseStructure
        implements DigestMethod {

    static final String SHA224 =
            "http://www.w3.org/2001/04/xmldsig-more#sha224"; // see RFC 4051
    static final String SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#sha384"; // see RFC 4051
    static final String WHIRLPOOL =
            "http://www.w3.org/2007/05/xmldsig-more#whirlpool"; // see RFC 6931
    static final String SHA3_224 =
            "http://www.w3.org/2007/05/xmldsig-more#sha3-224"; // see RFC 6931
    static final String SHA3_256 =
            "http://www.w3.org/2007/05/xmldsig-more#sha3-256"; // see RFC 6931
    static final String SHA3_384 =
            "http://www.w3.org/2007/05/xmldsig-more#sha3-384"; // see RFC 6931
    static final String SHA3_512 =
            "http://www.w3.org/2007/05/xmldsig-more#sha3-512"; // see RFC 6931

    static final List<String> GOST3411 = Arrays.asList(
            GostIds.GOST3411_URI,
            GostIds.GOST3411_URN);
    static final List<String> GOST3411_2012_256 = Arrays.asList(
            GostIds.GOST3411_2012_256_URI,
            GostIds.GOST3411_2012_256_URN);
    static final List<String> GOST3411_2012_512 = Arrays.asList(
            GostIds.GOST3411_2012_512_URI,
            GostIds.GOST3411_2012_512_URN);

    private DigestMethodParameterSpec params;

    /**
     * Creates a <code>DOMDigestMethod</code>.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this digest method
     */
    DOMDigestMethod(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
    {
        if (params != null && !(params instanceof DigestMethodParameterSpec)) {
            throw new InvalidAlgorithmParameterException
                    ("params must be of type DigestMethodParameterSpec");
        }
        checkParams((DigestMethodParameterSpec)params);
        this.params = (DigestMethodParameterSpec)params;
    }

    /**
     * Creates a <code>DOMDigestMethod</code> from an element. This constructor
     * invokes the abstract {@link #unmarshalParams unmarshalParams} method to
     * unmarshal any algorithm-specific input parameters.
     *
     * @param dmElem a DigestMethod element
     */
    DOMDigestMethod(Element dmElem) throws MarshalException {
        Element paramsElem = DOMUtils.getFirstChildElement(dmElem);
        if (paramsElem != null) {
            params = unmarshalParams(paramsElem);
        }
        try {
            checkParams(params);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new MarshalException(iape);
        }
    }

    static DigestMethod unmarshal(Element dmElem) throws MarshalException {
        String alg = DOMUtils.getAttributeValue(dmElem, "Algorithm");
        if (alg.equals(DigestMethod.SHA1)) {
            return new SHA1(dmElem);
        } else if (alg.equals(SHA224)) {
            return new SHA224(dmElem);
        } else if (alg.equals(DigestMethod.SHA256)) {
            return new SHA256(dmElem);
        } else if (alg.equals(SHA384)) {
            return new SHA384(dmElem);
        } else if (alg.equals(DigestMethod.SHA512)) {
            return new SHA512(dmElem);
        } else if (alg.equals(DigestMethod.RIPEMD160)) {
            return new RIPEMD160(dmElem);
        } else if (alg.equals(WHIRLPOOL)) {
            return new WHIRLPOOL(dmElem);
        } else if (alg.equals(SHA3_224)) {
            return new SHA3_224(dmElem);
        } else if (alg.equals(SHA3_256)) {
            return new SHA3_256(dmElem);
        } else if (alg.equals(SHA3_384)) {
            return new SHA3_384(dmElem);
        } else if (alg.equals(SHA3_512)) {
            return new SHA3_512(dmElem);
        } else if (GOST3411.contains(alg)) {
            return new GOST3411(dmElem, alg);
        } else if (GOST3411_2012_256.contains(alg)) {
            return new GOST3411_2012_256(dmElem, alg);
        } else if (GOST3411_2012_512.contains(alg)) {
            return new GOST3411_2012_512(dmElem, alg);
        } else {
            throw new MarshalException("unsupported DigestMethod algorithm: " +
                    alg);
        }
    }

    /**
     * Checks if the specified parameters are valid for this algorithm. By
     * default, this method throws an exception if parameters are specified
     * since most DigestMethod algorithms do not have parameters. Subclasses
     * should override it if they have parameters.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this digest method
     */
    void checkParams(DigestMethodParameterSpec params)
            throws InvalidAlgorithmParameterException
    {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("no parameters " +
                    "should be specified for the " + getMessageDigestAlgorithm() + " DigestMethod algorithm");
        }
    }

    @Override
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }

    /**
     * Unmarshals <code>DigestMethodParameterSpec</code> from the specified
     * <code>Element</code>.  By default, this method throws an exception since
     * most DigestMethod algorithms do not have parameters. Subclasses should
     * override it if they have parameters.
     *
     * @param paramsElem the <code>Element</code> holding the input params
     * @return the algorithm-specific <code>DigestMethodParameterSpec</code>
     * @throws MarshalException if the parameters cannot be unmarshalled
     */
    DigestMethodParameterSpec unmarshalParams(Element paramsElem)
            throws MarshalException
    {
        throw new MarshalException("no parameters should be specified for the " +
                getMessageDigestAlgorithm() + " DigestMethod algorithm");
    }

    /**
     * This method invokes the abstract {@link #marshalParams marshalParams}
     * method to marshal any algorithm-specific parameters.
     */
    public static void marshal(XmlWriter xwriter, DigestMethod digest, String prefix)
            throws MarshalException
    {
        xwriter.writeStartElement(prefix, "DigestMethod", XMLSignature.XMLNS);
        xwriter.writeAttribute("", "", "Algorithm", digest.getAlgorithm());

        // this is totally over-engineered - nothing implements marshalParams.
        if (digest.getParameterSpec() != null && digest instanceof DOMDigestMethod) {
            ( (DOMDigestMethod) digest).marshalParams(xwriter, prefix);
        }
        xwriter.writeEndElement(); // "DigestMethod"
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof DigestMethod)) {
            return false;
        }
        DigestMethod odm = (DigestMethod)o;

        boolean paramsEqual = params == null ? odm.getParameterSpec() == null :
                params.equals(odm.getParameterSpec());

        return getAlgorithm().equals(odm.getAlgorithm()) && paramsEqual;
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (params != null) {
            result = 31 * result + params.hashCode();
        }
        result = 31 * result + getAlgorithm().hashCode();

        return result;
    }

    /**
     * Marshals the algorithm-specific parameters to an Element and
     * appends it to the specified parent element. By default, this method
     * throws an exception since most DigestMethod algorithms do not have
     * parameters. Subclasses should override it if they have parameters.
     *
     * @param xwriter the parent element to append the parameters to
     * @param prefix the namespace prefix to use
     * @throws MarshalException if the parameters cannot be marshalled
     */
    void marshalParams(XmlWriter xwriter, String prefix) throws MarshalException
    {
        throw new MarshalException("no parameters should be specified for the " +
                getMessageDigestAlgorithm() + " DigestMethod algorithm");
    }

    /**
     * Returns the MessageDigest standard algorithm name.
     */
    abstract String getMessageDigestAlgorithm();

    static final class SHA1 extends DOMDigestMethod {
        SHA1(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA1(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return DigestMethod.SHA1;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-1";
        }
    }

    static final class SHA224 extends DOMDigestMethod {
        SHA224(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA224(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SHA224;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-224";
        }
    }

    static final class SHA256 extends DOMDigestMethod {
        SHA256(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA256(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return DigestMethod.SHA256;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-256";
        }
    }

    static final class SHA384 extends DOMDigestMethod {
        SHA384(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA384(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SHA384;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-384";
        }
    }

    static final class SHA512 extends DOMDigestMethod {
        SHA512(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA512(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return DigestMethod.SHA512;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA-512";
        }
    }

    static final class RIPEMD160 extends DOMDigestMethod {
        RIPEMD160(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        RIPEMD160(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return DigestMethod.RIPEMD160;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "RIPEMD160";
        }
    }

    static final class WHIRLPOOL extends DOMDigestMethod {
        WHIRLPOOL(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        WHIRLPOOL(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return WHIRLPOOL;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "WHIRLPOOL";
        }
    }

    static final class SHA3_224 extends DOMDigestMethod {
        SHA3_224(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA3_224(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SHA3_224;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA3-224";
        }
    }

    static final class SHA3_256 extends DOMDigestMethod {
        SHA3_256(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA3_256(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SHA3_256;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA3-256";
        }
    }

    static final class SHA3_384 extends DOMDigestMethod {
        SHA3_384(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA3_384(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SHA3_384;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA3-384";
        }
    }

    static final class SHA3_512 extends DOMDigestMethod {
        SHA3_512(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }
        SHA3_512(Element dmElem) throws MarshalException {
            super(dmElem);
        }
        @Override
        public String getAlgorithm() {
            return SHA3_512;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "SHA3-512";
        }
    }

    static final class GOST3411 extends DOMDigestMethod {
        private final String algorithm;
        GOST3411(AlgorithmParameterSpec params, String algorithm)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithm = algorithm;
        }
        GOST3411(Element dmElem, String algorithm) throws MarshalException {
            super(dmElem);
            this.algorithm = algorithm;
        }
        @Override
        public String getAlgorithm() {
            return algorithm;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "GOST3411";
        }
    }

    static final class GOST3411_2012_256 extends DOMDigestMethod {
        private final String algorithm;
        GOST3411_2012_256(AlgorithmParameterSpec params, String algorithm)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithm = algorithm;
        }
        GOST3411_2012_256(Element dmElem, String algorithm) throws MarshalException {
            super(dmElem);
            this.algorithm = algorithm;
        }
        @Override
        public String getAlgorithm() {
            return algorithm;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "GOST3411-2012-256";
        }
    }

    static final class GOST3411_2012_512 extends DOMDigestMethod {
        private final String algorithm;
        GOST3411_2012_512(AlgorithmParameterSpec params, String algorithm)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithm = algorithm;
        }
        GOST3411_2012_512(Element dmElem, String algorithm) throws MarshalException {
            super(dmElem);
            this.algorithm = algorithm;
        }
        @Override
        public String getAlgorithm() {
            return algorithm;
        }
        @Override
        String getMessageDigestAlgorithm() {
            return "GOST3411-2012-512";
        }
    }
}
