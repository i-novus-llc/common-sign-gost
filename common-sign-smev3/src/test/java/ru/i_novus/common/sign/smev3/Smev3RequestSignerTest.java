package ru.i_novus.common.sign.smev3;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.EnumSet;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class Smev3RequestSignerTest {

    private static final String TRANSFORM_ALGORITHM_URN = "urn://smev-gov-ru/xmldsig/transform";
    private static final String REFERENCE_URI_ID = "someReferenceUriId";
    private static final String PEM_ENCODED_CERTIFICATE = "somePemEncodedCertificate";
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    public static final String GOST3411_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    public static final String GOST3410_2001_URI = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    public static final String GOST3411_2012_256_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
    public static final String GOST3410_2012_256_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
    public static final String GOST3411_2012_512_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
    public static final String GOST3410_2012_512_URN = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

    @Test
    public void testCreateSignatureElements() throws Exception {

        Method method = Smev3RequestSigner.class.getDeclaredMethod("createSignatureElements", String.class, String.class, SignAlgorithmType.class);
        method.setAccessible(true);

        for (SignAlgorithmType signAlgorithmType : EnumSet.allOf(SignAlgorithmType.class)) {

            try {

                Object result = method.invoke(null, REFERENCE_URI_ID, PEM_ENCODED_CERTIFICATE, signAlgorithmType);

                Assert.assertNotNull(result);

                Assert.assertTrue(result instanceof Element);

                //Signature

                Element resultElement = (Element) result;

                Assert.assertEquals(resultElement.getNamespaceURI(), DS_NS);
                Assert.assertEquals(resultElement.getLocalName(), "Signature");

                NodeList signatureNodes = resultElement.getChildNodes();
                Assert.assertEquals(signatureNodes.getLength(), 3);

                //SignedInfo

                Node signedInfoNode = signatureNodes.item(0);
                Assert.assertEquals(signedInfoNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(signedInfoNode.getLocalName(), "SignedInfo");
                Assert.assertEquals(signedInfoNode.getAttributes().getLength(), 0);

                NodeList signedInfoNodes = signedInfoNode.getChildNodes();
                Assert.assertEquals(signedInfoNodes.getLength(), 3);

                //CanonicalizationMethod

                Node canonicalizationMethodNode = signedInfoNodes.item(0);
                Assert.assertEquals(canonicalizationMethodNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(canonicalizationMethodNode.getLocalName(), "CanonicalizationMethod");

                NamedNodeMap canonicalizationMethodAttributes = canonicalizationMethodNode.getAttributes();
                Assert.assertEquals(canonicalizationMethodAttributes.getLength(), 1);

                Node canonicalizationMethodAttributeNode = canonicalizationMethodAttributes.getNamedItem("Algorithm");
                Assert.assertNotNull(canonicalizationMethodAttributeNode);
                Assert.assertEquals(canonicalizationMethodAttributeNode.getTextContent(), Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

                //SignatureMethod

                Node signatureMethodNode = signedInfoNodes.item(1);
                Assert.assertEquals(signatureMethodNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(signatureMethodNode.getLocalName(), "SignatureMethod");

                NamedNodeMap signatureMethodAttributes = signatureMethodNode.getAttributes();
                Assert.assertEquals(signatureMethodAttributes.getLength(), 1);

                Node signatureMethodAttributeNode = signatureMethodAttributes.getNamedItem("Algorithm");
                Assert.assertNotNull(signatureMethodAttributeNode);
                Assert.assertEquals(signatureMethodAttributeNode.getTextContent(), getSignatureMethodAlgorithm(signAlgorithmType));

                //Reference

                Node referenceNode = signedInfoNodes.item(2);
                Assert.assertEquals(referenceNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(referenceNode.getLocalName(), "Reference");

                NamedNodeMap referenceAttributes = referenceNode.getAttributes();
                Assert.assertEquals(referenceAttributes.getLength(), 1);

                Node referenceAttributeNode = referenceAttributes.getNamedItem("URI");
                Assert.assertNotNull(referenceAttributeNode);
                Assert.assertEquals(referenceAttributeNode.getTextContent(), "#" + REFERENCE_URI_ID);

                NodeList referenceNodes = referenceNode.getChildNodes();

                //Transforms

                Node transformsNode = referenceNodes.item(0);
                Assert.assertEquals(transformsNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(transformsNode.getLocalName(), "Transforms");
                Assert.assertEquals(transformsNode.getAttributes().getLength(), 0);

                NodeList transformsNodes = transformsNode.getChildNodes();

                Assert.assertEquals(transformsNodes.getLength(), 2);

                //Transform

                Node transformNode = transformsNodes.item(0);
                Assert.assertEquals(transformNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(transformNode.getLocalName(), "Transform");

                NamedNodeMap transformAttributes = transformNode.getAttributes();
                Assert.assertEquals(transformAttributes.getLength(), 1);

                Node transformAttributeNode = transformAttributes.getNamedItem("Algorithm");
                Assert.assertNotNull(transformAttributeNode);
                Assert.assertEquals(transformAttributeNode.getTextContent(), Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

                //Transform

                transformNode = transformsNodes.item(1);
                Assert.assertEquals(transformNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(transformNode.getLocalName(), "Transform");

                transformAttributes = transformNode.getAttributes();
                Assert.assertEquals(transformAttributes.getLength(), 1);

                transformAttributeNode = transformAttributes.getNamedItem("Algorithm");
                Assert.assertNotNull(transformAttributeNode);
                Assert.assertEquals(transformAttributeNode.getTextContent(), TRANSFORM_ALGORITHM_URN);

                //DigestMethod

                Node digestMethodNode = referenceNodes.item(1);
                Assert.assertEquals(digestMethodNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(digestMethodNode.getLocalName(), "DigestMethod");
                Assert.assertEquals(digestMethodNode.getAttributes().getLength(), 1);

                NamedNodeMap digestMethodAttributes = digestMethodNode.getAttributes();
                Assert.assertEquals(digestMethodAttributes.getLength(), 1);

                Node digestMethodAttributeNode = digestMethodAttributes.getNamedItem("Algorithm");
                Assert.assertNotNull(digestMethodAttributeNode);
                Assert.assertEquals(digestMethodAttributeNode.getTextContent(), getDigestMethodAlgorithm(signAlgorithmType));

                //DigestValue
                Node digestValueNode = referenceNodes.item(2);
                Assert.assertEquals(digestValueNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(digestValueNode.getLocalName(), "DigestValue");
                Assert.assertEquals(digestValueNode.getAttributes().getLength(), 0);
                Assert.assertEquals(digestValueNode.getTextContent(), StringUtils.EMPTY);

                //SignatureValue

                Node signatureValueNode = signatureNodes.item(1);
                Assert.assertEquals(signatureValueNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(signatureValueNode.getLocalName(), "SignatureValue");
                Assert.assertEquals(signatureValueNode.getTextContent(), StringUtils.EMPTY);
                Assert.assertEquals(signatureValueNode.getAttributes().getLength(), 0);

                //KeyInfo

                Node keyInfoNode = signatureNodes.item(2);
                Assert.assertEquals(keyInfoNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(keyInfoNode.getLocalName(), "KeyInfo");
                Assert.assertEquals(keyInfoNode.getAttributes().getLength(), 0);

                NodeList keyInfoNodes = keyInfoNode.getChildNodes();
                Assert.assertEquals(keyInfoNodes.getLength(), 1);

                //X509Data
                Node x509DataNode = keyInfoNodes.item(0);
                Assert.assertEquals(x509DataNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(x509DataNode.getLocalName(), "X509Data");
                Assert.assertEquals(x509DataNode.getAttributes().getLength(), 0);

                NodeList x509DataNodes = x509DataNode.getChildNodes();
                Assert.assertEquals(x509DataNodes.getLength(), 1);

                //X509Certificate
                Node x509CertificateNode = x509DataNodes.item(0);
                Assert.assertEquals(x509CertificateNode.getNamespaceURI(), DS_NS);
                Assert.assertEquals(x509CertificateNode.getLocalName(), "X509Certificate");
                Assert.assertEquals(x509CertificateNode.getTextContent(), PEM_ENCODED_CERTIFICATE);
                Assert.assertEquals(x509CertificateNode.getAttributes().getLength(), 0);

            } catch (InvocationTargetException ex) {

                switch (signAlgorithmType) {
                    case ECGOST3410:
                    case ECGOST3410_2012_256:
                    case ECGOST3410_2012_512:
                        assert false;
                        break;
                    default:

                        Throwable cause = ex.getCause();

                        if (cause != null) {
                            assertThat(cause.getMessage(), is("Signature algorithm type " + signAlgorithmType + " is not supported."));
                        } else
                            assert false;

                        break;
                }
            }
        }
    }

    private String getSignatureMethodAlgorithm(SignAlgorithmType signAlgorithmType) {

        String result = null;

        switch (signAlgorithmType) {
            case ECGOST3410:
                result = GOST3410_2001_URI;
                break;
            case ECGOST3410_2012_256:
                result = GOST3410_2012_256_URN;
                break;
            case ECGOST3410_2012_512:
                result = GOST3410_2012_512_URN;
                break;
            default:
                assert false;
                break;
        }
        return result;
    }

    private String getDigestMethodAlgorithm(SignAlgorithmType signAlgorithmType) {

        String result = null;

        switch (signAlgorithmType) {
            case ECGOST3410:
                result = GOST3411_URI;
                break;
            case ECGOST3410_2012_256:
                result = GOST3411_2012_256_URN;
                break;
            case ECGOST3410_2012_512:
                result = GOST3411_2012_512_URN;
                break;
            default:
                assert false;
                break;
        }

        return result;
    }
}