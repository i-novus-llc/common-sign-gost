package ru.i_novus.common.sign.smev;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.i_novus.common.sign.api.SignAlgorithmType;
import ru.i_novus.common.sign.util.CryptoFormatConverter;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class Smev3RequestSigner {
    private static final String SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS = "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.2";

    private Smev3RequestSigner() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static void signSmev3Request(SOAPMessage message, PrivateKey privateKey, X509Certificate certificate)
            throws SOAPException, XMLSecurityException {
        SOAPEnvelope envelope = message.getSOAPPart().getEnvelope();
        SOAPBody soapBody = envelope.getBody();
        Node actionNode = getActionNode(soapBody);

        if (actionNode != null) {
            String contentElementId = getContentId(actionNode);

            // Добавляем элемент CallerInformationSystemSignature
            Element callerInformationSignature = soapBody.getOwnerDocument().createElementNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "CallerInformationSystemSignature");
            Node callerSigElement = actionNode.appendChild(callerInformationSignature);
            callerSigElement.setPrefix("ns2");

            // Подписываем сообщение
            Transforms transforms = new Transforms(soapBody.getOwnerDocument());
            transforms.addTransform(CanonicalizationMethod.EXCLUSIVE);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);

            SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);

            XMLSignature signature = new XMLSignature(soapBody.getOwnerDocument(), "", signAlgorithmType.getSignUri(), CanonicalizationMethod.EXCLUSIVE);
            signature.addDocument("#" + contentElementId, transforms, signAlgorithmType.getDigestUri());

            signature.addKeyInfo(certificate);
            signature.sign(privateKey);
            callerSigElement.appendChild(soapBody.getOwnerDocument().importNode(signature.getElement(), true));
        }
    }

    public static void signSmev3Request(SOAPMessage message, String encodedCertificate, String privateKey) throws
            XMLSecurityException, SOAPException {

        CryptoFormatConverter converter = CryptoFormatConverter.getInstance();
        X509Certificate certificate = converter.getCertificateFromPEMEncoded(encodedCertificate);
        SignAlgorithmType signAlgorithmType = SignAlgorithmType.findByCertificate(certificate);
        PrivateKey pk = converter.getPKFromPEMEncoded(signAlgorithmType, privateKey);

        signSmev3Request(message, pk, certificate);
    }

    private static Node getActionNode(SOAPBody soapBody) {
        Node actionNode = null;
        if (soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "SendRequestRequest").getLength() > 0) {           // SendRequest
            actionNode = soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "SendRequestRequest").item(0);
        } else if (soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "SendReponseRequest").getLength() > 0) {    // SendResponse
            actionNode = soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "SendReponseRequest").item(0);
        } else if (soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "GetResponseRequest").getLength() > 0) {    // GetResponse
            actionNode = soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "GetResponseRequest").item(0);
        } else if (soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "SendResponseRequest").getLength() > 0) {   // SendResponse
            actionNode = soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "SendResponseRequest").item(0);
        } else if (soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "AckRequest").getLength() > 0) {            // AckRequest
            actionNode = soapBody.getElementsByTagNameNS(SMEV3_MESSAGE_EXCHANGE_TYPES_1_2_NS, "AckRequest").item(0);
        }
        return actionNode;
    }

    private static String getContentId(Node actionNode) {
        String id = null;
        NodeList nodes = actionNode.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element) {
                Element element = (Element) node;
                String attributeValue = element.getAttribute("Id");
                if (!StringUtils.isEmpty(attributeValue)) {
                    id = attributeValue;
                    break;
                }
            }
        }

        return id;
    }
}
