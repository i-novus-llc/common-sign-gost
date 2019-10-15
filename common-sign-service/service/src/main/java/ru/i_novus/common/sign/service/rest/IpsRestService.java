package ru.i_novus.common.sign.service.rest;

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import ru.i_novus.common.sign.ips.IpsRequestSigner;
import ru.i_novus.common.sign.service.api.model.DocumentToSign;
import ru.i_novus.common.sign.service.api.model.IpsRequestToSign;
import ru.i_novus.common.sign.service.api.model.SignatureResult;
import ru.i_novus.common.sign.service.api.rest.IpsRest;
import ru.i_novus.common.sign.service.core.api.KeystoreService;
import ru.i_novus.common.sign.soap.SoapUtil;

import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Slf4j
@Controller
public class IpsRestService implements IpsRest {

    @Autowired
    private KeystoreService keystoreService;

    @Override
    public SignatureResult signIpsRequest(IpsRequestToSign document) {
        SignatureResult result = new SignatureResult();
        try {
            byte[] messageContent = Base64.getDecoder().decode(document.getDocContent());
            SOAPMessage soapMessage = getSoapMessage(messageContent);

            final BigInteger serialNumber = document.getSerialNumber();
            X509Certificate certificate = keystoreService.getCertificate(serialNumber)
                    .orElseThrow(() -> new IllegalStateException("Certificate with serial number '" + serialNumber + "' is not found"));

            PrivateKey privateKey = keystoreService.getPrivateKey(serialNumber)
                    .orElseThrow(() -> new IllegalStateException("Private key for certificate '" + serialNumber + "' is not found"));

            result = signRequest(document, certificate, soapMessage, privateKey);
        } catch (RuntimeException e) {
            logger.error("Cannot process request document to sign", e);
            result.setError("Cannot process request document to sign");
            result.setMessage(e.getLocalizedMessage());
        }

        return result;
    }

    private SignatureResult signRequest(IpsRequestToSign document, X509Certificate certificate, SOAPMessage soapMessage, PrivateKey privateKey) {
        SignatureResult result = new SignatureResult();
        try {
            IpsRequestSigner.signIpsRequest(soapMessage, document.getSoapService(), document.getSoapAction(),
                    document.getClientEntityId(), privateKey, certificate);
            result.setSignedData(SoapUtil.getSoapMessageContent(soapMessage).getBytes(StandardCharsets.UTF_8));
        } catch (SOAPException | GeneralSecurityException | TransformerException |
                InvalidCanonicalizerException | CanonicalizationException | IOException e) {
            logger.error(e.getLocalizedMessage(), e);
            result.setError("Cannot sign request");
            result.setMessage(e.getLocalizedMessage());
        }
        return result;
    }

    @Override
    public SignatureResult signIpsResponse(DocumentToSign document) {
        SignatureResult result;
        try {
            byte[] messageContent = Base64.getDecoder().decode(document.getDocContent());
            SOAPMessage soapMessage = getSoapMessage(messageContent);

            final BigInteger serialNumber = document.getSerialNumber();
            X509Certificate certificate = keystoreService.getCertificate(serialNumber)
                    .orElseThrow(() -> new IllegalStateException("Certificate with serial number '" + serialNumber + "' is not found"));

            PrivateKey privateKey = keystoreService.getPrivateKey(serialNumber)
                    .orElseThrow(() -> new IllegalStateException("Private key for certificate '" + serialNumber + "' is not found"));

            result = signResponse(soapMessage, certificate, privateKey);
        } catch (RuntimeException e) {
            logger.error(e.getLocalizedMessage(), e);
            result = new SignatureResult();
            result.setError("Cannot sign request");
            result.setMessage(e.getLocalizedMessage());
        }

        return result;
    }

    private SignatureResult signResponse(SOAPMessage soapMessage, X509Certificate certificate, PrivateKey privateKey) {
        SignatureResult result = new SignatureResult();
        try {
            IpsRequestSigner.signIpsResponse(soapMessage, privateKey, certificate);
            result.setSignedData(SoapUtil.getSoapMessageContent(soapMessage).getBytes(StandardCharsets.UTF_8));
        } catch (SOAPException | GeneralSecurityException | TransformerException |
                InvalidCanonicalizerException | CanonicalizationException | IOException e) {
            logger.error(e.getLocalizedMessage(), e);
            result.setError("Cannot sign response");
            result.setMessage(e.getLocalizedMessage());
        }
        return result;
    }

    private SOAPMessage getSoapMessage(final byte[] docContent) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(docContent);
        return SoapUtil.constructMessage(inputStream, SOAPConstants.SOAP_1_1_PROTOCOL);
    }
}
