package ru.i_novus.common.sign.service.rest;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import ru.i_novus.common.sign.service.api.model.SignatureResult;
import ru.i_novus.common.sign.service.api.model.ValidateResult;
import ru.i_novus.common.sign.service.api.model.XmlDocumentToSign;
import ru.i_novus.common.sign.service.api.rest.XmlRest;
import ru.i_novus.common.sign.service.core.api.KeystoreService;
import ru.i_novus.common.sign.util.CryptoIO;


@Slf4j
@Controller
public class XmlRestService implements XmlRest {
    @Autowired
    private KeystoreService keystoreService;

    @Autowired
    private CryptoIO cryptoIO;

    @Override
    public ValidateResult verify() {
        throw new NotImplementedException("The feature is not implemented yet");
    }

    @Override
    public ValidateResult verifyhash() {
        throw new NotImplementedException("The feature is not implemented yet");
    }

    @Override
    public SignatureResult sign(XmlDocumentToSign params) {
        throw new NotImplementedException("The feature is not implemented yet");
        /*
        X509Certificate certificate = keystoreService.getCertificate(params.getSerialNumber())
                .orElseThrow(() -> new IllegalStateException("Certificate with serial number '" + params.getSerialNumber() + "' is not found"));

        SignAlgorithmType algorithmType = SignAlgorithmType.findByCertificate(certificate);

        PrivateKey privateKey = keystoreService.getPrivateKey(params.getSerialNumber())
                .orElseThrow(() -> new IllegalStateException("Private key for certificate '" + params.getSerialNumber() + "' is not found"));

        byte[] signature;
        try {
            signature = CryptoUtil.getSignature(params.getDocContent(), privateKey, algorithmType);
        } catch (GeneralSecurityException e) {
            logger.error("Cannot sign data", e);
            throw new RuntimeException("Cannot sign data", e);
        }
        SignatureResult result = new SignatureResult();
        result.setSignedData(signature);
        return result;
        */
    }
}
