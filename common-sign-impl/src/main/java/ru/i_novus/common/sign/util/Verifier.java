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
package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import static ru.i_novus.common.sign.util.CryptoUtil.CRYPTO_PROVIDER_NAME;

/**
 * Verifies signature
 */
@Slf4j
public class Verifier {
    private Verifier() {
        // don't instantiate
        Security.addProvider(new BouncyCastleProvider());
    }

    public static Verifier getInstance() {
        return new Verifier();
    }

    /**
     * Verifies CMS signature
     *
     * @param data signed file in {@link java.nio.file.Path} format. May be 'null'
     * @param cmsSignature CMS detached signature file in {@link java.nio.file.Path} format
     * @return result of verification as a boolean value. 'true' value means 'valid'
     * @throws CMSException cannot parse passed data as CMS signature
     * @throws CertificateException cannot construct certificate instance {@link X509Certificate}
     * @throws FileNotFoundException file cannot be found
     */
    public boolean verifyCmsSignature(Path data, Path cmsSignature) throws CMSException, CertificateException, FileNotFoundException {
        CMSSignedData signedData;
        if (data != null) {
            CMSProcessable signedContent = new CMSProcessableFile(data.toFile());
            signedData = new CMSSignedData(signedContent, new FileInputStream(cmsSignature.toFile()));
        } else {
            signedData = new CMSSignedData(new FileInputStream(cmsSignature.toFile()));
        }
        return verifyCmsSignature(signedData);
    }

    /**
     * Verifies CMS signature
     *
     * @param content signed data in byte array format
     * @param cmsSignature MS detached signature data in byta array format
     * @return result of verification as a boolean value. 'true' value means 'valid'
     * @throws CMSException cannot parse passed data as CMS signature
     * @throws CertificateException cannot construct certificate instance {@link X509Certificate}
     */
    public boolean verifyCmsSignature(byte[] content, byte[] cmsSignature) throws CMSException, CertificateException {
        CMSSignedData signedData;
        if (content != null) {
            CMSProcessable signedContent = new CMSProcessableByteArray(content);
            InputStream is = new ByteArrayInputStream(cmsSignature);
            signedData = new CMSSignedData(signedContent, is);
        } else {
            signedData = new CMSSignedData(cmsSignature);
        }
        return verifyCmsSignature(signedData);
    }

    /**
     * Verifies CMS signature by certificates
     *
     * @param signedData data in {@link org.bouncycastle.cms.CMSSignedData} format
     * @return result of verification as a boolean value. 'true' value means 'valid'
     * @throws CertificateException cannot construct certificate instance {@link X509Certificate}
     */
    public boolean verifyCmsSignature(CMSSignedData signedData) throws CertificateException {
        Store<X509CertificateHolder> store = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> signerInformation = signers.getSigners();
        boolean valid = true;
        for (SignerInformation signer : signerInformation) {
            Collection<X509CertificateHolder> certCollection = store.getMatches(signer.getSID());
            Iterator<X509CertificateHolder> certIt = certCollection.iterator();
            X509CertificateHolder certHolder = certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(CRYPTO_PROVIDER_NAME).getCertificate(certHolder);
            try {
                valid &= signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(CRYPTO_PROVIDER_NAME).build(cert));
            } catch (CMSException | OperatorCreationException e) {
                logger.warn("Certificate of '{}', SN='{}' is not valid", cert.getIssuerDN(), cert.getSerialNumber(), cert);
            }
        }
        return valid;
    }
}
