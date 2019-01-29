package ru.i_novus.common.sign.util;

import lombok.extern.slf4j.Slf4j;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.pkcs.SignerInfo;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Slf4j
public class PKCS7Util {

    private PKCS7Util() {
        // не позволяет создать экземпляр класса, класс утилитный
    }

    public static PKCS9Attributes getPKCS9Attributes(byte[] attachmentDigest) throws IOException {

        PKCS9Attribute[] authenticatedAttributeList = {
                new PKCS9Attribute(PKCS9Attribute.CONTENT_TYPE_OID, sun.security.pkcs.ContentInfo.DATA_OID),
                new PKCS9Attribute(PKCS9Attribute.SIGNING_TIME_OID, new Date()),
                new PKCS9Attribute(PKCS9Attribute.MESSAGE_DIGEST_OID, attachmentDigest)
        };

        return new PKCS9Attributes(authenticatedAttributeList);
    }

    public static SignerInfo getSignerInfo(final X509Certificate certificate, PKCS9Attributes authenticatedAttributes, byte[] signedAttributes, final String encryptionAlgorithmOid, final String hashAlgorithmOid) throws IOException, NoSuchAlgorithmException {

        BigInteger serial = certificate.getSerialNumber();

        X500Name x500Name = new X500Name(certificate.getIssuerX500Principal().getName());

        return new SignerInfo(
                x500Name,
                serial,
                AlgorithmId.get(hashAlgorithmOid),
                authenticatedAttributes,
                new AlgorithmId(new ObjectIdentifier(encryptionAlgorithmOid)),
                signedAttributes,
                null);
    }

    public static SignerInfo[] getSignerInfos(final X509Certificate certificate, PKCS9Attributes authenticatedAttributes, byte[] signedAttributes, final String encryptionAlgorithmOid, final String hashAlgorithmOid) throws IOException, NoSuchAlgorithmException {
        return new SignerInfo[]{getSignerInfo(certificate, authenticatedAttributes, signedAttributes, encryptionAlgorithmOid, hashAlgorithmOid)};
    }
}