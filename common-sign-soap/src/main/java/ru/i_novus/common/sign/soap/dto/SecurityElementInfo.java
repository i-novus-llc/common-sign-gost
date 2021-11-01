package ru.i_novus.common.sign.soap.dto;

import lombok.Getter;
import lombok.Setter;
import ru.i_novus.common.sign.api.SignAlgorithmType;

import javax.xml.soap.SOAPMessage;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

@Getter
@Setter
public class SecurityElementInfo {
    private SOAPMessage message;
    private X509Certificate certificate;
    private SignAlgorithmType signAlgorithmType;
    private String actor;
    private ZonedDateTime expireDateTime;
    private String bodyReferenceId;
    private String messageIdReferenceId;
    private String replyToReferenceId;
    private String toReferenceId;
    private String actionReferenceId;
}