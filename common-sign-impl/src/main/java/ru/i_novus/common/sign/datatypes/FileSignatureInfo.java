package ru.i_novus.common.sign.datatypes;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public final class FileSignatureInfo {

    private String encodedDigestValue;

    private byte[] signaturePKCS7;
}
