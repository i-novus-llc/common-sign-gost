package ru.i_novus.common.sign.exception;

public class SignatureVerificationException extends RuntimeException {
    public SignatureVerificationException(String message) {
        super(message);
    }
    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
