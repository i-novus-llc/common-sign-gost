package ru.i_novus.common.sign.exception;

public class CommonSignRuntimeException extends RuntimeException {
    public CommonSignRuntimeException(Throwable cause) {
        super(cause);
    }
    public CommonSignRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }
    public CommonSignRuntimeException(String message) {
        super(message);
    }
}
