package com.example.ca.common.exception;

public class PkiException extends RuntimeException {
    public PkiException(String message) {
        super(message);
    }

    public PkiException(String message, Throwable cause) {
        super(message, cause);
    }
}
