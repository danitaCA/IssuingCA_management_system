package com.example.ca.common.domain;

public record CertificateId(String value) {
    public CertificateId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Certificate ID is required");
        }
    }
}
