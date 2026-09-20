package com.example.ca.core.domain;

public class CertificateRequest {
    private final String csr;

    public CertificateRequest(String csr) {
        this.csr = csr;
    }

    public String getCsr() {
        return csr;
    }
}
