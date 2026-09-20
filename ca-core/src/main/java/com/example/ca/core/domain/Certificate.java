package com.example.ca.core.domain;

public class Certificate {
    private final String serialNumber;

    public Certificate(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSerialNumber() {
        return serialNumber;
    }
}
