package com.example.ca.core.domain;

public class AuditEvent {
    private final String action;

    public AuditEvent(String action) {
        this.action = action;
    }

    public String getAction() {
        return action;
    }
}
