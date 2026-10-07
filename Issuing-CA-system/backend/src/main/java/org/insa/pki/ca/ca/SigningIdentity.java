package org.insa.pki.ca.ca;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

/** A signing identity whose private key may be a non-exportable HSM token handle. */
public record SigningIdentity(X509Certificate certificate, PrivateKey privateKey, Provider signingProvider) {}
