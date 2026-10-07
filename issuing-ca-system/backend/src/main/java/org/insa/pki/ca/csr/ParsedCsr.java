package org.insa.pki.ca.csr;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x500.X500Name;
import java.security.PublicKey;
import java.util.List;

public record ParsedCsr(String commonName, String subjectDn, X500Name subject, String keyAlgorithm, int keySize,
                        String signatureOid, PublicKey publicKey, List<GeneralName> subjectAltNames) {}
