package org.insa.pki.ca.crypto;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pki.ca.ca.SigningIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HsmContentSignerFactory {
    private final String hash;
    public HsmContentSignerFactory(@Value("${app.ca.signature-hash:SHA256}") String hash) {
        if (!java.util.Set.of("SHA256", "SHA384", "SHA512").contains(hash.toUpperCase())) {
            throw new IllegalArgumentException("CA signature hash must be SHA256, SHA384, or SHA512");
        }
        this.hash = hash.toUpperCase();
    }

    public ContentSigner create(SigningIdentity identity) {
        String keyAlgorithm = identity.certificate().getPublicKey().getAlgorithm();
        String signatureAlgorithm = hash + "with" + ("EC".equalsIgnoreCase(keyAlgorithm) ? "ECDSA" : keyAlgorithm);
        try {
            return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(identity.signingProvider())
                    .build(identity.privateKey());
        } catch (Exception exception) {
            throw new IllegalStateException("Configured HSM does not support " + signatureAlgorithm, exception);
        }
    }
}
