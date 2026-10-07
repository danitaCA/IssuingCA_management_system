package org.insa.pki.ca.crl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.insa.pki.ca.ca.SigningIdentity;
import org.insa.pki.ca.ca.SigningIdentityProvider;
import org.insa.pki.ca.crypto.HsmContentSignerFactory;
import org.insa.pki.ca.revocation.CaRevocationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class CrlService {
    private static final Map<String, Integer> REASONS = Map.of(
            "keyCompromise", 1, "cACompromise", 2, "affiliationChanged", 3,
            "superseded", 4, "cessationOfOperation", 5, "certificateHold", 6,
            "privilegeWithdrawn", 9, "aACompromise", 10);
    private final CaRevocationService revocations;
    private final SigningIdentityProvider identityProvider;
    private final HsmContentSignerFactory signerFactory;
    private final long validityHours;

    public CrlService(CaRevocationService revocations, SigningIdentityProvider identityProvider,
                      HsmContentSignerFactory signerFactory,
                      @Value("${app.ca.crl-validity-hours:24}") long validityHours) {
        if (validityHours < 1 || validityHours > 168) throw new IllegalArgumentException("CRL validity must be in 1..168 hours");
        this.revocations = revocations;
        this.identityProvider = identityProvider;
        this.signerFactory = signerFactory;
        this.validityHours = validityHours;
    }

    public byte[] generate() {
        try {
            SigningIdentity identity = identityProvider.load();
            Instant now = Instant.now();
            X500Name issuer = X500Name.getInstance(identity.certificate().getSubjectX500Principal().getEncoded());
            X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, Date.from(now));
            builder.setNextUpdate(Date.from(now.plusSeconds(validityHours * 3600)));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils().createAuthorityKeyIdentifier(identity.certificate()));
            for (var certificate : revocations.revokedCertificates()) {
                Integer reason = REASONS.get(certificate.getRevocationReason());
                if (reason == null) throw new IllegalStateException("Unknown stored CRL revocation reason");
                builder.addCRLEntry(new java.math.BigInteger(certificate.getSerialNumber(), 16),
                        Date.from(certificate.getRevokedAt()), reason);
            }
            X509CRLHolder crl = builder.build(signerFactory.create(identity));
            return crl.getEncoded();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to generate a CRL with the configured CA HSM identity", exception);
        }
    }
}
