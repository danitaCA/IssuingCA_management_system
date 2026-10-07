package org.insa.pki.ca.issuance;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.insa.pki.ca.audit.CaAuditService;
import org.insa.pki.ca.ca.SigningIdentity;
import org.insa.pki.ca.ca.SigningIdentityProvider;
import org.insa.pki.ca.certificate.IssuedCertificate;
import org.insa.pki.ca.certificate.IssuedCertificateRepository;
import org.insa.pki.ca.csr.ParsedCsr;
import org.insa.pki.ca.csr.Pkcs10CsrParser;
import org.insa.pki.ca.crypto.HsmContentSignerFactory;
import org.insa.pki.ca.profiles.CertificateProfile;
import org.insa.pki.ca.profiles.CertificateProfileService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class CaCertificateService {
    private final IssuedCertificateRepository certificates;
    private final Pkcs10CsrParser csrParser;
    private final CertificateProfileService profiles;
    private final SigningIdentityProvider signingIdentityProvider;
    private final HsmContentSignerFactory signerFactory;
    private final CaAuditService audit;
    private final SecureRandom secureRandom = new SecureRandom();

    public CaCertificateService(IssuedCertificateRepository certificates, Pkcs10CsrParser csrParser,
                                CertificateProfileService profiles, SigningIdentityProvider signingIdentityProvider,
                                HsmContentSignerFactory signerFactory, CaAuditService audit) {
        this.certificates = certificates;
        this.csrParser = csrParser;
        this.profiles = profiles;
        this.signingIdentityProvider = signingIdentityProvider;
        this.signerFactory = signerFactory;
        this.audit = audit;
    }

    @Transactional
    public CaApiDtos.IssueResponse issue(CaApiDtos.IssueRequest request, String actor, String ip) {
        String requestFingerprint = fingerprint(request.csrPem(), request.profileName());
        var existing = certificates.findByRequestId(request.requestId());
        if (existing.isPresent()) {
            if (!existing.get().getRequestFingerprint().equals(requestFingerprint)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency key was already used for a different CSR or profile");
            }
            return toResponse(existing.get());
        }

        ParsedCsr csr = csrParser.parseAndVerify(request.csrPem());
        CertificateProfile profile = profiles.validate(request.profileName(), csr);
        SigningIdentity identity = signingIdentityProvider.load();
        X509Certificate issuer = identity.certificate();
        if (!issuer.getNotAfter().toInstant().isAfter(Instant.now().plus(profile.validity()))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Configured CA certificate expires before the requested certificate validity");
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(profile.validity());
        BigInteger serial = new BigInteger(159, secureRandom).setBit(158);
        X500Name issuerName = X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, serial, Date.from(issuedAt.minusSeconds(60)), Date.from(expiresAt),
                csr.subject(), csr.publicKey());

        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            int usages = KeyUsage.digitalSignature;
            if (profile.keyEnciphermentAllowed() && "RSA".equals(csr.keyAlgorithm())) usages |= KeyUsage.keyEncipherment;
            if ("code-signing".equals(profile.name())) usages |= KeyUsage.nonRepudiation;
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(usages));
                KeyPurposeId[] eku = profile.extendedKeyUsages().stream()
                    .map(oid -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(oid)))
                    .toArray(KeyPurposeId[]::new);
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
            builder.addExtension(Extension.subjectKeyIdentifier, false, new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils().createSubjectKeyIdentifier(csr.publicKey()));
            builder.addExtension(Extension.authorityKeyIdentifier, false, new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer));
            if (!csr.subjectAltNames().isEmpty()) {
                builder.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(csr.subjectAltNames().toArray(GeneralName[]::new)));
            }

            ContentSigner signer = signerFactory.create(identity);
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
            certificate.verify(issuer.getPublicKey());
            certificate.checkValidity(Date.from(issuedAt));
            if (!java.security.MessageDigest.isEqual(csr.publicKey().getEncoded(), certificate.getPublicKey().getEncoded())) {
                throw new IllegalStateException("Issued certificate public key differs from the CSR");
            }
            String pem = toPem(holder);
            IssuedCertificate saved = certificates.saveAndFlush(new IssuedCertificate(UUID.randomUUID().toString(),
                    request.requestId(), serial.toString(16).toUpperCase(), csr.subjectDn(), profile.name(),
                    requestFingerprint, pem, issuedAt, expiresAt));
            audit.record(actor, ip, "CERTIFICATE_ISSUED", saved.getSerialNumber(), "Profile=" + profile.name());
            return toResponse(saved);
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Certificate signing or validation failed", exception);
        }
    }

    @Transactional(readOnly = true)
    public java.util.List<CertificateProfile> listProfiles() { return profiles.list(); }

    private String toPem(X509CertificateHolder holder) throws Exception {
        StringWriter text = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(text)) { writer.writeObject(holder); }
        return text.toString();
    }

    private CaApiDtos.IssueResponse toResponse(IssuedCertificate certificate) {
        return new CaApiDtos.IssueResponse(certificate.getRequestId(), certificate.getSerialNumber(),
                certificate.getCertificatePem(), certificate.getIssuedAt(), certificate.getExpiresAt(), "ISSUED");
    }

    private String fingerprint(String csrPem, String profileName) {
        try {
            byte[] bytes = (profileName + "\n" + csrPem).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
