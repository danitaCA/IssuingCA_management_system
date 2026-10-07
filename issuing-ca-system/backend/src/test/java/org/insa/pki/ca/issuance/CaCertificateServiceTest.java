package org.insa.pki.ca.issuance;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.insa.pki.ca.audit.CaAuditService;
import org.insa.pki.ca.ca.SigningIdentity;
import org.insa.pki.ca.ca.SigningIdentityProvider;
import org.insa.pki.ca.certificate.IssuedCertificate;
import org.insa.pki.ca.certificate.IssuedCertificateRepository;
import org.insa.pki.ca.crypto.HsmContentSignerFactory;
import org.insa.pki.ca.csr.Pkcs10CsrParser;
import org.insa.pki.ca.profiles.CertificateProfileService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CaCertificateServiceTest {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    @BeforeAll
    static void registerProvider() { Security.addProvider(BC); }

    @Test
    void issuesCertificateFromValidCsrWithProfileExtensions() throws Exception {
        KeyPair issuerKey = rsaKeyPair();
        var issuer = selfSignedCaCertificate(issuerKey);
        KeyPair subjectKey = rsaKeyPair();
        String csrPem = createCsr(subjectKey, true);

        IssuedCertificateRepository repository = mock(IssuedCertificateRepository.class);
        when(repository.findByRequestId(anyString())).thenReturn(Optional.empty());
        AtomicReference<IssuedCertificate> saved = new AtomicReference<>();
        when(repository.saveAndFlush(any(IssuedCertificate.class))).thenAnswer(invocation -> {
            IssuedCertificate certificate = invocation.getArgument(0);
            saved.set(certificate);
            return certificate;
        });
        SigningIdentityProvider identityProvider = () -> new SigningIdentity(issuer, issuerKey.getPrivate(), BC);
        CaCertificateService service = new CaCertificateService(repository, new Pkcs10CsrParser(),
                new CertificateProfileService(365), identityProvider, new HsmContentSignerFactory("SHA256"),
                mock(CaAuditService.class));

        CaApiDtos.IssueResponse result = service.issue(new CaApiDtos.IssueRequest(
                "31ff071b-ffbb-4562-b9de-bd419263e979", csrPem, "tls-server"), "CN=ra-client", "127.0.0.1");

        assertEquals("ISSUED", result.status());
        assertNotNull(saved.get());
        assertEquals("31ff071b-ffbb-4562-b9de-bd419263e979", result.requestId());
        X509CertificateHolder holder;
        try (PEMParser parser = new PEMParser(new StringReader(result.certificatePem()))) {
            holder = (X509CertificateHolder) parser.readObject();
        }
        var certificate = new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
        certificate.verify(issuer.getPublicKey());
        assertArrayEquals(subjectKey.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
        assertEquals("svc.example.org", certificate.getSubjectAlternativeNames().iterator().next().get(1));
        assertTrue(KeyUsage.fromExtensions(holder.getExtensions()).hasUsages(
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        assertTrue(ExtendedKeyUsage.fromExtensions(holder.getExtensions()).hasKeyPurposeId(
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth));
        verify(repository).saveAndFlush(any(IssuedCertificate.class));
    }

    @Test
    void retriesAreIdempotentByRequestId() {
        IssuedCertificate existing = new IssuedCertificate("id", "31ff071b-ffbb-4562-b9de-bd419263e979",
                "12AB", "CN=svc.example.org", "tls-server", fingerprint("unused", "tls-server"),
                "CERTIFICATE", Instant.now(), Instant.now().plusSeconds(3600));
        IssuedCertificateRepository repository = mock(IssuedCertificateRepository.class);
        when(repository.findByRequestId(existing.getRequestId())).thenReturn(Optional.of(existing));
        SigningIdentityProvider identityProvider = mock(SigningIdentityProvider.class);
        CaCertificateService service = new CaCertificateService(repository, new Pkcs10CsrParser(),
                new CertificateProfileService(365), identityProvider, new HsmContentSignerFactory("SHA256"),
                mock(CaAuditService.class));

        CaApiDtos.IssueResponse result = service.issue(new CaApiDtos.IssueRequest(
                existing.getRequestId(), "unused", "tls-server"), "CN=ra-client", "127.0.0.1");

        assertEquals(existing.getSerialNumber(), result.serialNumber());
        verifyNoInteractions(identityProvider);
        verify(repository, never()).saveAndFlush(any());
    }

        @Test
        void rejectsReusingIdempotencyKeyForDifferentCsr() throws Exception {
        IssuedCertificate existing = new IssuedCertificate("id", "31ff071b-ffbb-4562-b9de-bd419263e979",
                "12AB", "CN=svc.example.org", "tls-server", fingerprint("original", "tls-server"),
                "CERTIFICATE", Instant.now(), Instant.now().plusSeconds(3600));
        IssuedCertificateRepository repository = mock(IssuedCertificateRepository.class);
        when(repository.findByRequestId(existing.getRequestId())).thenReturn(Optional.of(existing));
        CaCertificateService service = new CaCertificateService(repository, new Pkcs10CsrParser(),
                new CertificateProfileService(365), mock(SigningIdentityProvider.class),
                new HsmContentSignerFactory("SHA256"), mock(CaAuditService.class));

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> service.issue(new CaApiDtos.IssueRequest(existing.getRequestId(), "different", "tls-server"),
                        "CN=ra-client", "127.0.0.1"));
    }

    @Test
        void rejectsTlsServerRequestWithoutSan() {
        KeyPair issuerKey = rsaKeyPair();
        var issuer = selfSignedCaCertificate(issuerKey);
        String csrPem = createCsr(rsaKeyPair(), false);
        CaCertificateService service = new CaCertificateService(mock(IssuedCertificateRepository.class),
                new Pkcs10CsrParser(), new CertificateProfileService(365),
                () -> new SigningIdentity(issuer, issuerKey.getPrivate(), BC),
                new HsmContentSignerFactory("SHA256"), mock(CaAuditService.class));

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> service.issue(new CaApiDtos.IssueRequest("31ff071b-ffbb-4562-b9de-bd419263e979",
                        csrPem, "tls-server"), "CN=ra-client", "127.0.0.1"));
    }

    private KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private java.security.cert.X509Certificate selfSignedCaCertificate(KeyPair keyPair) throws Exception {
        Instant now = Instant.now();
        X500Name name = new X500Name("CN=Test Issuing CA,O=Example");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(42), Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(86400L * 3650)), name, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(1));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        var holder = builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(keyPair.getPrivate()));
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    }

    private String createCsr(KeyPair keyPair, boolean withSan) throws Exception {
        var builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=svc.example.org,O=Example"), keyPair.getPublic());
        if (withSan) {
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "svc.example.org")));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        }
        PKCS10CertificationRequest csr = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BC).build(keyPair.getPrivate()));
        String pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(csr.getEncoded()) + "\n-----END CERTIFICATE REQUEST-----\n";
        return pem;
    }

        private String fingerprint(String csr, String profile) throws Exception {
                return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                                .digest((profile + "\n" + csr).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
}
