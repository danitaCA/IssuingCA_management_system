package org.insa.pki.ra.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class CsrParserTest {
    private final CsrParser parser = new CsrParser();

    @BeforeAll
    static void addProvider() { Security.addProvider(new BouncyCastleProvider()); }

    @Test
    void parsesAndVerifiesRsaPkcs10Request() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=service.example.org");
        var builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
        PKCS10CertificationRequest request = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(pair.getPrivate()));
        StringWriter output = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(output)) { writer.writeObject(request); }

        CsrParser.ParsedCsr parsed = parser.parseAndVerify(output.toString());

        assertEquals("service.example.org", parsed.commonName());
        assertEquals("RSA", parsed.keyAlgorithm());
        assertEquals(2048, parsed.keySize());
        assertTrue(parsed.sans().isEmpty());
    }

    @Test
    void rejectsMalformedCsr() {
        assertThrows(ResponseStatusException.class, () -> parser.parseAndVerify("not a CSR"));
    }

    @Test
    void rejectsARequestWithoutCommonName() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Name subject = new X500Name("O=Example");
        PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate()));
        StringWriter output = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(output)) { writer.writeObject(request); }

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> parser.parseAndVerify(output.toString()));
        assertTrue(exception.getReason().contains("Common Name"));
    }
}
