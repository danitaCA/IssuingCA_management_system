package org.insa.pki.ca.csr;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class Pkcs10CsrParser {
    private static final Set<String> ALLOWED_SIGNATURE_OIDS = Set.of(
            "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
            "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4");

    public ParsedCsr parseAndVerify(String pem) {
        if (pem == null || pem.isBlank() || pem.length() > 65_536) throw badRequest("CSR PEM is missing or too large");
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object object = parser.readObject();
            if (!(object instanceof PKCS10CertificationRequest csr) || parser.readObject() != null) {
                throw badRequest("Exactly one PKCS#10 CSR is required");
            }
            String signatureOid = csr.getSignatureAlgorithm().getAlgorithm().getId();
            if (!ALLOWED_SIGNATURE_OIDS.contains(signatureOid)) throw badRequest("CSR signature hash must be SHA-256, SHA-384, or SHA-512");
            if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(csr.getSubjectPublicKeyInfo()))) {
                throw badRequest("CSR signature verification failed");
            }

            PublicKey key = new JcaPKCS10CertificationRequest(csr).setProvider("BC").getPublicKey();
            String algorithm;
            int bits;
            if (key instanceof RSAPublicKey rsa) {
                algorithm = "RSA";
                bits = rsa.getModulus().bitLength();
            } else if (key instanceof ECPublicKey ec) {
                algorithm = "ECDSA";
                bits = ec.getParams().getCurve().getField().getFieldSize();
            } else {
                throw badRequest("Only RSA and ECDSA CSR keys are supported");
            }

            RDN[] cns = csr.getSubject().getRDNs(BCStyle.CN);
            if (cns.length == 0) throw badRequest("CSR subject must contain a Common Name");
            String commonName = IETFUtils.valueToString(cns[0].getFirst().getValue());
            if (commonName.isBlank() || commonName.length() > 255) throw badRequest("CSR Common Name is invalid");
                return new ParsedCsr(commonName, csr.getSubject().toString(), csr.getSubject(), algorithm, bits,
                    signatureOid, key, extractSans(csr));
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (Exception exception) {
            throw badRequest("CSR is malformed or cannot be verified");
        }
    }

    private List<GeneralName> extractSans(PKCS10CertificationRequest csr) {
        List<GeneralName> names = new ArrayList<>();
        ASN1ObjectIdentifier extensionRequest = PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
        for (var attribute : csr.getAttributes(extensionRequest)) {
            Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
            Extension sanExtension = extensions.getExtension(Extension.subjectAlternativeName);
            if (sanExtension != null) {
                for (GeneralName name : GeneralNames.getInstance(sanExtension.getParsedValue()).getNames()) names.add(name);
            }
        }
        return List.copyOf(names);
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
