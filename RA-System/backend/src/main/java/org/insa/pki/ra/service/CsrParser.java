package org.insa.pki.ra.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class CsrParser {
    public record ParsedCsr(String commonName, List<String> sans, String keyAlgorithm,
                            int keySize, String signatureAlgorithm, PublicKey publicKey) {}

    public ParsedCsr parseAndVerify(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object object = parser.readObject();
            if (!(object instanceof PKCS10CertificationRequest csr) || parser.readObject() != null) {
                throw invalid("Exactly one PKCS#10 CSR is required");
            }
            var verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(csr.getSubjectPublicKeyInfo());
            if (!csr.isSignatureValid(verifier)) throw invalid("CSR signature verification failed");
            PublicKey publicKey = new JcaPKCS10CertificationRequest(csr).setProvider("BC").getPublicKey();
            String algorithm = publicKey.getAlgorithm().toUpperCase(Locale.ROOT);
            int size;
            if (publicKey instanceof RSAPublicKey rsa) {
                algorithm = "RSA";
                size = rsa.getModulus().bitLength();
            } else if (publicKey instanceof ECPublicKey ec) {
                algorithm = "ECDSA";
                size = ec.getParams().getCurve().getField().getFieldSize();
            } else {
                throw invalid("Only RSA and ECDSA public keys are supported");
            }
            RDN[] commonNames = csr.getSubject().getRDNs(BCStyle.CN);
            if (commonNames.length == 0) throw invalid("CSR subject must contain a Common Name (CN)");
            String commonName = IETFUtils.valueToString(commonNames[0].getFirst().getValue());
            List<String> sans = extractSans(csr);
            return new ParsedCsr(commonName, sans, algorithm, size,
                    csr.getSignatureAlgorithm().getAlgorithm().getId(), publicKey);
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (Exception exception) {
            throw invalid("CSR is malformed or uses an unsupported format");
        }
    }

    public String serialNumber(String certificatePem, ParsedCsr csr) {
        try (PEMParser parser = new PEMParser(new StringReader(certificatePem))) {
            Object object = parser.readObject();
            if (!(object instanceof X509CertificateHolder holder) || parser.readObject() != null) {
                throw invalid("CA returned an invalid certificate PEM");
            }
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
            if (!java.security.MessageDigest.isEqual(csr.publicKey().getEncoded(), certificate.getPublicKey().getEncoded())) {
                throw invalid("Issued certificate public key does not match the CSR");
            }
            return certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT);
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (Exception exception) {
            throw invalid("CA returned an invalid certificate");
        }
    }

    private List<String> extractSans(PKCS10CertificationRequest csr) {
        List<String> sans = new ArrayList<>();
        ASN1ObjectIdentifier extensionRequest = PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
        for (var attribute : csr.getAttributes(extensionRequest)) {
            Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
            Extension extension = extensions.getExtension(Extension.subjectAlternativeName);
            if (extension != null) {
                for (GeneralName name : GeneralNames.getInstance(extension.getParsedValue()).getNames()) {
                    sans.add(name.toString());
                }
            }
        }
        return sans;
    }

    private ResponseStatusException invalid(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
