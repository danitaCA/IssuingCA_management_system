package org.insa.pki.ca.ca;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;

/** Loads the CA key handle from a Java PKCS#11 provider without exporting key bytes. */
@Component
public class Pkcs11SigningIdentityProvider implements SigningIdentityProvider {
    private final String configPath;
    private final String alias;
    private final String pin;

    public Pkcs11SigningIdentityProvider(@Value("${app.hsm.pkcs11-config:}") String configPath,
                                         @Value("${app.hsm.key-alias:}") String alias,
                                         @Value("${app.hsm.pin:}") String pin) {
        this.configPath = configPath;
        this.alias = alias;
        this.pin = pin;
    }

    @Override
    public SigningIdentity load() {
        if (configPath.isBlank() || alias.isBlank() || pin.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "PKCS#11 HSM is not configured; issuance is disabled");
        }
        try {
            Provider baseProvider = Security.getProvider("SunPKCS11");
            if (baseProvider == null) throw new IllegalStateException("JDK SunPKCS11 provider is unavailable");
            Provider provider = baseProvider.configure(configPath);
            if (Security.getProvider(provider.getName()) == null) Security.addProvider(provider);

            KeyStore token = KeyStore.getInstance("PKCS11", provider);
            char[] tokenPin = pin.toCharArray();
            token.load(null, tokenPin);
            Certificate certificate = token.getCertificate(alias);
            java.security.Key key = token.getKey(alias, tokenPin);
            if (!(certificate instanceof X509Certificate issuer) || !(key instanceof PrivateKey privateKey)) {
                throw new IllegalStateException("HSM alias must have an X.509 CA certificate and private signing key");
            }
            issuer.checkValidity();
            if (issuer.getBasicConstraints() < 0) throw new IllegalStateException("Configured HSM certificate is not a CA certificate");
            boolean[] usage = issuer.getKeyUsage();
            if (usage == null || usage.length < 7 || !usage[5] || !usage[6]) {
                throw new IllegalStateException("CA certificate must permit keyCertSign and cRLSign");
            }
            if (!privateKey.getAlgorithm().equalsIgnoreCase(issuer.getPublicKey().getAlgorithm())) {
                throw new IllegalStateException("HSM private key algorithm does not match the CA certificate");
            }
            return new SigningIdentity(issuer, privateKey, provider);
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Unable to load the CA signing identity from the configured HSM");
        }
    }
}
