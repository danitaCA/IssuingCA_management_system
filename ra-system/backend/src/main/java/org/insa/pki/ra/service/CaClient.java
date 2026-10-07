package org.insa.pki.ra.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;

@Service
public class CaClient {
    public record IssuePayload(String requestId, String csrPem, String profileName) {}
    public record IssueResult(String certificatePem) {}
    public record RevokePayload(String requestId, String serialNumber, String reason) {}

    private final RestClient client;

    public CaClient(@Value("${app.ca.base-url}") String baseUrl,
                    @Value("${app.ca.connect-timeout-seconds:3}") long connectTimeout,
                    @Value("${app.ca.read-timeout-seconds:20}") long readTimeout,
                    @Value("${app.ca.client-keystore:}") String keyStorePath,
                    @Value("${app.ca.client-keystore-password:}") String keyStorePassword,
                    @Value("${app.ca.truststore:}") String trustStorePath,
                    @Value("${app.ca.truststore-password:}") String trustStorePassword) {
        try {
            boolean local = "localhost".equalsIgnoreCase(URI.create(baseUrl).getHost()) || "127.0.0.1".equals(URI.create(baseUrl).getHost());
            boolean haveKey = !keyStorePath.isBlank() && !keyStorePassword.isBlank();
            boolean haveTrust = !trustStorePath.isBlank() && !trustStorePassword.isBlank();
            if (!local && !URI.create(baseUrl).getScheme().equalsIgnoreCase("https")) {
                throw new IllegalStateException("CA_BASE_URL must use HTTPS outside local development");
            }
            if (!local && (!haveKey || !haveTrust)) {
                throw new IllegalStateException("CA client keystore and truststore are required for non-local CA integration");
            }
            if (haveKey != haveTrust) throw new IllegalStateException("Configure both CA mTLS stores or neither for local development");

            HttpClient.Builder http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(connectTimeout));
            if (haveKey) http.sslContext(createSslContext(keyStorePath, keyStorePassword, trustStorePath, trustStorePassword));
            JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(http.build());
            requestFactory.setReadTimeout(Duration.ofSeconds(readTimeout));
            this.client = RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to configure mTLS connection to Issuing CA", exception);
        }
    }

    public IssueResult issue(IssuePayload payload) {
        IssueResult result = client.post().uri("/certificates/issue")
                .header("Idempotency-Key", payload.requestId())
                .contentType(MediaType.APPLICATION_JSON).body(payload)
                .retrieve().body(IssueResult.class);
        if (result == null || result.certificatePem() == null || result.certificatePem().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Issuing CA returned no certificate");
        }
        return result;
    }

    public void revoke(RevokePayload payload) {
        client.post().uri("/certificates/revoke")
                .header("Idempotency-Key", payload.requestId())
                .contentType(MediaType.APPLICATION_JSON).body(payload)
                .retrieve().toBodilessEntity();
    }

    private SSLContext createSslContext(String keyPath, String keyPassword, String trustPath, String trustPassword) throws Exception {
        char[] keyPass = keyPassword.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(Path.of(keyPath))) { keyStore.load(input, keyPass); }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, keyPass);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(Path.of(trustPath))) { trustStore.load(input, trustPassword.toCharArray()); }
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        return context;
    }
}
