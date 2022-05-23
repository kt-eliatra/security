package org.opensearch.security;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.PemUtils;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.junit.Test;
import org.opensearch.client.*;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.util.Optional;

public class RestIT extends OpenSearchRestTestCase {

    public static final String CA_CERTIFICATE_SETTING = "plugins.security.test_certificate.ca_certificate";
    public static final String CERTIFICATE_SETTING = "plugins.security.test_certificate.certificate";
    public static final String PRIVATE_KEY_SETTING = "plugins.security.test_certificate.private_key";
    public static final String PRIVATE_KEY_PASSWORD_SETTING = "plugins.security.test_certificate.private_key_password";
    public static final String CLIENT_AUTHENTICATION_SETTING = "plugins.security.test_certificate.client_authentication";

    @Test
    public void firstTest() throws IOException {
        Request request = new Request("GET", "_cluster/health");
        Response response = adminClient().performRequest(request);
        assertEquals(200, response.getStatusLine().getStatusCode());
        String body = new String(response.getEntity().getContent().readAllBytes());
        assertNotEquals(body + ".indexOf(status:green) != -1 ", -1, body.indexOf("\"status\":\"green\""));
    }

    @Test
    public void secondTest() throws IOException {
        Request request = new Request("GET", "_cluster/health");
        request.addParameter("ignore", "401");
        Response response = client().performRequest(request);
        assertEquals("Response status == 401", 401, response.getStatusLine().getStatusCode());
    }

    @Override
    protected String getProtocol() {
        return "https";
    }

    @Override
    protected Settings restClientSettings() {
        return Settings
                .builder()
                .put(CA_CERTIFICATE_SETTING, "root-ca.pem")
                .put(CERTIFICATE_SETTING, "spock.pem")
                .put(PRIVATE_KEY_SETTING, "spock.key")
                .put(CLIENT_AUTHENTICATION_SETTING, false)
                .build();
    }

    @Override
    protected Settings restAdminSettings() {
        return Settings
                .builder()
                .put(CA_CERTIFICATE_SETTING, "root-ca.pem")
                .put(CERTIFICATE_SETTING, "kirk.pem")
                .put(PRIVATE_KEY_SETTING, "kirk.key")
                .put(CLIENT_AUTHENTICATION_SETTING, true)
                .build();
    }

    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {
        RestClientBuilder builder = RestClient.builder(hosts);
        configureClient(builder, settings);
        builder.setStrictDeprecationMode(false);
        return builder
                .setHttpClientConfigCallback(sslContextInitializer(settings))
                .build();
    }

    private RestClientBuilder.HttpClientConfigCallback sslContextInitializer(Settings settings) {
        return httpClientBuilder -> httpClientBuilder.setSSLStrategy(
                new SSLIOSessionStrategy(getSslContext(settings), null, null, NoopHostnameVerifier.INSTANCE));
    }

    private SSLContext getSslContext(Settings settings) {
        String caCertificate = settings.get(CA_CERTIFICATE_SETTING);
        String certificate = settings.get(CERTIFICATE_SETTING);
        String privateKey = settings.get(PRIVATE_KEY_SETTING);
        String privateKeyPassword = settings.get(PRIVATE_KEY_PASSWORD_SETTING);
        boolean clientAuthentication = settings.getAsBoolean(CLIENT_AUTHENTICATION_SETTING, false);

        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(getClass().getClassLoader().getResourceAsStream(caCertificate));

        SSLFactory.Builder builder = SSLFactory.builder()
                .withTrustMaterial(trustManager);

        if (clientAuthentication) {
            X509ExtendedKeyManager keyManager = Optional.ofNullable(privateKeyPassword)
                    .map(password -> PemUtils.loadIdentityMaterial(
                            getClass().getClassLoader().getResourceAsStream(certificate),
                            getClass().getClassLoader().getResourceAsStream(privateKey),
                            password.toCharArray()))
                    .orElse(PemUtils.loadIdentityMaterial(
                            getClass().getClassLoader().getResourceAsStream(certificate),
                            getClass().getClassLoader().getResourceAsStream(privateKey)));
            builder.withIdentityMaterial(keyManager);
        }

        return builder.build().getSslContext();
    }

}
