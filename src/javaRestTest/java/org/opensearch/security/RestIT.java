package org.opensearch.security;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.PemUtils;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.*;
import org.opensearch.client.indices.CreateIndexRequest;
import org.opensearch.client.indices.CreateIndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.support.XContentMapValues;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class RestIT extends OpenSearchRestTestCase {

    public static final String CA_CERTIFICATE_SETTING = "plugins.security.test_certificate.ca_certificate";
    public static final String CERTIFICATE_SETTING = "plugins.security.test_certificate.certificate";
    public static final String PRIVATE_KEY_SETTING = "plugins.security.test_certificate.private_key";
    public static final String PRIVATE_KEY_PASSWORD_SETTING = "plugins.security.test_certificate.private_key_password";
    public static final String CLIENT_AUTHENTICATION_SETTING = "plugins.security.test_certificate.client_authentication";


    @Before
    public void initSecurityIndex() throws Exception {
        DynamicSecurityConfig dynamicSecurityConfig = new DynamicSecurityConfig();
        try (HighLevelClient client = new HighLevelClient(adminClient())) {
            CreateIndexResponse createSecurityIndexResponse = client.indices()
                    .create(createIndexRequest(dynamicSecurityConfig.getSecurityIndexName()), RequestOptions.DEFAULT);
            List<IndexRequest> configRequests = dynamicSecurityConfig.getDynamicConfig(getResourceFolder());
            for(IndexRequest ir: configRequests) {
                String configResponse = client.index(ir, RequestOptions.DEFAULT).getId();
            }
            Request configUpdateRequest = new Request(
                    "PUT", "/_plugins/_security/configupdate?config_types=" + String.join(",", CType.lcStringValues())
            );
            Response configUpdateResponse = client.getLowLevelClient()
                    .performRequest(configUpdateRequest);

            Map<String, Object> configUpdateResponseBody = responseAsMap(configUpdateResponse);
            assertFalse("Config update should not cause any failure", (Boolean) XContentMapValues.extractValue("configupdate_response.has_failures", configUpdateResponseBody));
        }
    }

    private String getResourceFolder() {
        return null;
    }


    private static class TestConfig {

        public TestConfig(String user, String endpoint, Boolean shouldSucceed) {
            this(user, "password", endpoint, shouldSucceed);
        }

        public TestConfig(String user, String password, String endpoint, Boolean shouldSucceed) {
            this.user = user;
            this.password = password;
            this.endpoint = endpoint;
            this.shouldSucceed = shouldSucceed;
        }

        private String user;
        private String password;
        private String endpoint;
        private Boolean shouldSucceed;

        public String getUser() {
            return user;
        }

        public String getPassword() {
            return password;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public Boolean getShouldSucceed() {
            return shouldSucceed;
        }
    }

    @Test
    public void firstTest() throws IOException {
        Request healthRequest = new Request("GET", "_cluster/health/");
        Response healthResponse = adminClient().performRequest(healthRequest);
        Map<String, Object> healthResponseBody = responseAsMap(healthResponse);
        assertEquals("Health status should be green", "green", healthResponseBody.get("status"));

        try (HighLevelClient client = new HighLevelClient(adminClient())) {
            CreateIndexResponse responseA = client.indices().create(createIndexRequest("index-a"), RequestOptions.DEFAULT);
            CreateIndexResponse responseB = client.indices().create(createIndexRequest("index-b"), RequestOptions.DEFAULT);
        }

        List<TestConfig> testConfigs = Arrays.asList(
                new TestConfig("user-a", "index-a/_search", true),
                new TestConfig("user-a", "index-b/_search", false),
                new TestConfig("user-b", "index-a/_search", true),
                new TestConfig("user-b", "index-b/_search", true)
        );
        testConfigs.forEach(config -> {
            RequestOptions basicAuth = basicAuthRequestOptions(config.getUser(), config.getPassword());
            Request searchRequest = new Request("GET", config.getEndpoint());
            searchRequest.setOptions(basicAuth);
            try {
                Response searchResponse = client().performRequest(searchRequest);
                assertEquals(200, searchResponse.getStatusLine().getStatusCode());
            } catch (IOException e) {
                assertFalse("request should not cause exception", config.getShouldSucceed());
            }
        });
    }

    private CreateIndexRequest createIndexRequest(String name) {
        return new CreateIndexRequest(name)
                .settings(Settings.builder()
                        .put("index.number_of_shards", 1)
                        .put("index.auto_expand_replicas", "0-all")
                );
    }

    private RequestOptions basicAuthRequestOptions(String user, String password) {
        return RequestOptions.DEFAULT.toBuilder()
                .addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8)))
                .build();
    }

    @Override
    protected String getProtocol() {
        return "https";
    }

    @Override
    protected Settings restClientSettings() {
        return Settings
                .builder()
                .put(CA_CERTIFICATE_SETTING, "certs/root-ca.pem")
                .put(CERTIFICATE_SETTING, "certs/spock.pem")
                .put(PRIVATE_KEY_SETTING, "certs/spock.key")
                .put(CLIENT_AUTHENTICATION_SETTING, false)
                .build();
    }

    @Override
    protected Settings restAdminSettings() {
        return Settings
                .builder()
                .put(CA_CERTIFICATE_SETTING, "certs/root-ca.pem")
                .put(CERTIFICATE_SETTING, "certs/kirk.pem")
                .put(PRIVATE_KEY_SETTING, "certs/kirk.key")
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

    private static class HighLevelClient extends RestHighLevelClient {
        private HighLevelClient(RestClient restClient) {
            super(restClient, (client) -> {}, Collections.emptyList());
        }
    }

}
