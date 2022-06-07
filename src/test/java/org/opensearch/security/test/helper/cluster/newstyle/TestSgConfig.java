/*
 * Copyright 2021 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.test.helper.cluster.newstyle;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.test.helper.cluster.newstyle.NestedValueMap.Path;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.tools.Hasher;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class TestSgConfig {
    private static final Logger log = LogManager.getLogger(TestSgConfig.class);

    private String resourceFolder = null;
    private NestedValueMap overrideSgConfigSettings;
    private NestedValueMap overrideUserSettings;
    private NestedValueMap overrideRoleSettings;
    private String indexName = ".opendistro_security";

    public TestSgConfig() {

    }

    public TestSgConfig resources(String resourceFolder) {
        this.resourceFolder = resourceFolder;
        return this;
    }

    public TestSgConfig sgConfigSettings(String keyPath, Object value, Object... more) {
        if (overrideSgConfigSettings == null) {
            overrideSgConfigSettings = new NestedValueMap();
        }

        overrideSgConfigSettings.put(Path.parse(keyPath), value);

        for (int i = 0; i < more.length - 1; i += 2) {
            overrideSgConfigSettings.put(Path.parse(String.valueOf(more[i])), more[i + 1]);
        }

        return this;
    }

    public String getIndexName() {
        return indexName;
    }

    public TestSgConfig authc(AuthcDomain authcDomain) {
        if (overrideSgConfigSettings == null) {
            overrideSgConfigSettings = new NestedValueMap();
        }

        overrideSgConfigSettings.put(new Path("config", "dynamic", "authc"), authcDomain.toMap());

        return this;
    }

    public TestSgConfig xff(String proxies) {
        if (overrideSgConfigSettings == null) {
            overrideSgConfigSettings = new NestedValueMap();
        }

        overrideSgConfigSettings.put(new Path("config", "dynamic", "http", "xff"),
                NestedValueMap.of("enabled", true, "internalProxies", proxies));

        return this;
    }

    public TestSgConfig user(User user) {
        if (user.roleNames != null) {
            return this.user(user.name, user.password, user.attributes, user.roleNames);
        } else {
            return this.user(user.name, user.password, user.attributes, user.roles);
        }
    }

    public TestSgConfig user(String name, String password, String... sgRoles) {
        return user(name, password, null, sgRoles);
    }

    public TestSgConfig user(String name, String password, Map<String, Object> attributes, String... sgRoles) {
        if (overrideUserSettings == null) {
            overrideUserSettings = new NestedValueMap();
        }

        overrideUserSettings.put(new Path(name, "hash"), Hasher.hash(password.toCharArray()));

        if (sgRoles != null && sgRoles.length > 0) {
            overrideUserSettings.put(new Path(name, "opendistro_security_roles"), sgRoles);
        }

        if (attributes != null && attributes.size() != 0) {
            for (Map.Entry<String, Object> attr : attributes.entrySet()) {
                overrideUserSettings.put(new Path(name, "attributes", attr.getKey()), attr.getValue());
            }
        }

        return this;
    }

    public TestSgConfig user(String name, String password, Role... sgRoles) {
        return user(name, password, null, sgRoles);
    }

    public TestSgConfig user(String name, String password, Map<String, Object> attributes, Role... sgRoles) {
        if (overrideUserSettings == null) {
            overrideUserSettings = new NestedValueMap();
        }

        overrideUserSettings.put(new Path(name, "hash"), Hasher.hash(password.toCharArray()));

        if (sgRoles != null && sgRoles.length > 0) {
            String roleNamePrefix = "user_" + name + "__";

            overrideUserSettings.put(new Path(name, "opendistro_security_roles"),
                    Arrays.asList(sgRoles).stream().map((r) -> roleNamePrefix + r.name).collect(Collectors.toList()));
            roles(roleNamePrefix, sgRoles);
        }

        if (attributes != null && attributes.size() != 0) {
            for (Map.Entry<String, Object> attr : attributes.entrySet()) {
                overrideUserSettings.put(new Path(name, "attributes", attr.getKey()), attr.getValue());
            }
        }

        return this;
    }

    public TestSgConfig roles(Role... roles) {
        return roles("", roles);
    }

    public TestSgConfig roles(String roleNamePrefix, Role... roles) {
        if (overrideRoleSettings == null) {
            overrideRoleSettings = new NestedValueMap();
        }

        for (Role role : roles) {

            String name = roleNamePrefix + role.name;

            if (role.clusterPermissions.size() > 0) {
                overrideRoleSettings.put(new Path(name, "cluster_permissions"), role.clusterPermissions);
            }

            if (role.indexPermissions.size() > 0) {
                overrideRoleSettings.put(new Path(name, "index_permissions"),
                        role.indexPermissions.stream().map((p) -> p.toJsonMap()).collect(Collectors.toList()));
            }

            //todo commented code - because exclude_cluster_permissions was unrecognized
//            if (role.excludedClusterPermissions.size() > 0) {
//                overrideRoleSettings.put(new Path(name, "exclude_cluster_permissions"), role.excludedClusterPermissions);
//            }

            //todo commented code - because exclude_index_permissions was unrecognized
//            if (role.excludedIndexPermissions.size() > 0) {
//                overrideRoleSettings.put(new Path(name, "exclude_index_permissions"), role.excludedIndexPermissions.stream()
//                        .map((p) -> NestedValueMap.of("index_patterns", p.indexPatterns, "actions", p.actions)).collect(Collectors.toList()));
//            }
        }

        return this;
    }

    public TestSgConfig authFailureListener(AuthFailureListener authFailureListener) {
        if (overrideSgConfigSettings == null) {
            overrideSgConfigSettings = new NestedValueMap();
        }

        overrideSgConfigSettings.put(new Path("config", "dynamic", "auth_failure_listeners"), authFailureListener.toMap());

        return this;
    }

    public TestSgConfig clone() {
        TestSgConfig result = new TestSgConfig();

        result.resourceFolder = resourceFolder;
        result.indexName = indexName;
        result.overrideRoleSettings = overrideRoleSettings != null ? overrideRoleSettings.clone() : null;
        result.overrideSgConfigSettings = overrideSgConfigSettings != null ? overrideSgConfigSettings.clone() : null;
        result.overrideUserSettings = overrideUserSettings != null ? overrideUserSettings.clone() : null;

        return result;
    }

    void initIndex(Client client) {
        client.admin().indices().create(new CreateIndexRequest(indexName)).actionGet();

        writeConfigToIndex(client, CType.CONFIG, "config.yml", overrideSgConfigSettings);
        writeConfigToIndex(client, CType.ROLES, "roles.yml", overrideRoleSettings);
        writeConfigToIndex(client, CType.INTERNALUSERS, "internal_users.yml", overrideUserSettings);
        writeConfigToIndex(client, CType.ROLESMAPPING, "roles_mapping.yml", null);
        writeConfigToIndex(client, CType.ACTIONGROUPS, "action_groups.yml", null);
        writeConfigToIndex(client, CType.TENANTS, "roles_tenants.yml", null);
        //todo commented code
//        writeConfigToIndex(client, CType.BLOCKS, "sg_blocks.yml", null);

        ConfigUpdateResponse configUpdateResponse = client
                .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]))).actionGet();

        if (configUpdateResponse.hasFailures()) {
            throw new RuntimeException("ConfigUpdateResponse produced failures: " + configUpdateResponse.failures());
        }
    }

    private void writeConfigToIndex(Client client, CType configType, String file, NestedValueMap overrides) {
        try {
            NestedValueMap config;

            if (resourceFolder != null) {
                config = NestedValueMap.fromYaml(openFile(file));
            } else {
                config = NestedValueMap.of(new Path("_meta", "type"), configType.toLCString(),
                        new Path("_meta", "config_version"), 2);
            }

            if (overrides != null) {
                config.overrideLeafs(overrides);
            }

            log.info("Writing " + configType + "\n:" + config.toJsonString());

            client.index(new IndexRequest(indexName).id(configType.toLCString()).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(configType.toLCString(), BytesReference.fromByteBuffer(ByteBuffer.wrap(config.toJsonString().getBytes("utf-8")))))
                    .actionGet();

        } catch (Exception e) {
            throw new RuntimeException("Error while initializing config for " + indexName, e);
        }
    }

    private InputStream openFile(String file) throws IOException {

        String path;

        if (resourceFolder == null || resourceFolder.length() == 0 || resourceFolder.equals("/")) {
            path = "/" + file;
        } else {
            path = "/" + resourceFolder + "/" + file;
        }

        InputStream is = FileHelper.class.getResourceAsStream(path);

        if (is == null) {
            throw new FileNotFoundException("Could not find resource in class path: " + path);
        }

        return is;
    }

    public static NestedValueMap fromYaml(String yamlString) {
        try {
            return NestedValueMap.fromYaml(yamlString);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class User {
        private String name;
        private String password;
        private Role[] roles;
        private String[] roleNames;
        private Map<String, Object> attributes = new HashMap<>();

        public User(String name) {
            this.name = name;
            this.password = "secret";
        }

        public User password(String password) {
            this.password = password;
            return this;
        }

        public User roles(Role... roles) {
            this.roles = roles;
            return this;
        }

        public User roles(String... roles) {
            this.roleNames = roles;
            return this;
        }

        public User attr(String key, Object value) {
            this.attributes.put(key, value);
            return this;
        }

        public String getName() {
            return name;
        }

        public String getPassword() {
            return password;
        }

    }

    public static class Role {
        private String name;
        private List<String> clusterPermissions = new ArrayList<>();
        private List<String> excludedClusterPermissions = new ArrayList<>();

        private List<IndexPermission> indexPermissions = new ArrayList<>();
        private List<ExcludedIndexPermission> excludedIndexPermissions = new ArrayList<>();

        public Role(String name) {
            this.name = name;
        }

        public Role clusterPermissions(String... clusterPermissions) {
            this.clusterPermissions.addAll(Arrays.asList(clusterPermissions));
            return this;
        }

        public Role excludeClusterPermissions(String... clusterPermissions) {
            this.excludedClusterPermissions.addAll(Arrays.asList(clusterPermissions));
            return this;
        }

        public IndexPermission indexPermissions(String... indexPermissions) {
            return new IndexPermission(this, indexPermissions);
        }

        public ExcludedIndexPermission excludeIndexPermissions(String... indexPermissions) {
            return new ExcludedIndexPermission(this, indexPermissions);
        }

    }

    public static class IndexPermission {
        private List<String> allowedActions;
        private List<String> indexPatterns;
        private Role role;
        private String dlsQuery;
        private List<String> fls;
        private List<String> maskedFields;

        IndexPermission(Role role, String... allowedActions) {
            this.allowedActions = Arrays.asList(allowedActions);
            this.role = role;
        }

        public IndexPermission dls(String dlsQuery) {
            this.dlsQuery = dlsQuery;
            return this;
        }

        public IndexPermission fls(String... fls) {
            this.fls = Arrays.asList(fls);
            return this;
        }

        public IndexPermission maskedFields(String... maskedFields) {
            this.maskedFields = Arrays.asList(maskedFields);
            return this;
        }

        public Role on(String... indexPatterns) {
            this.indexPatterns = Arrays.asList(indexPatterns);
            this.role.indexPermissions.add(this);
            return this.role;
        }

        public NestedValueMap toJsonMap() {
            NestedValueMap result = new NestedValueMap();

            result.put("index_patterns", indexPatterns);
            result.put("allowed_actions", allowedActions);

            if (dlsQuery != null) {
                result.put("dls", dlsQuery);
            }

            if (fls != null) {
                result.put("fls", fls);
            }

            if (maskedFields != null) {
                result.put("masked_fields", maskedFields);
            }

            return result;
        }

    }

    public static class ExcludedIndexPermission {
        private List<String> actions;
        private List<String> indexPatterns;
        private Role role;

        ExcludedIndexPermission(Role role, String... actions) {
            this.actions = Arrays.asList(actions);
            this.role = role;
        }

        public Role on(String... indexPatterns) {
            this.indexPatterns = Arrays.asList(indexPatterns);
            this.role.excludedIndexPermissions.add(this);
            return this.role;
        }

    }

    public static class AuthcDomain {

        private final String id;
        private boolean enabled = true;
        private boolean transportEnabled = true;
        private int order;
        private List<String> skipUsers = new ArrayList<>();
        private List<String> enabledOnlyForIps = null;
        private HttpAuthenticator httpAuthenticator;
        private AuthenticationBackend authenticationBackend;

        public AuthcDomain(String id, int order) {
            this.id = id;
            this.order = order;
        }

        public AuthcDomain httpAuthenticator(String type) {
            this.httpAuthenticator = new HttpAuthenticator(type);
            return this;
        }

        public AuthcDomain challengingAuthenticator(String type) {
            this.httpAuthenticator = new HttpAuthenticator(type).challenge(true);
            return this;
        }

        public AuthcDomain httpAuthenticator(HttpAuthenticator httpAuthenticator) {
            this.httpAuthenticator = httpAuthenticator;
            return this;
        }

        public AuthcDomain backend(String type) {
            this.authenticationBackend = new AuthenticationBackend(type);
            return this;
        }

        public AuthcDomain backend(AuthenticationBackend authenticationBackend) {
            this.authenticationBackend = authenticationBackend;
            return this;
        }

        public AuthcDomain skipUsers(String... users) {
            this.skipUsers.addAll(Arrays.asList(users));
            return this;
        }

        public AuthcDomain enabledOnlyForIps(String... ips) {
            if (enabledOnlyForIps == null) {
                enabledOnlyForIps = new ArrayList<>();
            }

            enabledOnlyForIps.addAll(Arrays.asList(ips));
            return this;
        }

        NestedValueMap toMap() {
            NestedValueMap result = new NestedValueMap();
            result.put(new Path(id, "http_enabled"), enabled);
            result.put(new Path(id, "transport_enabled"), transportEnabled);
            result.put(new Path(id, "order"), order);

            if (httpAuthenticator != null) {
                result.put(new Path(id, "http_authenticator"), httpAuthenticator.toMap());
            }

            if (authenticationBackend != null) {
                result.put(new Path(id, "authentication_backend"), authenticationBackend.toMap());
            }

            if (enabledOnlyForIps != null) {
                result.put(new Path(id, "enabled_only_for_ips"), enabledOnlyForIps);
            }

            if (skipUsers != null && skipUsers.size() > 0) {
                result.put(new Path(id, "skip_users"), skipUsers);
            }

            return result;
        }

        public static class HttpAuthenticator {
            private final String type;
            private boolean challenge;
            private NestedValueMap config = new NestedValueMap();

            public HttpAuthenticator(String type) {
                this.type = type;
            }

            public HttpAuthenticator challenge(boolean challenge) {
                this.challenge = challenge;
                return this;
            }

            public HttpAuthenticator config(Map<String, Object> config) {
                this.config.putAllFromAnyMap(config);
                return this;
            }

            public HttpAuthenticator config(String key, Object value) {
                this.config.put(Path.parse(key), value);
                return this;
            }

            NestedValueMap toMap() {
                NestedValueMap result = new NestedValueMap();
                result.put("type", type);
                result.put("challenge", challenge);
                result.put("config", config);
                return result;
            }
        }

        public static class AuthenticationBackend {
            private final String type;
            private NestedValueMap config = new NestedValueMap();

            public AuthenticationBackend(String type) {
                this.type = type;
            }

            public AuthenticationBackend config(Map<String, Object> config) {
                this.config.putAllFromAnyMap(config);
                return this;
            }

            public AuthenticationBackend config(String key, Object value) {
                this.config.put(Path.parse(key), value);
                return this;
            }

            NestedValueMap toMap() {
                NestedValueMap result = new NestedValueMap();
                result.put("type", type);
                result.put("config", config);
                return result;
            }
        }
    }

    public static class AuthFailureListener {
        private final String id;
        private final String type;
        private int allowedTries;
        private int timeWindowSeconds = 3600;
        private int blockExpirySeconds = 600;

        public AuthFailureListener(String id, String type) {
            this.id = id;
            this.type = type;
            this.allowedTries = 3;
        }

        public AuthFailureListener(String id, String type, int allowedTries) {
            this.id = id;
            this.type = type;
            this.allowedTries = allowedTries;
        }

        NestedValueMap toMap() {
            NestedValueMap result = new NestedValueMap();
            result.put("type", type);
            result.put("allowed_tries", allowedTries);
            result.put("time_window_seconds", timeWindowSeconds);
            result.put("block_expiry_seconds", blockExpirySeconds);

            return NestedValueMap.of(id, result);
        }
    }

}
