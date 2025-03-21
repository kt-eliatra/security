/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.saml;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;

import com.amazon.dlic.util.SettingsBasedSSLConfigurator;

import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;

public class SamlHTTPMetadataResolver extends HTTPMetadataResolver {

    SamlHTTPMetadataResolver(String idpMetadataUrl, Settings opensearchSettings, Path configPath) throws Exception {
        super(createHttpClient(opensearchSettings, configPath), idpMetadataUrl);
        setMinRefreshDelay(opensearchSettings.getAsLong("idp.min_refresh_delay", 60L * 1000L));
        setMaxRefreshDelay(opensearchSettings.getAsLong("idp.max_refresh_delay", 14400000L));
        setRefreshDelayFactor(opensearchSettings.getAsFloat("idp.refresh_delay_factor", 0.75f));
    }

    @Override
    @SuppressWarnings("removal")
    protected byte[] fetchMetadata() throws ResolverException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                @Override
                public byte[] run() throws ResolverException {
                    return SamlHTTPMetadataResolver.super.fetchMetadata();
                }
            });
        } catch (PrivilegedActionException e) {

            if (e.getCause() instanceof ResolverException) {
                throw (ResolverException) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private static SettingsBasedSSLConfigurator.SSLConfig getSSLConfig(Settings settings, Path configPath)
            throws Exception {
        return new SettingsBasedSSLConfigurator(settings, configPath, "idp").buildSSLConfig();
    }

    @SuppressWarnings("removal")
    private static HttpClient createHttpClient(Settings settings, Path configPath) throws Exception {
        try {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged(new PrivilegedExceptionAction<HttpClient>() {
                @Override
                public HttpClient run() throws Exception {
                    return createHttpClient0(settings, configPath);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private static HttpClient createHttpClient0(Settings settings, Path configPath) throws Exception {

        HttpClientBuilder builder = HttpClients.custom();

        builder.useSystemProperties();

        SettingsBasedSSLConfigurator.SSLConfig sslConfig = getSSLConfig(settings, configPath);

        if (sslConfig != null) {
            builder.setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory());
        }

        return builder.build();
    }

}
