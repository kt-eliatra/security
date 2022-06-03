package org.opensearch.security;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.securityconf.impl.CType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DynamicSecurityConfig {

    private String securityIndexName = ".opendistro_security";
    private String securityConfig = "config.yml";
    private String securityRoles = "roles.yml";
    private String securityTenants = "roles_tenants.yml";
    private String securityRolesMapping = "roles_mapping.yml";
    private String securityInternalUsers = "internal_users.yml";
    private String securityActionGroups = "action_groups.yml";
    private String securityNodesDn = "nodes_dn.yml";
    private String securityWhitelist= "whitelist.yml";
    private String securityAllowlist= "allowlist.yml";
    private String securityAudit = "audit.yml";
    private String securityConfigAsYamlString = null;
    private String legacyConfigFolder = "";

    public String getSecurityIndexName() {
        return securityIndexName;
    }

    public DynamicSecurityConfig setSecurityIndexName(String securityIndexName) {
        this.securityIndexName = securityIndexName;
        return this;
    }

    public DynamicSecurityConfig setConfig(String securityConfig) {
        this.securityConfig = securityConfig;
        return this;
    }

    public DynamicSecurityConfig setConfigAsYamlString(String securityConfigAsYamlString) {
        this.securityConfigAsYamlString = securityConfigAsYamlString;
        return this;
    }

    public DynamicSecurityConfig setSecurityRoles(String securityRoles) {
        this.securityRoles = securityRoles;
        return this;
    }

    public DynamicSecurityConfig setSecurityRolesMapping(String securityRolesMapping) {
        this.securityRolesMapping = securityRolesMapping;
        return this;
    }

    public DynamicSecurityConfig setSecurityInternalUsers(String securityInternalUsers) {
        this.securityInternalUsers = securityInternalUsers;
        return this;
    }

    public DynamicSecurityConfig setSecurityActionGroups(String securityActionGroups) {
        this.securityActionGroups = securityActionGroups;
        return this;
    }

    public DynamicSecurityConfig setSecurityNodesDn(String nodesDn) {
        this.securityNodesDn = nodesDn;
        return this;
    }

    public DynamicSecurityConfig setSecurityWhitelist(String whitelist){
        this.securityWhitelist = whitelist;
        return this;
    }

    public DynamicSecurityConfig setSecurityAllowlist(String allowlist){
        this.securityAllowlist = allowlist;
        return this;
    }

    public DynamicSecurityConfig setSecurityAudit(String audit) {
        this.securityAudit = audit;
        return this;
    }

    public DynamicSecurityConfig setLegacy() {
        this.legacyConfigFolder = "legacy/securityconfig_v6/";
        return this;
    }

    public List<IndexRequest> getDynamicConfig(String folder) {

        final String prefix = legacyConfigFolder+(folder == null?"":folder+"/");

        List<IndexRequest> ret = new ArrayList<IndexRequest>();

        //todo is XContentType.JSON required, it was not used before, but I had some problems with it, sometimes it was YAML, sometimes SMILE...
        ret.add(new IndexRequest(securityIndexName)
                .id(CType.CONFIG.toLCString())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .source(XContentType.JSON, CType.CONFIG.toLCString(), securityConfigAsYamlString==null? FileHelper.readYamlContent(prefix+securityConfig):FileHelper.readYamlContentFromString(securityConfigAsYamlString)));

        ret.add(new IndexRequest(securityIndexName)
                .id(CType.ACTIONGROUPS.toLCString())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .source(XContentType.JSON, CType.ACTIONGROUPS.toLCString(), FileHelper.readYamlContent(prefix+securityActionGroups)));

        ret.add(new IndexRequest(securityIndexName)
                .id(CType.INTERNALUSERS.toLCString())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .source(XContentType.JSON, CType.INTERNALUSERS.toLCString(), FileHelper.readYamlContent(prefix+securityInternalUsers)));

        ret.add(new IndexRequest(securityIndexName)
                .id(CType.ROLES.toLCString())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .source(XContentType.JSON, CType.ROLES.toLCString(), FileHelper.readYamlContent(prefix+securityRoles)));

        ret.add(new IndexRequest(securityIndexName)
                .id(CType.ROLESMAPPING.toLCString())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .source(XContentType.JSON, CType.ROLESMAPPING.toLCString(), FileHelper.readYamlContent(prefix+securityRolesMapping)));
        if("".equals(legacyConfigFolder)) {
            ret.add(new IndexRequest(securityIndexName)
                    .id(CType.TENANTS.toLCString())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(XContentType.JSON, CType.TENANTS.toLCString(), FileHelper.readYamlContent(prefix+securityTenants)));
        }

        if (null != FileHelper.getAbsoluteFilePathFromClassPath(prefix + securityNodesDn)) {
            ret.add(new IndexRequest(securityIndexName)
                    .id(CType.NODESDN.toLCString())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(XContentType.JSON, CType.NODESDN.toLCString(), FileHelper.readYamlContent(prefix + securityNodesDn)));

        }

        final String whitelistYmlFile = prefix + securityWhitelist;
        if (null != FileHelper.getAbsoluteFilePathFromClassPath(whitelistYmlFile)) {
            ret.add(new IndexRequest(securityIndexName)
                    .id(CType.WHITELIST.toLCString())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(XContentType.JSON, CType.WHITELIST.toLCString(), FileHelper.readYamlContent(whitelistYmlFile)));
        }

        final String allowlistYmlFile = prefix + securityAllowlist;
        if (null != FileHelper.getAbsoluteFilePathFromClassPath(allowlistYmlFile)) {
            ret.add(new IndexRequest(securityIndexName)
                    .id(CType.ALLOWLIST.toLCString())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(XContentType.JSON, CType.ALLOWLIST.toLCString(), FileHelper.readYamlContent(allowlistYmlFile)));
        }

        final String auditYmlFile = prefix + securityAudit;
        if (null != FileHelper.getAbsoluteFilePathFromClassPath(auditYmlFile)) {
            ret.add(new IndexRequest(securityIndexName)
                    .id(CType.AUDIT.toLCString())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(XContentType.JSON, CType.AUDIT.toLCString(), FileHelper.readYamlContent(auditYmlFile)));
        }

        return Collections.unmodifiableList(ret);
    }

}
