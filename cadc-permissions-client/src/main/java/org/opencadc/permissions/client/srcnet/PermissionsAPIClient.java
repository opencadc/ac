/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)        licence, soit (à votre gré)
 *  any later version.                  toute version ultérieure.
 *
 ************************************************************************
 */

package org.opencadc.permissions.client.srcnet;

import ca.nrc.cadc.net.FileContent;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.NetUtil;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * HTTP client for the SKAO Permissions API {@code /v1/authorise} endpoints.
 * Requires a proper base URL to be configured.
 *
 * <p>Endpoint shapes and behaviour follow the service OpenAPI description:
 * <a href="https://permissions.srcnet.skao.int/api/openapi.json">https://permissions.srcnet.skao.int/api/openapi.json</a>
 */
public class PermissionsAPIClient {

    private static final String JSON_CONTENT_TYPE = "application/json";

    private final URL baseURL;

    /**
     * Resolve the Permissions API base URL from the registry.
     *
     * @param baseServiceURL  Base URL to the PermissionsAPI service
     */
    public PermissionsAPIClient(final URL baseServiceURL) {
        Objects.requireNonNull(baseServiceURL, "Base service URL cannot be null");
        this.baseURL = normalizeBase(baseServiceURL);
    }

    /**
     * POST {@code /v1/authorise/plugin/{service}}.
     *
     * @param requestBody JSON body; null is treated as {@code {}}
     */
    public AuthorisationResult authorisePlugin(final String serviceName, final String token,
                                               final JSONObject requestBody, final String version) throws IOException {
        assertArg(serviceName, "serviceName");
        assertArg(token, "token");
        final JSONObject body = requestBody != null ? requestBody : new JSONObject();
        final URL url = buildPluginURL(serviceName, token, version);
        final JSONObject json = PermissionsAPIClient.postBody(url, body);
        try {
            return AuthorisationResult.parse(json);
        } catch (JSONException e) {
            throw new IOException("invalid JSON response", e);
        }
    }

    /**
     * POST {@code /v1/authorise/route/{service}}.
     *
     * @param route       required route query parameter
     * @param httpMethod  optional HTTP method; if null the server default applies
     * @param requestBody JSON body; null is treated as {@code {}}
     */
    public AuthorisationResult authoriseRoute(final String serviceName, final String route, final String token,
                                              final String httpMethod, final JSONObject requestBody,
                                              final String version) throws IOException {
        assertArg(serviceName, "serviceName");
        assertArg(route, "route");
        assertArg(token, "token");
        final JSONObject body = requestBody != null ? requestBody : new JSONObject();
        final URL url = buildRouteURL(serviceName, route, token, httpMethod, version);
        final JSONObject json = PermissionsAPIClient.postBody(url, body);
        try {
            return AuthorisationResult.parse(json);
        } catch (JSONException e) {
            throw new IOException("invalid JSON response", e);
        }
    }

    private URL buildPluginURL(final String serviceName, final String token, final String version)
            throws MalformedURLException {
        String q = PermissionsAPIClient.queryTokenVersion(token, version);
        String path = "v1/authorise/plugin/" + PermissionsAPIClient.encodePathSegment(serviceName);
        return new URL(baseURL.toExternalForm() + "/" + path + "?" + q);
    }

    private URL buildRouteURL(final String serviceName, final String route, final String token,
                              final String httpMethod, final String version) throws MalformedURLException {
        final StringBuilder q = new StringBuilder();
        q.append("route=").append(NetUtil.encode(route));
        q.append("&token=").append(NetUtil.encode(token));
        if (httpMethod != null && !httpMethod.isEmpty()) {
            q.append("&method=").append(NetUtil.encode(httpMethod));
        }
        if (version != null && !version.isEmpty()) {
            q.append("&version=").append(NetUtil.encode(version));
        }
        final String path = "v1/authorise/route/" + PermissionsAPIClient.encodePathSegment(serviceName);
        return new URL(baseURL.toExternalForm() + "/" + path + "?" + q);
    }

    private static String queryTokenVersion(final String token, final String version) {
        final StringBuilder q = new StringBuilder();

        q.append("token=").append(NetUtil.encode(token));
        if (version != null && !version.isEmpty()) {
            q.append("&version=").append(NetUtil.encode(version));
        }
        return q.toString();
    }

    private static String encodePathSegment(final String s) {
        return NetUtil.encode(s);
    }

    private static URL normalizeBase(final URL u) {
        try {
            final String s = u.toExternalForm();
            if (s.endsWith("/")) {
                return new URL(s.substring(0, s.length() - 1));
            }
            return u;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private static void assertArg(final String value, final String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("invalid " + name + ": null or empty");
        }
    }

    private static JSONObject postBody(final URL url, final JSONObject json) throws IOException {
        final HttpPost post = new HttpPost(url, new FileContent(json.toString(), PermissionsAPIClient.JSON_CONTENT_TYPE,
                StandardCharsets.UTF_8), false);
        post.setRequestProperty("Accept", "application/json");
        try {
            post.prepare();
        } catch (Throwable t) {
            final int code = post.getResponseCode();
            throw new IOException("HTTP transfer failed: " + code + ": " + t.getMessage(), t);
        }

        return new JSONObject(new JSONTokener(post.getInputStream()));
    }
}
