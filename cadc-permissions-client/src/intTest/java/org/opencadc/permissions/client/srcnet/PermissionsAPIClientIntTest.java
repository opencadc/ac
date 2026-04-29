/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *
 ************************************************************************
 */

package org.opencadc.permissions.client.srcnet;

import java.net.URL;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * Live calls to a deployed Permissions API (OpenAPI
 * <a href="https://permissions.srcnet.skao.int/api/openapi.json">permissions.srcnet.skao.int</a>).
 * <p>
 * Set {@code PERMISSIONS_API_INT_TEST_BASE_URL} (e.g. {@code https://permissions.srcnet.skao.int}) and
 * {@code PERMISSIONS_API_INT_TEST_TOKEN} (access token for the {@code token} query parameter).
 * Optional: {@code PERMISSIONS_API_INT_TEST_PLUGIN_SERVICE} (defaults to {@code echo}),
 * {@code PERMISSIONS_API_INT_TEST_ROUTE_SERVICE}, {@code PERMISSIONS_API_INT_TEST_ROUTE_PATH},
 * {@code PERMISSIONS_API_INT_TEST_HTTP_METHOD} (for route test).
 */
public class PermissionsAPIClientIntTest {

    private static final String ENV_BASE_URL = "PERMISSIONS_API_INT_TEST_BASE_URL";
    private static final String ENV_TOKEN = "PERMISSIONS_API_INT_TEST_TOKEN";
    private static final String ENV_PLUGIN_SERVICE = "PERMISSIONS_API_INT_TEST_PLUGIN_SERVICE";
    private static final String ENV_ROUTE_SERVICE = "PERMISSIONS_API_INT_TEST_ROUTE_SERVICE";
    private static final String ENV_ROUTE_PATH = "PERMISSIONS_API_INT_TEST_ROUTE_PATH";
    private static final String ENV_ROUTE_METHOD = "PERMISSIONS_API_INT_TEST_HTTP_METHOD";

    @Test
    public void testLiveAuthorisePlugin() throws Exception {
        final String base = System.getenv(ENV_BASE_URL);
        final String token = System.getenv(ENV_TOKEN);
        Assume.assumeTrue(
                "Set " + ENV_BASE_URL + " and " + ENV_TOKEN + " to run this integration test",
                base != null && !base.trim().isEmpty() && token != null && !token.isEmpty());

        String pluginService = System.getenv(ENV_PLUGIN_SERVICE);
        if (pluginService == null || pluginService.isEmpty()) {
            pluginService = "echo";
        }

        final PermissionsAPIClient client = new PermissionsAPIClient(new URL(base.trim()));
        final AuthorisationResult result = client.authorisePlugin(pluginService, token, new JSONObject(), null);
        Assert.assertNotNull(result);
    }

    @Test
    public void testLiveAuthoriseRoute() throws Exception {
        final String base = System.getenv(ENV_BASE_URL);
        final String token = System.getenv(ENV_TOKEN);
        final String routeService = System.getenv(ENV_ROUTE_SERVICE);
        final String routePath = System.getenv(ENV_ROUTE_PATH);
        Assume.assumeTrue(
                "Set " + ENV_BASE_URL + ", " + ENV_TOKEN + ", " + ENV_ROUTE_SERVICE + ", and "
                        + ENV_ROUTE_PATH + " to run this integration test",
                base != null && !base.trim().isEmpty() && token != null && !token.isEmpty()
                        && routeService != null && !routeService.isEmpty()
                        && routePath != null && !routePath.isEmpty());

        String httpMethod = System.getenv(ENV_ROUTE_METHOD);
        if (httpMethod != null && httpMethod.isEmpty()) {
            httpMethod = null;
        }

        final PermissionsAPIClient client = new PermissionsAPIClient(new URL(base.trim()));
        final AuthorisationResult result =
                client.authoriseRoute(routeService, routePath, token, httpMethod, new JSONObject(), null);
        Assert.assertNotNull(result);
    }
}
