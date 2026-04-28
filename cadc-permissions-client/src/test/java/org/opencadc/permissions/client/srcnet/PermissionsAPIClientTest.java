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

import com.sun.net.httpserver.HttpServer;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

public class PermissionsAPIClientTest {

    @Test
    public void parseAuthorisationResult() {
        AuthorisationResult r = AuthorisationResult.parse(new JSONObject("{\"is_authorised\":true}"));
        Assert.assertTrue(r.isAuthorised);
        r = AuthorisationResult.parse(new JSONObject("{\"is_authorised\":false}"));
        Assert.assertFalse(r.isAuthorised);
    }

    @Test
    public void authorisePluginPostsExpectedPathAndBody() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/v1/authorise/plugin/echo", exchange -> {
            try {
                Assert.assertEquals("POST", exchange.getRequestMethod());
                String q = exchange.getRequestURI().getQuery();
                Assert.assertNotNull(q);
                Assert.assertTrue(q.contains("token="));
                byte[] req = exchange.getRequestBody().readAllBytes();
                Assert.assertEquals("{}", new String(req, StandardCharsets.UTF_8));
                byte[] resp = "{\"is_authorised\":true}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, resp.length);
                exchange.getResponseBody().write(resp);
            } finally {
                exchange.close();
            }
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            URL base = new URL("http://127.0.0.1:" + port);
            PermissionsAPIClient client = new PermissionsAPIClient(base);
            AuthorisationResult result = client.authorisePlugin("echo", "secret", new JSONObject(), null);
            Assert.assertTrue(result.isAuthorised);
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void authoriseRoutePostsExpectedQueryAndBody() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/v1/authorise/route/api", exchange -> {
            try {
                Assert.assertEquals("POST", exchange.getRequestMethod());
                String q = exchange.getRequestURI().getQuery();
                Assert.assertNotNull(q);
                Assert.assertTrue(q.contains("route="));
                Assert.assertTrue(q.contains("token="));
                Assert.assertTrue(q.contains("method=POST"));
                byte[] req = exchange.getRequestBody().readAllBytes();
                Assert.assertEquals("{\"x\":1}", new String(req, StandardCharsets.UTF_8));
                byte[] resp = "{\"is_authorised\":false}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, resp.length);
                exchange.getResponseBody().write(resp);
            } finally {
                exchange.close();
            }
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            URL base = new URL("http://127.0.0.1:" + port);
            PermissionsAPIClient client = new PermissionsAPIClient(base);
            JSONObject body = new JSONObject();
            body.put("x", 1);
            AuthorisationResult result =
                    client.authoriseRoute("api", "/data", "tok", "POST", body, null);
            Assert.assertFalse(result.isAuthorised);
        } finally {
            server.stop(0);
        }
    }
}
