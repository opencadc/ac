/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026.                            (c) 2026.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *
 ************************************************************************
 */

package org.opencadc.permissions.client.srcnet;

import ca.nrc.cadc.net.NetUtil;
import java.net.URL;
import org.junit.Assert;
import org.junit.Test;

public class PermissionsAPIClientTest {

    @Test
    public void buildAuthTokenExchangeUrlEncodesQuery() throws Exception {
        final URL base = new URL("https://auth.example");
        final URL u = PermissionsAPIClient.buildAuthTokenExchangeUrl(base, "my-service", "tok&=", "v1");
        Assert.assertTrue(u.toExternalForm().startsWith("https://auth.example/v1/token/exchange/my-service?"));
        Assert.assertTrue(u.getQuery().contains("access_token=" + NetUtil.encode("tok&=")));
        Assert.assertTrue(u.getQuery().contains("version=" + NetUtil.encode("v1")));
    }

    @Test
    public void buildAuthTokenExchangeUrlOmitsVersionWhenNull() throws Exception {
        final URL base = new URL("https://auth.example/sub");
        final URL u = PermissionsAPIClient.buildAuthTokenExchangeUrl(base, "s", "t", null);
        Assert.assertEquals(
                "https://auth.example/sub/v1/token/exchange/s?access_token=" + NetUtil.encode("t"),
                u.toExternalForm());
    }
}
