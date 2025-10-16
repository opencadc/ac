/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2025.                            (c) 2025.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.xml.UserReader;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.CookiePrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.PrincipalExtractor;
import ca.nrc.cadc.auth.RunnableAction;
import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.auth.SignedToken;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.date.DateUtil;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Log4jInit;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class LoginIntTest {
    private static final Logger log = Logger.getLogger(LoginIntTest.class);

    private final URI serviceURI;
    private final URL serviceURL;
    Subject authSubject;

    static {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.auth", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.net", Level.INFO);
    }

    public LoginIntTest() {
        serviceURI = URI.create(ConfigUsers.AC_SERVICE_ID);
        log.debug("serviceURI: " + serviceURI);
        RegistryClient regClient = new RegistryClient();
        serviceURL = regClient
                .getServiceURL(serviceURI, Standards.UMS_LOGIN_01, AuthMethod.ANON);
        log.info("serviceUrl: " + serviceURL);
        Assert.assertNotNull(serviceURL);
    }

    Set<Principal> getPrincipals(final Class<? extends Principal> principalClass, final Set<Principal> principals) {
        Set<Principal> matchedPrincipals = new HashSet<>();

        for (final Principal p : principals) {
            if (p.getClass().equals(principalClass)) {
                matchedPrincipals.add(p);
            }
        }

        return matchedPrincipals;
    }

    @Test
    public void testLoginHappyPath() throws Exception
    {
        try
        {
            PasswordAuthentication pa = ConfigUsers.getInstance().getPasswordAuthUser();
            HashMap<String, Object> params = new HashMap<>();
            params.put("username", pa.getUserName());
            params.put("password", pa.getPassword());

            OutputStream out = new ByteArrayOutputStream();
            HttpPost post = new HttpPost(serviceURL, params, out);
            post.run();

            Assert.assertNull(post.getThrowable());
            Assert.assertEquals(200, post.getResponseCode());

            // verify the token content
            String token = out.toString();

            SSOCookieManager ssoCookieManager = new SSOCookieManager();
            final SignedToken cookieToken = ssoCookieManager.parse(token);

            Assert.assertNotNull("Should have domains.", cookieToken.getDomains());

            log.info("output string: " + token);

            final Set<Principal> principals = cookieToken.getIdentityPrincipals();

            Assert.assertNotNull("Should have expiry date.", cookieToken.getExpiryTime());
            Assert.assertFalse("Should have domains.", cookieToken.getDomains().isEmpty());
            Assert.assertEquals("User should be ", pa.getUserName(), cookieToken.getUser().getName());
            Assert.assertFalse("Should have an X500 principal.",
                              getPrincipals(X500Principal.class, principals).isEmpty());
            Assert.assertFalse("Should have a Numeric principal.",
                               getPrincipals(NumericPrincipal.class, principals).isEmpty());
            Assert.assertEquals("Should have cadc canfar scope.", URI.create("sso:cadc+canfar"),
                                cookieToken.getScope());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
//            Assert.fail("unexpected exception: " + unexpected);
            throw unexpected;
        }
    }

    /**
     * Test that login with a missing userid will fail.
     */
    @Test
    public void testLoginMissingUserID()
    {
        try
        {
            HashMap<String, Object> params = new HashMap<>();
            params.put("username", "");
            params.put("password", "qS1U42Y");

            OutputStream out = new ByteArrayOutputStream();
            HttpPost post = new HttpPost(serviceURL, params, out);
            post.run();
            Assert.assertEquals(400, post.getResponseCode());
            Assert.assertNotNull(post.getThrowable());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    /**
     * Test that login with an invalid userid will fail.
     */
    @Test
    public void testLoginInvalidUserID()
    {
        try
        {
            HashMap<String, Object> params = new HashMap<>();
            params.put("username", "noSuchUser");
            params.put("password", "qS1U42Y");

            OutputStream out = new ByteArrayOutputStream();
            HttpPost post = new HttpPost(serviceURL, params, out);
            post.run();
            Assert.assertEquals(401, post.getResponseCode());
            Assert.assertNotNull(post.getThrowable());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    /**
     * Test that login with a missing password will fail.
     */
    @Test
    public void testLoginMissingPassword()
    {
        try
        {
            PasswordAuthentication pa = ConfigUsers.getInstance().getPasswordAuthUser();
            HashMap<String, Object> params = new HashMap<>();
            params.put("username", pa.getUserName());
            params.put("password", "");

            OutputStream out = new ByteArrayOutputStream();
            HttpPost post = new HttpPost(serviceURL, params, out);
            post.run();
            Assert.assertEquals(400, post.getResponseCode());
            Assert.assertNotNull(post.getThrowable());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    /**
     * Test that login with an invalid password will fail.
     */
    @Test
    public void testLoginInvalidPassword()
    {
        try
        {
            PasswordAuthentication pa = ConfigUsers.getInstance().getPasswordAuthUser();
            HashMap<String, Object> params = new HashMap<>();
            params.put("username", pa.getUserName());
            params.put("password", "badpasswd");

            OutputStream out = new ByteArrayOutputStream();
            HttpPost post = new HttpPost(serviceURL, params, out);
            post.run();
            Assert.assertEquals(401, post.getResponseCode());
            Assert.assertNotNull(post.getThrowable());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }


    @Test
    public void testLoginCookie() throws Exception {

        String currentAuthenticatorClass = System.getProperty(IdentityManager.class.getName());
        System.setProperty(IdentityManager.class.getName(), TestIdentityManagerImpl.class.getName());
        log.info("current authenticator class: " + currentAuthenticatorClass + ". Using class: " + TestIdentityManagerImpl.class.getName());

        try {
            authSubject = AuthenticationUtil.getSubject(new PrincipalExtractor()
            {
                public Set<Principal> cookiePrincipals = null;
                private SignedToken cookieToken;
                private String loginToken;
                public X509CertificateChain getCertificateChain() { return null; }
                private String domain = "";

                public SignedToken getDelegationToken()
                {
                    return null;
                }

                protected void getCookieTokens() {
                    PasswordAuthentication pa = ConfigUsers.getInstance().getPasswordAuthUser();
                    Map<String,Object> callparams = new TreeMap<String,Object>();
                    callparams = new HashMap<String, Object>();
                    callparams.put("username", pa.getUserName());
                    callparams.put("password", pa.getPassword());

                    log.debug("pwd: *****");
                    log.debug("username: " + pa.getUserName());

                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    HttpPost post = new HttpPost(serviceURL, callparams, out);
                    post.run();

                    Assert.assertNull(post.getThrowable());
                    log.debug("login post response code: " + post.getResponseCode());
                    Assert.assertEquals(200, post.getResponseCode());

                    if (post.getThrowable() != null)
                        throw new RuntimeException("login failed: " + post.getResponseCode(), post.getThrowable());
                    loginToken = out.toString();
                    log.debug("token: " + loginToken);

                    CookiePrincipal cookiePrincipal = new CookiePrincipal(SSOCookieManager.DEFAULT_SSO_COOKIE_NAME, loginToken);
                    cookiePrincipals = new HashSet<Principal>(Arrays.asList(cookiePrincipal));
                    domain = serviceURL.getHost();
                }

                public Date getExpirationDate()
                {
                    final Calendar cal = Calendar.getInstance(DateUtil.UTC);
                    cal.add(Calendar.HOUR, SSO_COOKIE_LIFETIME_HOURS);
                    return cal.getTime();
                }

                public static final int SSO_COOKIE_LIFETIME_HOURS = 2 * 24; // in hours

                public Set<Principal> getPrincipals()
                {
                    if (cookiePrincipals == null) {
                        getCookieTokens();
                    }
                    return cookiePrincipals;
                }

                public Set<Principal> getExpectedPrincipals() {
                    return cookiePrincipals;
                }
            });

            System.clearProperty(IdentityManager.class.getName());

            RegistryClient regClient = new RegistryClient();

            URL dataServiceURL = regClient.getServiceURL(serviceURI, Standards.UMS_WHOAMI_01, AuthMethod.COOKIE);
            log.debug("whoami service url: " + dataServiceURL);

            ByteArrayOutputStream whoamiout = new ByteArrayOutputStream(1024);
            HttpDownload httpGet = new HttpDownload(dataServiceURL, whoamiout);
            httpGet.setFollowRedirects(true);
            Subject.doAs(authSubject, new RunnableAction(httpGet));
            log.debug("auth subject principals: " + authSubject.getPrincipals().toString());
            assertNull("GET returned errors", httpGet.getThrowable());

            assertEquals("Wrong response code", 200, httpGet.getResponseCode());

            // Check content of whoami return
            UserReader userReader = new UserReader();
            User whoamiUser = userReader.read(new String(whoamiout.toByteArray()));

            // Check identities match (but cookie principal won't be in whoami)
            Set<CookiePrincipal> cookiePrincipals = authSubject.getPrincipals(CookiePrincipal.class);
            authSubject.getPrincipals().removeAll(cookiePrincipals);
            Set<Principal> whoamiPrin = whoamiUser.getIdentities();
            log.debug("whoami principals: " + whoamiPrin.toString());
            Assert.assertTrue("principal sets not equal", whoamiPrin.equals(authSubject.getPrincipals()));


        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            throw unexpected;
        } finally  {
            System.clearProperty(IdentityManager.class.getName());
        }
    }
}
