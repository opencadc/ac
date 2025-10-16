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
import ca.nrc.cadc.ac.json.JsonUserReader;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.RunnableAction;
import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.NetrcFile;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Log4jInit;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.Subject;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ResetPasswordIntTest
{
    private static final Logger log = Logger.getLogger(ResetPasswordIntTest.class);
    private static final String WEAK_PASSWORD = "b7SP83c";

    static URL postServiceURL;
    static URL getServiceURL;

    Map<String, Object> params;
    private static String email;

    @BeforeClass
    public static void before()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.reg", Level.INFO);

        URI umsServiceURI = URI.create(ConfigUsers.AC_SERVICE_ID);

        RegistryClient regClient = new RegistryClient();
        postServiceURL = regClient
            .getServiceURL(umsServiceURI, Standards.UMS_RESETPASS_01, AuthMethod.CERT);
        getServiceURL = new URL(postServiceURL.toExternalForm() + "?emailAddress=");
        log.info("getServiceUrl: " + getServiceURL);
        log.info("postServiceUrl: " + postServiceURL);

        Assert.assertNotNull(getServiceURL);
        PasswordAuthentication pa = ConfigUsers.getInstance().getPasswordAuthUser();
        HashMap<String, Object> params = new HashMap<>();
        params.put("username", pa.getUserName());
        params.put("password", pa.getPassword());

        URL loginUrl = regClient
                .getServiceURL(URI.create(ConfigUsers.AC_SERVICE_ID), Standards.UMS_LOGIN_01, AuthMethod.ANON);
        ByteArrayOutputStream cookieStream = new ByteArrayOutputStream();
        HttpPost post = new HttpPost(loginUrl, params, cookieStream);
        post.run();
        Assert.assertNull(post.getThrowable());
        Assert.assertEquals(200, post.getResponseCode());
        String token = cookieStream.toString();
        log.info("SSO cookie: " + token);

        // now get the user details including the email address
        URL usersUrl = regClient
                .getServiceURL(URI.create(ConfigUsers.AC_SERVICE_ID), Standards.UMS_USERS_01, AuthMethod.COOKIE);
        Assert.assertNotNull(usersUrl);
        URL userURL = new URL(usersUrl.toString() + "/" + pa.getUserName() + "?idType=http");
        log.info("userURL: " + userURL);
        ByteArrayOutputStream userInfoStream = new ByteArrayOutputStream();
        HttpGet getUser = new HttpGet(userURL, userInfoStream);
        getUser.setRequestProperty("Accept", "application/json; charset=UTF-8");
        getUser.setRequestProperty("Cookie", SSOCookieManager.DEFAULT_SSO_COOKIE_NAME + "=" + token);
        getUser.run();
        Assert.assertNull(getUser.getThrowable());
        Assert.assertEquals(200, getUser.getResponseCode());
        String userInfo = userInfoStream.toString();
        log.debug("userInfo: " + userInfo);
        JsonUserReader reader = new JsonUserReader();
        User user = reader.read(new StringReader(userInfo));
        Assert.assertNotNull(user.personalDetails);
        email = user.personalDetails.email;
        log.debug(email);
        Assert.assertNotNull(email);
    }

    private void getDelegationToken(final ByteArrayOutputStream out) throws Exception
    {
        // as the priv user, get the scoped token for the user with the email address
        URL userGetServiceURL = new URL(getServiceURL.toString() + email);
        HttpGet get = new HttpGet(userGetServiceURL, out);
        Subject subject = ConfigUsers.getInstance().getPrivSubject();
        Subject.doAs(subject, new RunnableAction(get));

        Assert.assertNull(get.getThrowable());
        Assert.assertEquals(200, get.getResponseCode());

        // verify the token content
        log.debug("scoped token: " + out.toString());
    }

    @Test
    public void testResetPassword() throws Exception
    {
        // get the scoped token to be used to reset the password
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        getDelegationToken(out);
        String delToken = out.toString();
        log.debug("delegation token: " + delToken);
        URI umsServiceURI = URI.create(ConfigUsers.AC_SERVICE_ID);

        RegistryClient regClient = new RegistryClient();
        postServiceURL = regClient
                .getServiceURL(umsServiceURI, Standards.UMS_RESETPASS_01, AuthMethod.CERT);
        NetrcFile netrc = new NetrcFile();
        PasswordAuthentication pa = netrc.getCredentials(postServiceURL.getHost(), false);
        // put the new password into the parameters
        params = new HashMap<String, Object>();
        params.put("password", pa.getPassword());

        Assert.assertNotNull(postServiceURL);

        log.debug("Del token:" + delToken);
        HttpPost post = new HttpPost(postServiceURL, params, false);
        post.setRequestProperty(AuthenticationUtil.AUTHORIZATION_HEADER, delToken); // old "X-CADC-DelegationToken"\
        post.run();
        Assert.assertEquals(200, post.getResponseCode());
        Assert.assertNull(post.getThrowable());
    }
    
    @Test
    public void testResetPasswordTooWeak() throws Exception
    {
        // get the scoped token to be used to reset the password
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        getDelegationToken(out);
        String delToken = out.toString();

        // put the new password into the parameters
        params = new HashMap<String, Object>();
        params.put("password", WEAK_PASSWORD);

        Assert.assertNotNull(postServiceURL);

        HttpPost post = new HttpPost(postServiceURL, params, false);
        post.setRequestProperty(AuthenticationUtil.AUTHORIZATION_HEADER, delToken);
        post.run();
        Assert.assertEquals(400, post.getResponseCode());
    }

}
