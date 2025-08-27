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
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PrivilegedExceptionAction;
import java.util.UUID;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.HttpUpload;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;

public abstract class AbstractUserIntTest
{
    private static final Logger log = Logger.getLogger(AbstractUserIntTest.class);

    static String userServiceUrl;
    static String userAnonServiceUrl;
    static String userReqServiceUrl;
    static String userReqAnonServiceUrl;
    static Subject user1;
    static Subject user2;
    static Subject opsSubject;

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        Log4jInit.setLevel("org.opencadc.ac", Level.INFO);
        Log4jInit.setLevel("org.opencadc.reg", Level.INFO);

        RegistryClient regClient = new RegistryClient();

        URI umsServiceURI = new URI("ivo://opencadc.org/gms");

        URL userServiceURL = regClient
            .getServiceURL(umsServiceURI, Standards.UMS_USERS_01, AuthMethod.CERT);
        log.info("userServiceUrl: " + userServiceUrl);

        userServiceUrl = userServiceURL.toExternalForm();


        URL userAnonServiceURL = new URL("http", userServiceURL.getHost(), userServiceURL.getFile());
        userAnonServiceUrl = userAnonServiceURL.toExternalForm();
        log.info("userAnonServiceUrl: " + userAnonServiceUrl);

        userReqServiceUrl = regClient
            .getServiceURL(umsServiceURI, Standards.UMS_REQS_01, AuthMethod.CERT).toString();
        log.info("userReqServiceUrl: " + userReqServiceUrl);

        userReqAnonServiceUrl = regClient
            .getServiceURL(umsServiceURI, Standards.UMS_REQS_01, AuthMethod.ANON).toString();
        log.info("userReqAnonServiceUrl: " + userReqAnonServiceUrl);

        user1 = SSLUtil.createSubject(FileUtil.getFileFromResource("user1.pem", AbstractUserIntTest.class));
        user2 = SSLUtil.createSubject(FileUtil.getFileFromResource("user2.pem", AbstractUserIntTest.class));
        opsSubject = SSLUtil.createSubject(FileUtil.getFileFromResource("ops.pem", AbstractUserIntTest.class));
    }

    abstract String writeUserRequest(final UserRequest userRequest)
        throws IOException, WriterException;

    abstract User readUser(final String userString)
        throws IOException, ReaderException, URISyntaxException;

    abstract String writeUser(final User user)
        throws IOException, WriterException;

    abstract String getContentType();

    @Test
    public void putUserRequest() throws Exception
    {
        HttpPrincipal httpPrincipal = new HttpPrincipal(createUsername());
        User user = new User();
        user.getIdentities().add(httpPrincipal);
        PersonalDetails pd = new PersonalDetails("test", "user");
        pd.email = user.getHttpPrincipal().getName() + "@canada.ca";
        user.personalDetails = pd;
        UserRequest userRequest = new UserRequest(user, "12345678".toCharArray());

        String userString = writeUserRequest(userRequest);
        InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));

        HttpUpload httpUpload = new HttpUpload(in, new URL(userReqAnonServiceUrl));
        httpUpload.setRequestProperty("Accept", getContentType());
        httpUpload.run();

        assertEquals("Wrong response code", 201, httpUpload.getResponseCode());
    }

//    @Test
    public void putUserRequestAlreadyExists() throws Exception
    {
        HttpPrincipal httpPrincipal = new HttpPrincipal("user1");
        User user = new User();
        user.getIdentities().add(httpPrincipal);
        user.personalDetails = new PersonalDetails("test", "user");
        user.personalDetails.email = "email";
        UserRequest userRequest = new UserRequest(user, "12345678".toCharArray());
        String userString = writeUserRequest(userRequest);
        InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));

        HttpUpload httpUpload = new HttpUpload(in, new URL(userReqAnonServiceUrl));
        httpUpload.setRequestProperty("Accept", getContentType());
        httpUpload.run();

        assertEquals("Wrong response code", 409, httpUpload.getResponseCode());
    }

//    @Test
    public void putInvalidUserRequest() throws Exception
    {
        HttpPrincipal httpPrincipal = new HttpPrincipal("FOO");
        User user = new User();
        user.getIdentities().add(httpPrincipal);
        user.personalDetails = new PersonalDetails("test", "user");
        UserRequest userRequest =
            new UserRequest(user, "123456".toCharArray());

        // replace userID with null
        String userString = writeUserRequest(userRequest);
        userString = userString.replaceFirst("FOO", "");
        InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));

        HttpUpload httpUpload = new HttpUpload(in, new URL(userReqAnonServiceUrl));
        httpUpload.setRequestProperty("Accept", getContentType());
        httpUpload.run();

        assertEquals("Wrong response code", 400, httpUpload.getResponseCode());
    }

//    @Test
    public void putUserNotAsPrivilegedUser() throws Exception
    {
        final String username = createUsername();
        X500Principal x500Principal = new X500Principal("cn=" + username + ",OU=cadc,O=hia,C=ca");
        final User user = new User();
        user.getIdentities().add(x500Principal);
        user.personalDetails = new PersonalDetails("test", "user");
        user.personalDetails.email = username + "@canada.ca";

        Subject.doAs(user1, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run() throws Exception
            {
                String userString = writeUser(user);
                InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));

                HttpUpload httpUpload = new HttpUpload(in, new URL(userServiceUrl));
                httpUpload.setRequestProperty("Accept", getContentType());
                httpUpload.run();

                assertEquals("Wrong response code", 403, httpUpload.getResponseCode());

                return null;
            }
        });
    }

//    @Test
    public void putInvalidUser() throws Exception
    {
        // Missing X500Principal
        final String username = createUsername();
        HttpPrincipal httpPrincipal = new HttpPrincipal(username);
        final User user = new User();
        user.getIdentities().add(httpPrincipal);
        user.personalDetails = new PersonalDetails("test", "user");
        user.personalDetails.email = username + "@canada.ca";

        Subject.doAs(opsSubject, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run() throws Exception
            {
                String userString = writeUser(user);
                InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));

                HttpUpload httpUpload = new HttpUpload(in, new URL(userServiceUrl));
                httpUpload.setRequestProperty("Accept", getContentType());
                httpUpload.run();

                assertEquals("Wrong response code", 400, httpUpload.getResponseCode());

                return null;
            }
        });
    }

//    @Test
    public void putUser() throws Exception
    {
        final String username = createUsername();
        X500Principal x500Principal = new X500Principal("cn=" + username + ",OU=cadc,O=hia,C=ca");
        final User user = new User();
        user.getIdentities().add(x500Principal);
        user.personalDetails = new PersonalDetails("test", "user");
        user.personalDetails.email = username + "@canada.ca";

        Subject.doAs(opsSubject, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run() throws Exception
            {
                String userString = writeUser(user);
                InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));

                HttpUpload httpUpload = new HttpUpload(in, new URL(userServiceUrl));
                httpUpload.setRequestProperty("Accept", getContentType());
                httpUpload.run();

                assertEquals("Wrong response code", 201, httpUpload.getResponseCode());

                return null;
            }
        });
    }

//    @Test
    public void getUser() throws Exception
    {
        Subject.doAs(user1, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run() throws Exception
            {
                URL userURL = new URL(userServiceUrl + "/user1?idType=http");
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);

                HttpDownload httpGet = new HttpDownload(userURL, out);
                httpGet.setRequestProperty("Accept", getContentType());
                httpGet.run();

                assertEquals("Wrong response code", 200, httpGet.getResponseCode());
                assertNull("GET returned errors", httpGet.getThrowable());

                out.close();
                byte[] bytes = out.toByteArray();

                User actual = readUser(new String(bytes));
                assertNotNull(actual);
                return null;
            }
        });
    }

//    @Test
    public void getUserAsAnon() throws Exception
    {
        URL userURL = new URL(userAnonServiceUrl + "/user1?idType=http");
        ByteArrayOutputStream out = new ByteArrayOutputStream(1024);

        HttpDownload httpGet = new HttpDownload(userURL, out);
        httpGet.setRequestProperty("Accept", getContentType());
        httpGet.run();

        assertEquals("Wrong response code", 403, httpGet.getResponseCode());
    }

//    @Test
    public void getUserAsSomeoneElse() throws Exception
    {
        Subject.doAs(user2, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run() throws Exception
            {
                URL userURL = new URL(userServiceUrl + "/user1?idType=http");
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);

                HttpDownload httpGet = new HttpDownload(userURL, out);
                httpGet.setRequestProperty("Accept", getContentType());
                httpGet.run();

                assertEquals("Wrong response code", 403, httpGet.getResponseCode());
                return null;
            }
        });
    }

    // currently only support a user getting self so no good way to test Not Found
    // without an external certificate
    //@Test
    public void getUserNotFound() throws Exception
    {
        Subject.doAs(user2, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run()
                throws Exception
            {
                URL userURL = new URL(userServiceUrl + "/foo?idType=http");
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);

                HttpDownload httpGet = new HttpDownload(userURL, out);
                httpGet.setRequestProperty("Accept", getContentType());
                httpGet.run();

                assertEquals("Wrong response code", 404, httpGet.getResponseCode());
                return null;
            }
        });
    }

//    @Test
    public void updateUser() throws Exception
    {
        Subject.doAs(user1, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run()
                throws Exception
            {
                // Get a user
                URL userURL = new URL(userServiceUrl + "/user1?idType=http");
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);

                HttpDownload httpGet = new HttpDownload(userURL, out);
                httpGet.setRequestProperty("Accept", getContentType());
                httpGet.run();

                assertEquals("Wrong response code", 200, httpGet.getResponseCode());
                assertNull("GET returned errors", httpGet.getThrowable());

                out.close();
                byte[] bytes = out.toByteArray();

                User expectedUser = readUser(new String(bytes));
                assertNotNull(expectedUser);

                // Update the user's email
                PersonalDetails expectedPD = expectedUser.personalDetails;
                expectedPD.email = UUID.randomUUID() + "@nrc.ca";

                // Update the user
                String userString = writeUser(expectedUser);
                HttpPost httpPost = new HttpPost(new URL(userServiceUrl + "/user1"),
                    userString, getContentType(), false);
                httpPost.setRequestProperty("Accept", getContentType());
                httpPost.run();

                assertEquals("Wrong response code", 303, httpPost.getResponseCode());
                assertNull("GET returned errors", httpPost.getThrowable());

                // Follow the redirect
                URL redirectURL = httpPost.getRedirectURL();
                out = new ByteArrayOutputStream(1024);

                httpGet = new HttpDownload(redirectURL, out);
                httpGet.setRequestProperty("Accept", getContentType());
                httpGet.run();

                assertEquals("Wrong response code", 200, httpGet.getResponseCode());
                assertNull("GET returned errors", httpGet.getThrowable());

                out.close();
                bytes = out.toByteArray();

                User actualUser = readUser(new String(bytes));
                assertNotNull(actualUser);
                assertEquals((expectedUser.getHttpPrincipal().getName()), actualUser.getHttpPrincipal().getName());

                PersonalDetails actualPD = actualUser.personalDetails;
                assertEquals(expectedPD.email, actualPD.email);
                return null;
            }
        });
    }

//    @Test
    public void updateUserAsAnon() throws Exception
    {
        HttpPrincipal httpPrincipal = new HttpPrincipal("user1");
        User user = new User();
        user.getIdentities().add(httpPrincipal);
        String userString = writeUser(user);

        HttpPost httpPost = new HttpPost(new URL(userAnonServiceUrl + "/user1"),
                                         userString, getContentType(), false);
        httpPost.setRequestProperty("Accept", getContentType());
        httpPost.run();

        assertEquals("Wrong response code", 403, httpPost.getResponseCode());
    }

//    @Test
    public void updateUserAsSomeoneElse() throws Exception
    {
        Subject.doAs(user2, new PrivilegedExceptionAction<Object>()
        {
            @Override
            public Object run()
                throws Exception
            {
                HttpPrincipal httpPrincipal = new HttpPrincipal("user1");
                User user = new User();
                user.getIdentities().add(httpPrincipal);
                String userString = writeUser(user);

                HttpPost httpPost = new HttpPost(new URL(userServiceUrl + "/user1"),
                    userString, getContentType(), false);
                httpPost.setRequestProperty("Accept", getContentType());
                httpPost.run();

                assertEquals("Wrong response code", 403, httpPost.getResponseCode());
                return null;
            }
        });
    }

    private String createUsername()
    {
        return "ac_ws-int-test-user-" + System.currentTimeMillis();
    }

}
