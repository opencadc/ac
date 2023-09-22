/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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

package org.opencadc.posix.mapper;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.InputStreamWrapper;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.Subject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public class UserManagementIntTest {
    private static final Logger log = Logger.getLogger(UserManagementIntTest.class);
    public static final URI POSIX_MAPPER_SERVICE_ID = URI.create("ivo://opencadc.org/posix-mapper");

    static {
        Log4jInit.setLevel("org.opencadc.posix.mapper", Level.DEBUG);
    }

    private static final String TEXT_PLAIN_CONTENT_PLAIN = "text/plain";
    private static final String TSV_CONTENT_PLAIN = "text/tab-separated-values";
    private static final URI USER_MAPPER_STANDARD_ID = URI.create("http://www.opencadc.org/std/posix#user-mapping-1.0");

    protected URL userMapperURL;
    protected Subject userSubject;

    public UserManagementIntTest() throws Exception {
        RegistryClient regClient = new RegistryClient();
        userMapperURL = regClient.getServiceURL(UserManagementIntTest.POSIX_MAPPER_SERVICE_ID,
                                                UserManagementIntTest.USER_MAPPER_STANDARD_ID, AuthMethod.TOKEN);
        log.info("User Mapping URL: " + userMapperURL);

        File bearerTokenFile = FileUtil.getFileFromResource("posix-mapper-test.token",
                                                            UserManagementIntTest.class);
        final String bearerToken = new String(Files.readAllBytes(bearerTokenFile.toPath()));
        userSubject = new Subject();
        userSubject.getPublicCredentials().add(
                new AuthorizationToken("bearer", bearerToken, List.of(NetUtil.getDomainName(userMapperURL))));
        log.debug("userSubject: " + userSubject);
    }

    final String randomUsername() {
        return RandomStringUtils.randomAlphabetic(4, 12);
    }

    @Test
    public void testNotAuthenticated() throws Exception {
        try {
            createUser(randomUsername());
            Assert.fail("Should throw NotAuthenticatedException");
        } catch (NotAuthenticatedException notAuthenticatedException) {
            // Good
        } catch (Throwable throwable) {
            throw new Exception(throwable.getMessage(), throwable);
        }
    }

    @Test
    public void testUserAdd() throws Exception {
        Subject.doAs(userSubject, (PrivilegedExceptionAction<Void>) () -> {
            final String username = randomUsername();
            try {
                final int uid = createUser(username);
                final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                getUsers(byteArrayOutputStream, UserManagementIntTest.TEXT_PLAIN_CONTENT_PLAIN);
                String output = byteArrayOutputStream.toString();
                Assert.assertTrue("Wrong output",
                                  output.contains(String.format("%s:x:%d:%d:::", username, uid, uid)));
                getUsers(byteArrayOutputStream, UserManagementIntTest.TSV_CONTENT_PLAIN);
                output = byteArrayOutputStream.toString();
                Assert.assertTrue("Wrong TSV output",
                                  output.contains(String.format("%s\t%d", username, uid)));
            } catch (Throwable throwable) {
                throw new Exception(throwable.getMessage(), throwable);
            }

            return null;
        });
    }

    private int createUser(final String username) throws Throwable {
        final Map<String, Object> payload = new HashMap<>();

        payload.put("username", username);

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final HttpPost httpPost = new HttpPost(userMapperURL, payload, byteArrayOutputStream);
        httpPost.run();

        if (httpPost.getThrowable() != null) {
            throw httpPost.getThrowable();
        }

        return Integer.parseInt(byteArrayOutputStream.toString());
    }

    private void getUsers(final OutputStream outputStream, final String contentType) throws Throwable {
        final InputStreamWrapper inputStreamWrapper = inputStream -> outputStream.write(inputStream.readAllBytes());
        final HttpGet httpGet = new HttpGet(userMapperURL, inputStreamWrapper);
        httpGet.setRequestProperty("accept", contentType);
        httpGet.run();

        if (httpGet.getThrowable() != null) {
            throw httpGet.getThrowable();
        }
    }
}
