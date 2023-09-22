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
import ca.nrc.cadc.net.InputStreamWrapper;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.reg.Standards;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.security.PrivilegedExceptionAction;
import java.util.List;

public class UserManagementIntTest {
    private static final Logger log = Logger.getLogger(UserManagementIntTest.class);
    public static final URI POSIX_MAPPER_SERVICE_ID = URI.create("ivo://opencadc.org/posix-mapper");

    static {
        Log4jInit.setLevel("org.opencadc.posix.mapper", Level.DEBUG);
    }

    private static final String TEXT_PLAIN_CONTENT_TYPE = "text/plain";
    private static final String TSV_CONTENT_TYPE = "text/tab-separated-values";

    protected URL userMapperURL;
    protected Subject userSubject;

    public UserManagementIntTest() throws Exception {
        RegistryClient regClient = new RegistryClient();
        userMapperURL = regClient.getServiceURL(UserManagementIntTest.POSIX_MAPPER_SERVICE_ID,
                                                Standards.POSIX_USERMAP, AuthMethod.TOKEN);
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
            final OutputStream outputStream = new ByteArrayOutputStream();
            getUsers(outputStream, UserManagementIntTest.TEXT_PLAIN_CONTENT_TYPE, new String[0]);
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
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                getUsers(byteArrayOutputStream, UserManagementIntTest.TEXT_PLAIN_CONTENT_TYPE, new String[]{username});
                String output = byteArrayOutputStream.toString();
                final int uid = Integer.parseInt(output.trim().split(":")[2]);

                Assert.assertTrue("Wrong output",
                                  output.contains(String.format("%s:x:%d:%d:::", username, uid, uid)));
                byteArrayOutputStream = new ByteArrayOutputStream();
                getUsers(byteArrayOutputStream, UserManagementIntTest.TSV_CONTENT_TYPE, new String[]{username});
                output = byteArrayOutputStream.toString();
                Assert.assertTrue("Wrong TSV output",
                                  output.contains(String.format("%s\t%d", username, uid)));
            } catch (Throwable throwable) {
                throw new Exception(throwable.getMessage(), throwable);
            }

            return null;
        });
    }

    private void getUsers(final OutputStream outputStream, final String contentType, final String[] usernames)
            throws Throwable {
        final InputStreamWrapper inputStreamWrapper = inputStream -> outputStream.write(inputStream.readAllBytes());
        final StringBuilder urlBuilder = new StringBuilder(userMapperURL.toString());

        if (usernames.length > 0) {
            urlBuilder.append("?");
            urlBuilder.append("username=");
            urlBuilder.append(String.join("&username=", usernames));
        }

        final HttpGet httpGet = new HttpGet(new URL(urlBuilder.toString()), inputStreamWrapper);
        httpGet.setRequestProperty("accept", contentType);
        httpGet.prepare();

        final byte[] buffer = new byte[8192];
        final InputStream inputStream = httpGet.getInputStream();
        int bytesRead = 0;
        while (((bytesRead = inputStream.read(buffer)) > 0)) {
            outputStream.write(buffer, 0, bytesRead);
        }
    }
}
