/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2015.                            (c) 2015.
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
package ca.nrc.cadc.ac.server.web.users;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import java.util.UUID;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.json.JsonUserWriter;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.web.SyncOutput;
import ca.nrc.cadc.ac.xml.UserWriter;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.util.Log4jInit;

public class GetUserActionTest
{
    private static final Logger log = Logger.getLogger(GetUserActionTest.class);

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac.server", Level.INFO);
    }

    @Test
    public void writeUserXML() throws Exception
    {
        final SyncOutput mockSyncOut =
                createMock(SyncOutput.class);
        final UserPersistence mockUserPersistence =
                createMock(UserPersistence.class);
        final HttpPrincipal userID = new HttpPrincipal("CADCtest");

        final GetUserAction testSubject = new GetUserAction(userID, null);
        testSubject.userPersistence = mockUserPersistence;

        final User user = new User();
        user.getIdentities().add(userID);
        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockUserPersistence.getUser(userID)).andReturn(user).once();
        expect(mockSyncOut.getWriter()).andReturn(printWriter).once();
        mockSyncOut.setHeader("Content-Type", "text/xml");
        expectLastCall().once();

        replay(mockSyncOut, mockUserPersistence);

        testSubject.setSyncOut(mockSyncOut);
        testSubject.doAction();

        StringBuilder sb = new StringBuilder();
        UserWriter userWriter = new UserWriter();
        userWriter.write(user, sb);
        assertEquals(sb.toString(), writer.toString());

        verify(mockSyncOut, mockUserPersistence);
    }

    @Test
    public void writeUserWithDetailIdentity() throws Exception
    {
        final HttpPrincipal httpPrincipal = new HttpPrincipal("CADCtest");
        final NumericPrincipal numericPrincipal = new NumericPrincipal(UUID.randomUUID());
        final X500Principal x500Principal = new X500Principal("cn=foo,o=bar");

        Subject testUser = new Subject();
        testUser.getPrincipals().add(httpPrincipal);
        testUser.getPrincipals().add(numericPrincipal);
        testUser.getPrincipals().add(x500Principal);

        Subject.doAs(testUser, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {

                final HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
                final UserPersistence mockUserPersistence =
                    createMock(UserPersistence.class);


                final GetUserAction testSubject = new GetUserAction(httpPrincipal, "identity");
                testSubject.userPersistence = mockUserPersistence;

                final User expected = new User();
                expected.getIdentities().add(httpPrincipal);
                expected.getIdentities().add(numericPrincipal);
                expected.getIdentities().add(x500Principal);

                StringBuilder sb = new StringBuilder();
                UserWriter userWriter = new UserWriter();
                userWriter.write(expected, sb);
                String expectedUser = sb.toString();

                expected.personalDetails = new PersonalDetails("cadc", "test");
                expected.personalDetails.city = "city";

                expected.posixDetails= new PosixDetails("username", 123L, 456L, "/dev/null");

                final Writer writer = new StringWriter();
                final PrintWriter printWriter = new PrintWriter(writer);

                mockResponse.setHeader("Content-Type", "text/xml");
                expectLastCall().once();
                expect(mockResponse.getWriter()).andReturn(printWriter).once();

                replay(mockUserPersistence, mockResponse);

                SyncOutput syncOutput = new SyncOutput(mockResponse);
                testSubject.setSyncOut(syncOutput);
                testSubject.doAction();

                String actualUser = writer.toString();

                assertEquals(expectedUser, actualUser);

                verify(mockUserPersistence, mockResponse);

                return null;
            }
        });
    }

    @Test
    public void writeUserWithDetailDisplay() throws Exception
    {
        final HttpServletResponse mockResponse = createMock(HttpServletResponse.class);
        final UserPersistence mockUserPersistence =
            createMock(UserPersistence.class);
        final HttpPrincipal userID = new HttpPrincipal("CADCtest");

        final GetUserAction testSubject = new GetUserAction(userID, "display");
        testSubject.userPersistence = mockUserPersistence;

        final User expected = new User();
        expected.getIdentities().add(userID);

        expected.personalDetails = new PersonalDetails("cadc", "test");

        StringBuilder sb = new StringBuilder();
        UserWriter userWriter = new UserWriter();
        userWriter.write(expected, sb);
        String expectedUser = sb.toString();

        expected.personalDetails.city = "city";

        expected.getIdentities().add(new NumericPrincipal(UUID.randomUUID()));
        expected.getIdentities().add(new X500Principal("cn=foo,o=bar"));

        expected.posixDetails = new PosixDetails("username", 123L, 456L, "/dev/null");

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockUserPersistence.getUser(userID)).andReturn(expected).once();
        mockResponse.setHeader("Content-Type", "text/xml");
        expectLastCall().once();
        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        replay(mockUserPersistence, mockResponse);

        SyncOutput syncOutput = new SyncOutput(mockResponse);
        testSubject.setSyncOut(syncOutput);
        testSubject.doAction();

        String actualUser = writer.toString();

        log.debug("expected:\n" + expectedUser);
        log.debug("actual:\n" + actualUser);

        assertEquals(expectedUser, actualUser);

        verify(mockUserPersistence, mockResponse);
    }

    @Test
    public void writeAugmentedUser() throws Exception
    {
        final UserPersistence mockUserPersistence =
            createMock(UserPersistence.class);
        final HttpServletResponse mockResponse = createMock(HttpServletResponse.class);

        final HttpPrincipal userID = new HttpPrincipal("CADCtest");
        final GetUserAction testSubject = new GetUserAction(userID, null);
        testSubject.userPersistence = mockUserPersistence;
        testSubject.setAugmentUser(true);

        final NumericPrincipal numericPrincipal = new NumericPrincipal(UUID.randomUUID());
        final X500Principal x500Principal = new X500Principal("cn=foo,o=bar");

        final User expected = new User();
        expected.getIdentities().add(userID);
        expected.getIdentities().add(numericPrincipal);
        expected.getIdentities().add(x500Principal);

        StringBuilder sb = new StringBuilder();
        UserWriter userWriter = new UserWriter();
        userWriter.write(expected, sb);
        String expectedUser = sb.toString();

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockUserPersistence.getAugmentedUser(userID)).andReturn(expected).once();
        mockResponse.setHeader("Content-Type", "text/xml");
        expectLastCall().once();
        expect(mockResponse.getWriter()).andReturn(printWriter).once();

        replay(mockUserPersistence, mockResponse);

        SyncOutput syncOutput = new SyncOutput(mockResponse);
        testSubject.setSyncOut(syncOutput);
        testSubject.doAction();

        String actualUser = writer.toString();

        assertEquals(expectedUser, actualUser);

        verify(mockUserPersistence, mockResponse);
    }

    @Test
    public void writeUserJSON() throws Exception
    {
        final SyncOutput mockSyncOut =
                createMock(SyncOutput.class);
        final UserPersistence mockUserPersistence =
                createMock(UserPersistence.class);
        final HttpPrincipal userID = new HttpPrincipal("CADCtest");

        final GetUserAction testSubject = new GetUserAction(userID, null);
        testSubject.userPersistence = mockUserPersistence;

        testSubject.setAcceptedContentType(AbstractUserAction.JSON_CONTENT_TYPE);

        final User user = new User();
        user.getIdentities().add(userID);
        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockUserPersistence.getUser(userID)).andReturn(user).once();
        expect(mockSyncOut.getWriter()).andReturn(printWriter).once();
        mockSyncOut.setHeader("Content-Type", "application/json");
        expectLastCall().once();

        replay(mockSyncOut, mockUserPersistence);
        testSubject.setSyncOut(mockSyncOut);
        UserLogInfo logInfo = createMock(UserLogInfo.class);
        testSubject.setLogInfo(logInfo);
        testSubject.doAction();

        StringBuilder sb = new StringBuilder();
        JsonUserWriter userWriter = new JsonUserWriter();
        userWriter.write(user, sb);
        assertEquals(sb.toString(), writer.toString());

        verify(mockSyncOut, mockUserPersistence);
    }
}
