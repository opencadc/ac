/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
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
package ca.nrc.cadc.ac.server.web.users;


import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.json.JsonUserListWriter;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.web.SyncOutput;
import ca.nrc.cadc.ac.xml.UserListWriter;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Level;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

/**
 * @author adriand
 */
public class GetUserListActionTest {
    @BeforeClass
    public static void setUpClass() {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass() {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testWriteUsersJSON() throws Exception {
        final SyncOutput mockSyncOut =
                createMock(SyncOutput.class);
        final UserPersistence mockUserPersistence =
                createMock(UserPersistence.class);
        List<User> expectedUsers = new ArrayList<User>();

        for (int i = 1; i <= 5; i++) {
            User user = new User();
            user.getIdentities().add(new HttpPrincipal("USER_" + i));
            PersonalDetails pd = new PersonalDetails("USER", Integer.toString(i));
            user.personalDetails = pd;
            expectedUsers.add(user);
        }

        final GetUserListAction testSubject = new GetUserListAction();
        testSubject.userPersistence = mockUserPersistence;

        testSubject.setAcceptedContentType(AbstractUserAction.JSON_CONTENT_TYPE);

        final Writer actualWriter = new StringWriter();
        final PrintWriter actualPrintWriter = new PrintWriter(actualWriter);

        expect(mockUserPersistence.getUsers()).andReturn(expectedUsers).once();
        expect(mockSyncOut.getWriter()).andReturn(actualPrintWriter).once();
        mockSyncOut.setHeader("Content-Type", "application/json");
        expectLastCall().once();

        replay(mockSyncOut, mockUserPersistence);
        testSubject.setSyncOut(mockSyncOut);
        UserLogInfo logInfo = createMock(UserLogInfo.class);
        testSubject.setLogInfo(logInfo);
        testSubject.doAction();

        final Writer expectedWriter = new StringWriter();
        final PrintWriter expectedPrintWriter = new PrintWriter(expectedWriter);
        JsonUserListWriter userListWriter = new JsonUserListWriter();
        userListWriter.write(expectedUsers, expectedPrintWriter);
        JSONAssert.assertEquals(expectedWriter.toString(), actualWriter.toString(), false);

        verify(mockSyncOut, mockUserPersistence);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testWriteUsersXML() throws Exception {
        final SyncOutput mockSyncOut =
                createMock(SyncOutput.class);
        final UserPersistence mockUserPersistence =
                createMock(UserPersistence.class);
        List<User> expectedUsers = new ArrayList<User>();

        for (int i = 1; i <= 5; i++) {
            User user = new User();
            user.getIdentities().add(new HttpPrincipal("USER_" + i));
            PersonalDetails pd = new PersonalDetails("USER", Integer.toString(i));
            user.personalDetails = pd;
            expectedUsers.add(user);
        }

        final GetUserListAction testSubject = new GetUserListAction();
        testSubject.userPersistence = mockUserPersistence;

        final Writer actualWriter = new StringWriter();
        final PrintWriter actualPrintWriter = new PrintWriter(actualWriter);

        expect(mockUserPersistence.getUsers()).andReturn(expectedUsers).once();
        expect(mockSyncOut.getWriter()).andReturn(actualPrintWriter).once();
        mockSyncOut.setHeader("Content-Type", "text/xml");
        expectLastCall().once();

        replay(mockSyncOut, mockUserPersistence);
        testSubject.setSyncOut(mockSyncOut);
        UserLogInfo logInfo = createMock(UserLogInfo.class);
        testSubject.setLogInfo(logInfo);
        testSubject.doAction();

        final Writer expectedWriter = new StringWriter();
        final PrintWriter expectedPrintWriter = new PrintWriter(expectedWriter);
        UserListWriter userListWriter = new UserListWriter();
        userListWriter.write(expectedUsers, expectedPrintWriter);
        assertEquals("Wrong XML", expectedWriter.toString(), actualWriter.toString());

        verify(mockSyncOut, mockUserPersistence);
    }
}
