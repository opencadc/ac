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


import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.auth.HttpPrincipal;
import org.apache.log4j.Level;

import org.json.JSONArray;

import ca.nrc.cadc.util.Log4jInit;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;

import static org.easymock.EasyMock.*;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import org.skyscreamer.jsonassert.JSONAssert;

/**
 *
 * @author adriand
 */
public class GetUsersActionTest
{
    @BeforeClass
    public static void setUpClass()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testWriteUsersJSON() throws Exception
    {
        final HttpServletResponse mockResponse =
                createMock(HttpServletResponse.class);
        final UserPersistence<HttpPrincipal> mockUserPersistence =
                createMock(UserPersistence.class);
        final Collection<String> userEntries = new ArrayList<String>();

        for (int i = 1; i <= 13; i++)
        {
            userEntries.add("USER_" + i);
        }

        final GetUsersAction testSubject = new GetUsersAction(null)
        {
            @Override
            UserPersistence<HttpPrincipal> getUserPersistence()
            {
                return mockUserPersistence;
            }
        };

        testSubject.setAcceptedContentType(UsersAction.JSON_CONTENT_TYPE);

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockUserPersistence.getUserNames()).andReturn(
                userEntries).once();
        expect(mockResponse.getWriter()).andReturn(printWriter).once();
        mockResponse.setContentType("application/json");
        expectLastCall().once();

        replay(mockResponse, mockUserPersistence);
        testSubject.doAction(null, mockResponse);

        final JSONArray expected =
                new JSONArray("['USER_1','USER_2','USER_3','USER_4','USER_5','USER_6','USER_7','USER_8','USER_9','USER_10','USER_11','USER_12','USER_13']");
        final JSONArray result = new JSONArray(writer.toString());

        JSONAssert.assertEquals(expected, result, true);
        verify(mockResponse, mockUserPersistence);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testWriteUsersXML() throws Exception
    {
        final HttpServletResponse mockResponse =
                createMock(HttpServletResponse.class);
        final UserPersistence<HttpPrincipal> mockUserPersistence =
                createMock(UserPersistence.class);
        final Collection<String> userEntries = new ArrayList<String>();

        for (int i = 1; i <= 13; i++)
        {
            userEntries.add("USER_" + i);
        }

        final GetUsersAction testSubject = new GetUsersAction(null)
        {
            @Override
            UserPersistence<HttpPrincipal> getUserPersistence()
            {
                return mockUserPersistence;
            }
        };

        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);

        expect(mockUserPersistence.getUserNames()).andReturn(
                userEntries).once();
        expect(mockResponse.getWriter()).andReturn(printWriter).once();
        mockResponse.setContentType("text/xml");
        expectLastCall().once();

        replay(mockResponse, mockUserPersistence);
        testSubject.doAction(null, mockResponse);

        final String expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
                                "<users>\r\n" +
                                "  <user>USER_1</user>\r\n" +
                                "  <user>USER_2</user>\r\n" +
                                "  <user>USER_3</user>\r\n" +
                                "  <user>USER_4</user>\r\n" +
                                "  <user>USER_5</user>\r\n" +
                                "  <user>USER_6</user>\r\n" +
                                "  <user>USER_7</user>\r\n" +
                                "  <user>USER_8</user>\r\n" +
                                "  <user>USER_9</user>\r\n" +
                                "  <user>USER_10</user>\r\n" +
                                "  <user>USER_11</user>\r\n" +
                                "  <user>USER_12</user>\r\n" +
                                "  <user>USER_13</user>\r\n" +
                                "</users>\r\n";
        final String result = writer.toString();

        assertEquals("Wrong XML", expected, result);
        verify(mockResponse, mockUserPersistence);
    }
}
