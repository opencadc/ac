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

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.json.JsonUserWriter;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.web.SyncOutput;
import ca.nrc.cadc.auth.HttpPrincipal;
import org.easymock.EasyMock;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.Principal;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

public class ModifyUserActionTest
{
    @Test
    public void run() throws Exception
    {
        final HttpPrincipal httpPrincipal = new HttpPrincipal("CADCtest");
        User<Principal> expected = new User<Principal>(httpPrincipal);
        expected.getIdentities().add(httpPrincipal);
        final PersonalDetails pd = new PersonalDetails("CADC", "Test");
        pd.email = "CADC.Test@nrc-cnrc.gc.ca";
        expected.details.add(pd);

        final StringBuilder sb = new StringBuilder();
        final JsonUserWriter userWriter = new JsonUserWriter();
        userWriter.write(expected, sb);

        final byte[] input = sb.toString().getBytes();
        final InputStream inputStream = new ByteArrayInputStream(input);

        // Should match the JSON above, without the e-mail modification.
        Principal principal = new HttpPrincipal("CADCtest");
        final User<Principal> userObject =
                new User<Principal>(principal);
        userObject.getIdentities().add(principal);
        final PersonalDetails personalDetail =
                new PersonalDetails("CADC", "Test");
        personalDetail.email = "CADC.Test@nrc-cnrc.gc.ca";
        userObject.details.add(personalDetail);

        StringBuffer requestUrl = new StringBuffer();
        requestUrl.append("http://host/ac/users/CADCtest?idType=HTTP");

        HttpServletRequest mockRequest = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(mockRequest.getPathInfo()).andReturn("/CADCtest");
        EasyMock.expect(mockRequest.getRequestURL()).andReturn(requestUrl).once();
        EasyMock.expect(mockRequest.getContextPath()).andReturn("/ac").once();
        EasyMock.expect(mockRequest.getServletPath()).andReturn("/users").once();

        final SyncOutput mockSyncOut =
                createMock(SyncOutput.class);

        @SuppressWarnings("unchecked")
        final UserPersistence<Principal> mockUserPersistence =
                createMock(UserPersistence.class);

        expect(mockUserPersistence.modifyUser(userObject)).andReturn(
            userObject).once();

        mockSyncOut.setHeader("Location", requestUrl.toString());
        expectLastCall().once();

        mockSyncOut.setCode(303);
        expectLastCall().once();

        mockSyncOut.setHeader("Content-Type", "application/json");
        expectLastCall().once();

        replay(mockRequest, mockSyncOut, mockUserPersistence);

        final ModifyUserAction testSubject = new ModifyUserAction(inputStream, mockRequest);
        testSubject.userPersistence = mockUserPersistence;

        testSubject.setAcceptedContentType("application/json");
        testSubject.syncOut = mockSyncOut;
        UserLogInfo logInfo = createMock(UserLogInfo.class);
        testSubject.setLogInfo(logInfo);
        try
        {
            testSubject.doAction();
        }
        catch (Throwable t)
        {
            t.printStackTrace();
        }
        verify(mockRequest, mockSyncOut, mockUserPersistence);
    }
}
