/**
 * ***********************************************************************
 * ******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 * *************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 * <p>
 * (c) 2014.                            (c) 2014.
 * Government of Canada                 Gouvernement du Canada
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits réservés
 * <p>
 * NRC disclaims any warranties,        Le CNRC dénie toute garantie
 * expressed, implied, or               énoncée, implicite ou légale,
 * statutory, of any kind with          de quelque nature que ce
 * respect to the software,             soit, concernant le logiciel,
 * including without limitation         y compris sans restriction
 * any warranty of merchantability      toute garantie de valeur
 * or fitness for a particular          marchande ou de pertinence
 * purpose. NRC shall not be            pour un usage particulier.
 * liable in any event for any          Le CNRC ne pourra en aucun cas
 * damages, whether direct or           être tenu responsable de tout
 * indirect, special or general,        dommage, direct ou indirect,
 * consequential or incidental,         particulier ou général,
 * arising from the use of the          accessoire ou fortuit, résultant
 * software.  Neither the name          de l'utilisation du logiciel. Ni
 * of the National Research             le nom du Conseil National de
 * Council of Canada nor the            Recherches du Canada ni les noms
 * names of its contributors may        de ses  participants ne peuvent
 * be used to endorse or promote        être utilisés pour approuver ou
 * products derived from this           promouvoir les produits dérivés
 * software without specific prior      de ce logiciel sans autorisation
 * written permission.                  préalable et particulière
 * par écrit.
 * <p>
 * This file is part of the             Ce fichier fait partie du projet
 * OpenCADC project.                    OpenCADC.
 * <p>
 * OpenCADC is free software:           OpenCADC est un logiciel libre ;
 * you can redistribute it and/or       vous pouvez le redistribuer ou le
 * modify it under the terms of         modifier suivant les termes de
 * the GNU Affero General Public        la “GNU Affero General Public
 * License as published by the          License” telle que publiée
 * Free Software Foundation,            par la Free Software Foundation
 * either version 3 of the              : soit la version 3 de cette
 * License, or (at your option)         licence, soit (à votre gré)
 * any later version.                   toute version ultérieure.
 * <p>
 * OpenCADC is distributed in the       OpenCADC est distribué
 * hope that it will be useful,         dans l’espoir qu’il vous
 * but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 * without even the implied             GARANTIE : sans même la garantie
 * warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 * or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 * PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 * General Public License for           Générale Publique GNU Affero
 * more details.                        pour plus de détails.
 * <p>
 * You should have received             Vous devriez avoir reçu une
 * a copy of the GNU Affero             copie de la Licence Générale
 * General Public License along         Publique GNU Affero avec
 * with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 * <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 * <http://www.gnu.org/licenses/>.
 * <p>
 * ***********************************************************************
 */

package ca.nrc.cadc.ac.server.web.groups;

import ca.nrc.cadc.util.Log4jInit;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

public class GroupActionFactoryTest {
    private final static Logger log = Logger.getLogger(GroupActionFactoryTest.class);

    public GroupActionFactoryTest() {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @Test
    public void testCreateAddGroupMemberAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName/groupMembers/groupToAdd");
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpPutFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof AddGroupMemberAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateAddUserMemberAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName/userMembers/userToAdd");
            EasyMock.expect(request.getParameter("idType")).andReturn("x509");
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpPutFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof AddUserMemberAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateCreateGroupAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("");
            EasyMock.expect(request.getInputStream()).andReturn(null);
            EasyMock.replay(request);

            AbstractGroupAction action = GroupsActionFactory.httpPutFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof CreateGroupAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateDeleteGroupAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName");
            EasyMock.replay(request);

            AbstractGroupAction action = GroupsActionFactory.httpDeleteFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof DeleteGroupAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateGetGroupAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName");
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpGetFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof GetGroupAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateGetGroupNamesAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("");
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpGetFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof GetGroupNamesAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateModifyGroupAction() {
        try {
            StringBuffer sb = new StringBuffer();
            sb.append("http://localhost:80/ac/groups/foo");

            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName");
            EasyMock.expect(request.getRequestURL()).andReturn(sb);
            EasyMock.expect(request.getContextPath()).andReturn("");
            EasyMock.expect(request.getServletPath()).andReturn("");
            EasyMock.expect(request.getInputStream()).andReturn(null);
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpPostFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof ModifyGroupAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateRemoveGroupMemberAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName/groupMembers/groupToRenove");
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpDeleteFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof RemoveGroupMemberAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testCreateRemoveUserMemberAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("groupName/userMembers/userToRemove");
            EasyMock.expect(request.getParameter("idType")).andReturn("x509");
            EasyMock.replay(request);
            AbstractGroupAction action = GroupsActionFactory.httpDeleteFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof RemoveUserMemberAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    /*
        {
            TestRequest[] testRequests =
            {
                new TestRequest("", "POST"),
                new TestRequest("", "DELETE"),
                new TestRequest("", "HEAD"),
                new TestRequest("groupName/groupMembers", "GET"),
                new TestRequest("groupName/groupMembers", "POST"),
                new TestRequest("groupName/groupMembers", "PUT"),
                new TestRequest("groupName/groupMembers", "DELETE"),
                new TestRequest("groupName/groupMembers", "HEAD"),
                new TestRequest("groupName/misspelled/id", "GET"),
                new TestRequest("groupName/groupMembers/groupMemberName", "GET"),
                new TestRequest("groupName/groupMembers/groupMemberName", "POST"),
                new TestRequest("groupName/groupMembers/groupMemberName", "HEAD"),
                new TestRequest("groupName/userMembers/userMemberName", "GET"),
                new TestRequest("groupName/userMembers/userMemberName", "POST"),
                new TestRequest("groupName/userMembers/userMemberName", "HEAD"),
                new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments", "GET"),
                new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments", "POST"),
                new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments", "PUT"),
                new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments", "HEAD"),
                new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments", "DELETE"),
            };
            */

    @Test
    public void testBadGetRequests() {
        try {
            TestRequest[] testRequests =
                    {
                            new TestRequest("groupName/groupMembers"),
                            new TestRequest("groupName/misspelled/id"),
                            new TestRequest("groupName/groupMembers/groupMemberName"),
                            new TestRequest("groupName/userMembers/userMemberName"),
                            new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments")
                    };

            for (TestRequest testRequest : testRequests) {

                log.debug("Testing: " + testRequest);

                HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
                EasyMock.expect(request.getPathInfo()).andReturn(testRequest.path);
                if (testRequest.paramName != null) {
                    EasyMock.expect(request.getParameter(testRequest.paramName)).andReturn(testRequest.paramValue);
                }
                EasyMock.replay(request);
                try {
                    GroupsActionFactory.httpGetFactory().createAction(request);
                    Assert.fail("Should have been a bad request: on " + testRequest.path);
                } catch (IllegalArgumentException e) {
                    // expected
                }
                EasyMock.verify(request);
            }
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testBadPutRequests() {
        try {
            TestRequest[] testRequests =
                    {
                            new TestRequest("groupName/groupMembers"),
                            new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments")
                    };

            for (TestRequest testRequest : testRequests) {

                log.debug("Testing: " + testRequest);

                HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
                EasyMock.expect(request.getPathInfo()).andReturn(testRequest.path);
                if (testRequest.paramName != null) {
                    EasyMock.expect(request.getParameter(testRequest.paramName)).andReturn(testRequest.paramValue);
                }
                EasyMock.replay(request);
                try {
                    GroupsActionFactory.httpPutFactory().createAction(request);
                    Assert.fail("Should have been a bad request: on " + testRequest.path);
                } catch (IllegalArgumentException e) {
                    // expected
                }
                EasyMock.verify(request);
            }
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testBadPostRequests() {
        try {
            TestRequest[] testRequests =
                    {
                            new TestRequest(""),
                            new TestRequest("groupName/groupMembers"),
                            new TestRequest("groupName/groupMembers/groupMemberName"),
                            new TestRequest("groupName/userMembers/userMemberName"),
                            new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments")
                    };

            for (TestRequest testRequest : testRequests) {

                log.debug("Testing: " + testRequest);

                HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
                EasyMock.expect(request.getPathInfo()).andReturn(testRequest.path);
                if (testRequest.paramName != null) {
                    EasyMock.expect(request.getParameter(testRequest.paramName)).andReturn(testRequest.paramValue);
                }
                EasyMock.replay(request);
                try {
                    GroupsActionFactory.httpPostFactory().createAction(request);
                    Assert.fail("Should have been a bad request: on " + testRequest.path);
                } catch (IllegalArgumentException e) {
                    // expected
                }
                EasyMock.verify(request);
            }
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testBadDeleteRequests() {
        try {
            TestRequest[] testRequests =
                    {
                            new TestRequest(""),
                            new TestRequest("groupName/groupMembers"),
                            new TestRequest("groupName/groupMembers/groupMemberName/tooManySegments"),
                    };

            for (TestRequest testRequest : testRequests) {

                log.debug("Testing: " + testRequest);

                HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
                EasyMock.expect(request.getPathInfo()).andReturn(testRequest.path);
                if (testRequest.paramName != null) {
                    EasyMock.expect(request.getParameter(testRequest.paramName)).andReturn(testRequest.paramValue);
                }
                EasyMock.replay(request);
                try {
                    GroupsActionFactory.httpDeleteFactory().createAction(request);
                    Assert.fail("Should have been a bad request: on " + testRequest.path);
                } catch (IllegalArgumentException e) {
                    // expected
                }
                EasyMock.verify(request);
            }
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    private class TestRequest {
        public String path;
        public String paramName;
        public String paramValue;

        public TestRequest(String path) {
            this(path, null, null);
        }

        public TestRequest(String path, String paramName, String paramValue) {
            this.path = path;
            this.paramName = paramName;
            this.paramValue = paramValue;
        }

        @Override
        public String toString() {
            return "paht " + path +
                    ((paramName == null) ? "" : "?" + paramName + "=" + paramValue);
        }

    }

}
