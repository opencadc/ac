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

package ca.nrc.cadc.ac.server.web.users;

import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;


public class UserActionFactoryTest {
    private final static Logger log = Logger.getLogger(UserActionFactoryTest.class);

    public UserActionFactoryTest() {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @BeforeClass
    public static void setUpClass() {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass() {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    @Test
    public void testCreateUserAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("");
            EasyMock.expect(request.getInputStream()).andReturn(null);
            EasyMock.replay(request);
            AbstractUserAction action = UserActionFactory.httpPutFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof CreateUserAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testDeleteUserAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("userName");
            EasyMock.expect(request.getParameter("iss")).andReturn(null);
            EasyMock.expect(request.getParameter("idType")).andReturn("sessionID");
            EasyMock.expect(request.getParameter("hard")).andReturn(null);
            EasyMock.replay(request);
            AbstractUserAction action = UserActionFactory.httpDeleteFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof DeleteUserAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testGetUserAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("userName");
            EasyMock.expect(request.getParameter("iss")).andReturn(null);
            EasyMock.expect(request.getParameter("idType")).andReturn("sessionID");
            EasyMock.expect(request.getParameter("detail")).andReturn("display");
            EasyMock.replay(request);
            AbstractUserAction action = UserActionFactory.httpGetFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof GetUserAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testGetUserNamesAction() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("");
            EasyMock.replay(request);
            AbstractUserAction action = UserActionFactory.httpGetFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof GetUserListAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testModifyUserAction() {
        try {
            StringBuffer sb = new StringBuffer();
            sb.append("http://localhost:80/ac/users/foo");

            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("CADCtest");
            EasyMock.expect(request.getInputStream()).andReturn(null);
            EasyMock.replay(request);
            AbstractUserAction action = UserActionFactory.httpPostFactory().createAction(request);
            EasyMock.verify(request);
            Assert.assertTrue("Wrong action", action instanceof ModifyUserAction);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testBadPostRequest() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("");
            EasyMock.replay(request);
            try {
                UserActionFactory.httpPostFactory().createAction(request);
                Assert.fail("Should have been a bad request");
            } catch (IllegalArgumentException e) {
                // expected
            }
            EasyMock.verify(request);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testBadDeleteRequest() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.expect(request.getPathInfo()).andReturn("");
            EasyMock.replay(request);
            try {
                UserActionFactory.httpDeleteFactory().createAction(request);
                Assert.fail("Should have been a bad request");
            } catch (IllegalArgumentException e) {
                // expected
            }
            EasyMock.verify(request);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }

    @Test
    public void testBadHeadRequest() {
        try {
            HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
            EasyMock.replay(request);
            try {
                UserActionFactory.httpHeadFactory().createAction(request);
                Assert.fail("Should have been a bad request");
            } catch (UnsupportedOperationException e) {
                // expected
            }
            EasyMock.verify(request);
        } catch (Throwable t) {
            log.error(t.getMessage(), t);
            Assert.fail("unexpected error: " + t.getMessage());
        }
    }


}
