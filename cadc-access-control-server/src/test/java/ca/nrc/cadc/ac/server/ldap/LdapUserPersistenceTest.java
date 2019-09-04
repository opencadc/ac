/**
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2018.                            (c) 2018.
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
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.db.StandaloneContextFactory;
import ca.nrc.cadc.util.Log4jInit;

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opencadc.gms.GroupURI;

public class LdapUserPersistenceTest extends AbstractLdapDAOTest
{	
    private static final Logger log = Logger.getLogger(LdapUserPersistenceTest.class);
    
    @BeforeClass
    public static void setUpClass()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        //System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass()
    {
        //System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }
    
    String createUsername()
    {
        return "CadcDaoTestUser-" + System.currentTimeMillis();
    }
    
    private void initJNDI() throws NamingException
    {
    	// disable checking the pool so that the non-test configuration won't be loaded
    	LdapPersistence.POOL_CHECK_INTERVAL_MILLESCONDS = -1;
    	
        StandaloneContextFactory.initJNDI();
        Context ctx = (new StandaloneContextFactory()).getInitialContext(null);
        
        Map<String,LdapConnectionPool> poolMap = new HashMap<String,LdapConnectionPool>(3);
        poolMap.put(LdapPersistence.POOL_READONLY, new LdapConnectionPool(
                config, config.getReadOnlyPool(), LdapPersistence.POOL_READONLY, true, true));
        poolMap.put(LdapPersistence.POOL_READWRITE, new LdapConnectionPool(
            config, config.getReadWritePool(), LdapPersistence.POOL_READWRITE, true, false));
        poolMap.put(LdapPersistence.POOL_UNBOUNDREADONLY, new LdapConnectionPool(
            config, config.getUnboundReadOnlyPool(), LdapPersistence.POOL_UNBOUNDREADONLY, false, true));

        ConnectionPools pools = new ConnectionPools(poolMap, config);

        String bindName = ConnectionPools.class.getName();
        ctx.bind(bindName, pools);
        log.debug("Bound connection pools with config " + config);
    }

    private void teardownJNDI() throws NamingException
    {
        Context ctx = (new StandaloneContextFactory()).getInitialContext(null);
        if (ctx != null)
            ctx.unbind(ConnectionPools.class.getName());
    }

    @Test
    public void testAddUserRequestWithExistingGroup() throws Exception
    {
        try {
            initJNDI();
            
            // prepare a userRequest
            final String username = createUsername();
            final HttpPrincipal userID = new HttpPrincipal(username);
    
            Subject subject = new Subject();
            subject.getPrincipals().add(userID);
    
            final User expectedUser = new User();
            final LdapUserPersistence userPersistence = new LdapUserPersistence();
            
            expectedUser.getIdentities().add(userID);
    
            expectedUser.personalDetails = new PersonalDetails("associated", "user");
            expectedUser.personalDetails.email = username + "@canada.ca";
                
            UserRequest userRequest = new UserRequest(expectedUser, "123456".toCharArray());
            Subject posixGroupOwnerSubject = new Subject();
            posixGroupOwnerSubject.getPrincipals().add(new HttpPrincipal("cadcops"));
    
            // add a group with the same username
            LdapGroupDAO groupDAO = getGroupDAO();
            Group existingGroup = new Group(new GroupURI("ivo://example.net/gms?" + username));
            setField(existingGroup, cadcDaoTest1_AugmentedUser, "owner");
            Group group = groupDAO.addGroup(existingGroup);
            
            try {
                // Adding a new user is done anonymously
                userPersistence.addUserRequest(userRequest, posixGroupOwnerSubject);
            } catch (RuntimeException rex) {
                if (rex.getMessage().contains("Group already exists")) {
                    // success
                } else {
                    fail("Caught unexpected expcetion: " + rex.getMessage());
                }
            } finally {
                // clean up
                if (group != null) {
                    groupDAO.deleteGroup(group.getID().getName());
                    try {
                        groupDAO.getGroup(group.getID().getName(), false);
                        fail("Failed to delete group");
                    } catch (GroupNotFoundException ex) {
                        // successful clean up
                    }
                }
            }
        } finally {
            teardownJNDI();
        }
    }
    
    @Test
    public void testAddAndApproveUserRequest() throws Exception
    {
        try {
            initJNDI();
            
            // add user using HttpPrincipal
            final String username = createUsername();
            final HttpPrincipal userID = new HttpPrincipal(username);
    
            Subject subject = new Subject();
            subject.getPrincipals().add(userID);
    
            final User expectedUser = new User();
            final LdapUserPersistence userPersistence = new LdapUserPersistence();
            
            expectedUser.getIdentities().add(userID);
    
            expectedUser.personalDetails = new PersonalDetails("associated", "user");
            expectedUser.personalDetails.email = username + "@canada.ca";
                
            UserRequest userRequest = new UserRequest(expectedUser, "123456".toCharArray());
            Subject posixGroupOwnerSubject = new Subject();
            posixGroupOwnerSubject.getPrincipals().add(new HttpPrincipal("cadcops"));
    
            // Adding a new user is done anonymously
            userPersistence.addUserRequest(userRequest, posixGroupOwnerSubject);
            boolean approved = false;
            try {
                Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                    public Object run() throws Exception {
                        return userPersistence.approveUserRequest(userID);
                    }
                });
                
                approved = true;                
                User actualUser = (User) Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                    public Object run() throws Exception {
                        return userPersistence.getUser(userID);
                    }
                });
                check(expectedUser, actualUser);
            } finally {
                if (approved) {
                    userPersistence.deleteUser(userID);
                    try {
                        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                            public Object run() throws Exception {
                                return userPersistence.getUser(userID);
                            }
                        });
                        fail("Failed to delete user.");
                    } catch (PrivilegedActionException ex) {
                        if (ex.getException() instanceof UserNotFoundException) {
                            // success, user was deleted
                        } else {
                            fail("Unexpected exception: " + ex.getException().getMessage());
                        }
                    }
                } else {
                    userPersistence.deleteUserRequest(userID);
                    try {
                        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                            public Object run() throws Exception {
                                return userPersistence.getUserRequest(userID);
                            }
                        });
                        fail("Failed to delete userRequest.");
                    } catch (PrivilegedActionException ex) {
                        if (ex.getException() instanceof UserNotFoundException) {
                            // success, userRequest was deleted
                        } else {
                            fail("Unexpected exception: " + ex.getException().getMessage());
                        }
                    }
                }
            }
        } finally {
            teardownJNDI();
        }
    }
    
    @Test
    public void testAddAndDeleteUserRequest() throws Exception
    {
        try {
            initJNDI();
            
            // add user using HttpPrincipal
            final String username = createUsername();
            final HttpPrincipal userID = new HttpPrincipal(username);
            
            Subject subject = new Subject();
            subject.getPrincipals().add(userID);
    
            final User expectedUser = new User();
            final LdapUserPersistence userPersistence = new LdapUserPersistence();
            
            expectedUser.getIdentities().add(userID);
    
            expectedUser.personalDetails = new PersonalDetails("associated", "user");
            expectedUser.personalDetails.email = username + "@canada.ca";
    
            UserRequest userRequest = new UserRequest(expectedUser, "123456".toCharArray());
            Subject posixGroupOwnerSubject = new Subject();
            posixGroupOwnerSubject.getPrincipals().add(new HttpPrincipal("cadcops"));
    
            // Adding a new user is done anonymously
            userPersistence.addUserRequest(userRequest, posixGroupOwnerSubject);
            boolean deleted = false;
            try {
                Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                    public Object run() throws Exception {
                        userPersistence.deleteUserRequest(userID);
                        return null;
                    }
                });
                
                try {
                    Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                        public Object run() throws Exception {
                            return userPersistence.approveUserRequest(userID);
                        }
                    });
                    fail("Failed to delete userRequest.");
                } catch (PrivilegedActionException ex) {
                    if (ex.getException() instanceof UserNotFoundException) {
                        // success, user was deleted
                        deleted = true;
                   } else {
                        fail("Unexpected exception: " + ex.getException().getMessage());
                    }
                }
            } finally {
                if (!deleted) {
                    userPersistence.deleteUserRequest(userID);
                }
            }
        } finally {
            teardownJNDI();
        }
    }

    private static void check(final User expected, final User actual)
    {
        if (expected.getID() != null)
        {
            assertEquals(expected, actual);
        }

        for (Principal p : expected.getIdentities())
        {
            log.debug("expected P: " + p.getName());
        }
        for (Principal p : actual.getIdentities())
        {
            log.debug("actual P: " + p.getName());
        }
        expected.isConsistent(actual);

        for( Principal princ1 : expected.getIdentities())
        {
            boolean found = false;
            for( Principal princ2 : actual.getIdentities())
            {
                if (princ2.getClass() == princ1.getClass())
                {
                    // NumericPrincipals are server generated, can't compare
                    if (princ2.getClass() != NumericPrincipal.class)
                    {
                        assertEquals(princ1, princ2);
                    }
                    found = true;
                }
            }
            assertTrue(princ1.getName(), found);
        }

        assertEquals(expected.personalDetails, actual.personalDetails);
        PersonalDetails pd1 = expected.personalDetails;
        PersonalDetails pd2 = actual.personalDetails;
        assertEquals(pd1, pd2);

        if (pd1 != null && pd2 != null)
        {
            assertEquals(pd1.getFirstName(), pd2.getFirstName());
            assertEquals(pd1.getLastName(), pd2.getLastName());
            assertEquals(pd1.address, pd2.address);
            assertEquals(pd1.city, pd2.city);
            assertEquals(pd1.country, pd2.country);
            assertEquals(pd1.email, pd2.email);
            assertEquals(pd1.institute, pd2.institute);
        }
        
        assertEquals(expected.posixDetails, actual.posixDetails);
        PosixDetails posixd1 = expected.posixDetails;
        PosixDetails posixd2 = actual.posixDetails;
        assertEquals(posixd1, posixd2);

        if (posixd1 != null && posixd2 != null)
        {
            assertEquals(posixd1.getUsername(), posixd2.getUsername());
            assertEquals(posixd1.getUid(), posixd2.getUid());
            assertEquals(posixd1.getGid(), posixd2.getGid());
            assertEquals(posixd1.getHomeDirectory(), posixd2.getHomeDirectory());
            assertEquals(posixd1.loginShell, posixd2.loginShell);
        }
    }
}
