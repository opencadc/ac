/*
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
 *  $Revision: 4 $
 *
 ************************************************************************
 */
package ca.nrc.cadc.ac.server.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import ca.nrc.cadc.auth.Authenticator;
import java.io.File;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;

import java.util.List;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;

public class LdapUserDAOTest extends AbstractLdapDAOTest
{

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

    private static final Logger log = Logger.getLogger(LdapUserDAOTest.class);

    String createUsername()
    {
        return "CadcDaoTestUser-" + System.currentTimeMillis();
    }

    @Test
    public void testAddIllegalUsername() throws Exception
    {
        // add user using HttpPrincipal
        final String username = "$" + createUsername();
        final HttpPrincipal userID = new HttpPrincipal(username);

        final User httpExpected = new User();
        httpExpected.getIdentities().add(userID);

        PersonalDetails pd = new PersonalDetails("foo", "bar");
        pd.email = username + "@canada.ca";
        httpExpected.personalDetails = pd;

        UserRequest userRequest = new UserRequest(httpExpected, "123456".toCharArray());

        try
        {
            final LdapUserDAO httpUserDAO = getUserDAO();
            httpUserDAO.addUserRequest(userRequest);
            fail("Illegal username " + username + " should've thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {}
    }

    @Test
    public void testAddUser() throws Exception
    {
        // add user using X500Principal
        String username = createUsername();
        final X500Principal userID = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");

        final User testUser = new User();
        testUser.getIdentities().add(userID);

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUser(testUser);

                    final User actual = userDAO.getUser(userID);
                    check(testUser, actual);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });

        // TODO should test passing in both Http and X500 Principals
    }

    /**
     * Test of addUserRequest method, of class LdapUserDAO.
     */
    @Test
    public void testAddUserRequest() throws Exception
    {
        // add user using HttpPrincipal
        final String username = createUsername();
        final HttpPrincipal userID = new HttpPrincipal(username);

        final User expectedUser = new User();
        expectedUser.getIdentities().add(userID);

        expectedUser.personalDetails = new PersonalDetails("foo", "bar");
        expectedUser.personalDetails.email = username + "@canada.ca";

        UserRequest userRequest = new UserRequest(expectedUser, "123456".toCharArray());

        // Adding a new user is done anonymously
        final LdapUserDAO userDAO = getUserDAO();
        userDAO.addUserRequest(userRequest);

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUserRequestsDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final User actualUser = userDAO.getUserRequest(userID);
                    check(expectedUser, actualUser);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });

        // try and add another user with the same username
        final User dupUsername = new User();
        dupUsername.getIdentities().add(userID);

        dupUsername.personalDetails = new PersonalDetails("foo", "bar");
        dupUsername.personalDetails.email = username + "@foo.com";

        UserRequest dupUsernameRequest = new UserRequest(dupUsername, "123456".toCharArray());

        try
        {
            userDAO.addUserRequest(dupUsernameRequest);
            fail("adding a duplicate user should throw a UserAlreadyExistsException");
        }
        catch (UserAlreadyExistsException expected)
        {
            log.debug("expected exception: " + expected.getMessage());
        }

        // try and add another user with the same email address
        final String username2 = createUsername();
        final HttpPrincipal userID2 = new HttpPrincipal(username);

        final User dupEmail = new User();
        dupEmail.getIdentities().add(userID2);

        dupEmail.personalDetails = new PersonalDetails("foo", "bar");
        dupEmail.personalDetails.email = username + "@canada.ca";

        UserRequest dupEmailRequest = new UserRequest(dupEmail, "123456".toCharArray());

        try
        {
            userDAO.addUserRequest(dupEmailRequest);
            fail("adding a user with an existing email address should throw a UserAlreadyExistsException");
        }
        catch (UserAlreadyExistsException expected)
        {
            log.debug("expected exception: " + expected.getMessage());
        }
    }

    /**
     * Test of getUser method, of class LdapUserDAO.
     */
    @Test
    public void testGetUserWithHttpPrincipal() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(cadcDaoTest1_HttpPrincipal);
        subject.getPrincipals().add(cadcDaoTest1_DNPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getUser(cadcDaoTest1_HttpPrincipal);
                    assertEquals(cadcDaoTest1_User.getHttpPrincipal(), actual.getHttpPrincipal());

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void testGetUserWithX500Principal() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(cadcDaoTest1_X500Principal);
        subject.getPrincipals().add(cadcDaoTest1_DNPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getUser(cadcDaoTest1_X500Principal);
                    assertEquals(cadcDaoTest1_User.getHttpPrincipal(), actual.getHttpPrincipal());

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void getGetUser() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(cadcDaoTest1_HttpPrincipal);
        subject.getPrincipals().add(cadcDaoTest1_DNPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getUser(cadcDaoTest1_HttpPrincipal);
                    assertEquals(cadcDaoTest1_User.getHttpPrincipal(), actual.getHttpPrincipal());

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void getGetAugmentedUser() throws Exception {
        Subject subject = new Subject();
        subject.getPrincipals().add(cadcDaoTest1_HttpPrincipal);
        subject.getPrincipals().add(cadcDaoTest1_DNPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            public Object run()
                throws Exception {
                try {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getAugmentedUser(cadcDaoTest1_HttpPrincipal, false);
                    assertEquals(cadcDaoTest1_User.getHttpPrincipal(), actual.getHttpPrincipal());
                    assertNull(actual.appData); // no cache
                    return null;
                } catch (Exception e) {
                    throw new Exception("Problems", e);
                }
            }
        });

        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            public Object run()  throws Exception {
                try {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getAugmentedUser(cadcDaoTest1_HttpPrincipal, true);
                    assertEquals(cadcDaoTest1_User.getHttpPrincipal(), actual.getHttpPrincipal());
                    assertNotNull(actual.appData);
                    return null;
                } catch (Exception e) {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    /**
     * Test of getUserByEmailAddress method, of class LdapUserDAO.
     */
    @Test
    public void testGetUserByEmailAddress() throws Exception
    {
        // create a user with the email attribute
        final String username = createUsername();
        final String emailAddress = username +"@canada.ca";
        final HttpPrincipal userID = new HttpPrincipal(username);
        final User testUser = new User();
        testUser.personalDetails = new PersonalDetails("foo", "bar");
        testUser.personalDetails.email = username + "@canada.ca";
        testUser.getIdentities().add(userID);

        addUser(userID, testUser);

        try
        {
            // case 1: only one user matches the email address
            testGetOneUserByEmailAddress(emailAddress, username);
         }
        finally
        {
            deleteUser(userID);
        }

    }

    @Test
    public void testGetPendingUser() throws Exception
    {
        final String username = "CADCtestRequest";
        final String x500DN = "cn=" + username + ",ou=cadc,o=hia,c=ca";
        final HttpPrincipal httpPrincipal = new HttpPrincipal(username);
        final X500Principal x500Principal = new X500Principal(x500DN);

        final User pendingUser = new User();
        pendingUser.personalDetails = new PersonalDetails("CADCtest", "Request");
        pendingUser.personalDetails.email = username + "@canada.ca";
        pendingUser.getIdentities().add(httpPrincipal);
        pendingUser.getIdentities().add(x500Principal);

        UserRequest userRequest = new UserRequest(pendingUser, "123456".toCharArray());

        try
        {
            final LdapUserDAO httpUserDAO = getUserDAO();
            httpUserDAO.addUserRequest(userRequest);
        }
        catch (UserAlreadyExistsException expected) {}

        final Subject subject = new Subject();
        subject.getPrincipals().add(httpPrincipal);
        subject.getPrincipals().add(x500Principal);
        subject.getPrincipals().add(new DNPrincipal(username + "," + config.getUsersDN()));

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getUserRequest(httpPrincipal);
                    check(pendingUser, actual);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    // TODO testGetUser for a user that doesn't exist

    @Test
    public void testApproveUser() throws Exception
    {
        String username = createUsername();

        final HttpPrincipal httpPrincipal = new HttpPrincipal(username);

        final User expected = new User();
        expected.getIdentities().add(httpPrincipal);

        expected.personalDetails = new PersonalDetails("foo", "bar");
        expected.personalDetails.email = username + "@canada.ca";

        final UserRequest userRequest = new UserRequest(expected, "123456".toCharArray());

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUserRequest(userRequest);

                    final User actual = userDAO.approveUserRequest(expected.getHttpPrincipal());
                    assertNotNull(actual);
                    assertEquals(expected.getHttpPrincipal(), actual.getHttpPrincipal());

                    User newUser = userDAO.getUser(userRequest.getUser().getHttpPrincipal());
                    assertNotNull(newUser);
                    assertEquals(expected.getHttpPrincipal(), newUser.getHttpPrincipal());

                    try
                    {
                        userDAO.getUserRequest(userRequest.getUser().getHttpPrincipal());
                        fail("approved user " + userRequest.getUser().getHttpPrincipal() +
                             " found in pending user tree");
                    }
                    catch (UserNotFoundException ignore) {}

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void testUpdateUser() throws Exception
    {
        // Create a test user
        final User testUser;
        final String username = createUsername();

        final HttpPrincipal userID = new HttpPrincipal(username);
        testUser = new User();
        testUser.getIdentities().add(userID);

        testUser.personalDetails = new PersonalDetails("firstName", "lastName");
        testUser.personalDetails.email = username + "@canada.ca";

        final UserRequest userRequest = new UserRequest(testUser, "password".toCharArray());

        // add the user
        Subject subject = new Subject();
        subject.getPrincipals().add(userID);
        final User newUser = (User) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public User run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUserRequest(userRequest);
                    userDAO.approveUserRequest(userID);
                    return userDAO.getUser(userID);
                }
                catch (Exception e)
                {
                    fail("exception updating user: " + e.getMessage());
                }
                return null;
            }
        });

        // update the user
        newUser.personalDetails.address = "address2";
        newUser.personalDetails.institute = "institute2";
        newUser.personalDetails.city = "city2";
        newUser.personalDetails.country = "country2";

        // add a DN
        newUser.getIdentities().add(new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca"));

        // update the userexpected
        subject.getPrincipals().add(userID);
        User updatedUser = (User) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
            {
                public Object run()
                    throws Exception
                {
                    try
                    {
                        final LdapUserDAO userDAO = getUserDAO();
                        return userDAO.modifyUser(newUser);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                        fail("exception updating user: " + e.getMessage());
                    }
                    return null;
                }
            });
        assertNotNull(updatedUser);
        check(newUser, updatedUser);
    }

    // TODO testUpdateUser for a user that doesn't exist

    /**
     * Test of deleteUser method, of class LdapUserDAO.
     */
    @Test
    public void deleteUser() throws Exception
    {
        String username = createUsername();

        final HttpPrincipal userID = new HttpPrincipal(username);

        final User testUser = new User();
        testUser.getIdentities().add(userID);
        testUser.personalDetails = new PersonalDetails("foo", "bar");
        testUser.personalDetails.email = username + "@canada.ca";

        final UserRequest userRequest = new UserRequest(testUser, "password".toCharArray());

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + userID + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUserRequest(userRequest);
                    userDAO.approveUserRequest(userID);

                    userDAO.deleteUser(userID, false);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    /**
     * Test of deleteUserRequest method, of class LdapUserDAO.
     */
    @Test
    public void deletePendingUser() throws Exception
    {
        String userID = createUsername();

        HttpPrincipal httpPrincipal = new HttpPrincipal(userID);
        X500Principal x500Principal = new X500Principal("cn=" + userID + ",ou=cadc,o=hia,c=ca");

        final User expected = new User();
        expected.getIdentities().add(httpPrincipal);
        expected.getIdentities().add(x500Principal);
        expected.personalDetails = new PersonalDetails("foo", "bar");
        expected.personalDetails.email = userID + "@canada.ca";

        final UserRequest userRequest = new UserRequest(expected, "123456".toCharArray());

        final LdapUserDAO userDAO = getUserDAO();
        userDAO.addUserRequest(userRequest);

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + userID + "," + config.getUserRequestsDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    userDAO.deleteUserRequest(expected.getHttpPrincipal());

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void testGetUsers() throws Exception
    {
        // authenticated access
        Subject subject = new Subject();
        subject.getPrincipals().add(cadcDaoTest1_X500Principal);
        subject.getPrincipals().add(cadcDaoTest1_DNPrincipal);

        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final Collection<User> users = getUserDAO().getUsers();
                    assertNotNull("returned users is null", users);
                    assertFalse("no users found", users.isEmpty());
                    log.debug("# users found: " + users.size());

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void testGetPendingUsers() throws Exception
    {
        // authenticated access
        Subject subject = new Subject();
        subject.getPrincipals().add(cadcDaoTest1_X500Principal);
        subject.getPrincipals().add(cadcDaoTest1_DNPrincipal);

        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final Collection<User> users = getUserDAO().getUserRequests();
                    assertNotNull("returned users is null", users);
                    assertFalse("no users found", users.isEmpty());
                    log.debug("# users found: " + users.size());

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void testDoLogin() throws Exception
    {
        final String username = createUsername();
        final String password = "123456";

        HttpPrincipal httpPrincipal = new HttpPrincipal(username);

        final User testUser = new User();
        testUser.getIdentities().add(httpPrincipal);

        testUser.personalDetails = new PersonalDetails("foo", "bar");
        testUser.personalDetails.email = username + "@canada.ca";

        final UserRequest userRequest = new UserRequest(testUser, password.toCharArray());

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    // add a user
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUserRequest(userRequest);

                    // approve the user
                    userDAO.approveUserRequest(testUser.getHttpPrincipal());

                    // login as the user
                    boolean success = userDAO.doLogin(username, password);
                    assertTrue("login failed", success);

                    // login with wrong username
                    try
                    {
                        success = userDAO.doLogin("foo", password);
                        fail("unknown username should throw AccessControlException");
                    }
                    catch (AccessControlException expected)
                    {
                        log.debug("expected exception " + expected.getMessage());
                    }

                    // login with wrong password
                    try
                    {
                        success = userDAO.doLogin(username, "foo");
                        fail("wrong password should throw AccessControlException");
                    }
                    catch (AccessControlException expected)
                    {
                        log.debug("expected exception " + expected.getMessage());
                    }

                    // delete the user
                    userDAO.deleteUser(testUser.getHttpPrincipal(), false);

                    // login as deleted user
                    try
                    {
                        success = userDAO.doLogin(username, password);
                        fail("deactivated user should throw AccessControlException");
                    }
                    catch (AccessControlException expected)
                    {
                        log.debug("expected exception " + expected.getMessage());
                    }

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }



    @Test
    public void testGetMultipleUser() throws Exception
    {
        // add user using X500Principal
        // was MultiAccount*, Multi*
        final String username = "DuplicateCadcUser2";
        log.info(username);

        try {
            // This allows multiple users with same DN to be created. This test requires
            // that scenario, in order to test that getUser works correctly under what
            // is generally an abnormal condition.

            // This test is to test a hack in the system to prevent issues where multiples
            // of users are created. (s2255)
            System.setProperty(LdapUserDAO.SUPPRESS_CHECKUSER_KEY, "true");

            final X500Principal userID = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");
            final HttpPrincipal testHttpPrincipal = new HttpPrincipal(username);

            log.info("user DN: " + config.getUsersDN());
            final DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUsersDN());
            Subject subject = new Subject();
            subject.getPrincipals().add(dnPrincipal);

            Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                public Object run() throws Exception {
                    final LdapUserDAO userDAO = getUserDAO();
                    User testUser = new User();

                    // Test to see if user already exsits.
                    try {
                        testUser = userDAO.getUser(userID);
                    } catch (UserNotFoundException unfe) {
                        testUser.getIdentities().add(userID);
                        testUser.getIdentities().add(testHttpPrincipal);
                        testUser.personalDetails = new PersonalDetails("Multi", "MultiAccountCadcUser");
                        testUser.personalDetails.email = username + "@canada.ca";
                        log.debug("Test user " + username + " not found, creating...");
                        UserRequest userRequest = new UserRequest(testUser, "password".toCharArray());
                        userDAO.addUserRequest(userRequest);
                        userDAO.approveUserRequest(testHttpPrincipal);
                    }

                    // Check to see if there are multiple users already existing.
                    List<User> userList = userDAO.getAllUsers(userID, config.getUsersDN());

                    if (userList.size() < 6) {
                        log.debug("Creating multiple users (5 more)");

                        // Run this 5x to create multiple users
                        for (int i = 0; i < 5; i++) {
                            try {
                                userDAO.addUser(testUser);
                            } catch (Exception e) {
                                throw new Exception("Problems", e);
                            }
                        }

                        // Retrieve new list
                        userList = userDAO.getAllUsers(userID, config.getUsersDN());
                    }

                    User retrievedUser = userDAO.getUser(userID);

                    // Test content of testUser name
                    // Test number of users with same name found
                    Assert.assertEquals("Test user not found", testUser, retrievedUser);
                    Assert.assertTrue("Error creating multiple users for test.", userList.size() > 5);

                    // Verify getAugmentedUser works in this case as well
                    final User actualAugmented = userDAO.getAugmentedUser(testHttpPrincipal, false);

                    Assert.assertEquals(testHttpPrincipal,actualAugmented.getHttpPrincipal());

                    return null;
                }
            });
        } finally {
            System.clearProperty(LdapUserDAO.SUPPRESS_CHECKUSER_KEY);
        }

        // TODO should test passing in both Http and X500 Principals
    }


    @Test
    public void testGetMultipleUserFail() throws Exception {

        // check to see if user exists
        // if not, make 3 using internal method so that all users have $EXTERNAL-CN
        // as ldap name. If there are > 1 of these AND no other users, there should be a
        // Runtime error thrown.

        final String username = "DuplicateCadcUser3";
        log.info(username);

        try {
            System.setProperty(LdapUserDAO.SUPPRESS_CHECKUSER_KEY, "true");

            final LdapUserDAO userDAO = getUserDAO();

            final X500Principal userID = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");

            List<User> userList = userDAO.getAllUsers(userID, config.getUsersDN());

            if (userList.size() < 2) {

                final User testUser = new User();
                testUser.getIdentities().add(userID);

                DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUsersDN());
                Subject subject = new Subject();
                subject.getPrincipals().add(dnPrincipal);

                Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                    public Object run() throws Exception {
                        try {
                            final LdapUserDAO userDAO = getUserDAO();
                            userDAO.addUser(testUser);
                            userDAO.addUser(testUser);
                        } catch (Exception e) {
                            throw new Exception("Problems", e);
                        }
                        return null;
                    };
                });
            }

            // This should throw an exception
            User foundUser = userDAO.getUser(userID);

        } catch (RuntimeException re){
            log.debug("expected Runtime exception");

        } catch (Exception e) {
            log.debug("unexpected exception", e);
            Assert.fail();
        }
        finally {
            System.clearProperty(LdapUserDAO.SUPPRESS_CHECKUSER_KEY);
        }
    }



//    @Test
    public void testSetPassword() throws Exception
    {
//        LDAPConnection connection =
//            new LDAPConnection(SocketFactory.getDefault(), config.getServer(), config.getPort());
//        connection.bind(config.getAdminUserDN(), config.getAdminPasswd());
//
//        // Create an SSLUtil instance that is configured to trust any certificate.
//        SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
//        SSLContext sslContext = sslUtil.createSSLContext();
//        StartTLSExtendedRequest startTLSRequest = new StartTLSExtendedRequest(sslContext);
//        ExtendedResult startTLSResult = connection.processExtendedOperation(startTLSRequest);
//        LDAPTestUtils.assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);

        // Create a test user with a known password
        final User testUser;
        final String username = createUsername();
        final char[] password = "foo".toCharArray();
        final char[] newPassword = "bar".toCharArray();

        final HttpPrincipal httpPrincipal = new HttpPrincipal(username);

        testUser = new User();
        testUser.getIdentities().add(httpPrincipal);
        testUser.personalDetails = new PersonalDetails("firstName", "lastName");

        // add the user
        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getHttpPrincipal());
        subject.getPrincipals().add(dnPrincipal);
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUser(testUser);
                }
                catch (Exception e)
                {
                    fail("exception updating user: " + e.getMessage());
                }
                return null;
            }
        });

        // authenticate new username and password
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    getUserDAO().doLogin(username, String.valueOf(password));
                }
                catch (Exception e)
                {
                    fail("exception during login: " + e.getMessage());
                }
                return null;
            }
        });

        // anonymous access should throw exception
        subject = new Subject();
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.setPassword(httpPrincipal, String.valueOf(password),
                        String.valueOf(newPassword));
                    fail("should throw exception if subject and user are not the same");
                }
                catch (Exception ignore)
                {
                }
                return null;
            }
        });

        // change the password
        subject.getPrincipals().add(testUser.getHttpPrincipal());
        subject.getPrincipals().add(dnPrincipal);
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.setPassword(httpPrincipal, String.valueOf(password),
                        String.valueOf(newPassword));
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    fail("exception setting password: " + e.getMessage());
                }
                return null;
            }
        });

        // verify new password
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    getUserDAO().doLogin(username, String.valueOf(password));
                }
                catch (Exception e)
                {
                    fail("exception during login: " + e.getMessage());
                }
                return null;
            }
        });

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
    }

    private UserRequest createUserRequest(final HttpPrincipal userID, final String email)
    {
        final String username = userID.getName();
        final String password = "123456";

        final User expected = new User();
        expected.getIdentities().add(userID);

        expected.personalDetails = new PersonalDetails("foo", "bar");
        expected.personalDetails.email = email;

        final UserRequest userRequest = new UserRequest(expected, password.toCharArray());

        return userRequest;
    }

    private void addUser(final HttpPrincipal userID, final User user)
        throws Exception
    {
        final UserRequest userRequest = new UserRequest(user, "password".toCharArray());

        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + userID.getName() + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getUserDAO().addUserRequest(userRequest);
                    getUserDAO().approveUserRequest(userID);
                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    private void deleteUser(final HttpPrincipal userID)
        throws Exception
    {
        DNPrincipal dnPrincipal = new DNPrincipal("uid=" + userID.getName() + "," + config.getUsersDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.deleteUser(userID, false);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    protected void testGetOneUserByEmailAddress(final String emailAddress, final String username)
        throws PrivilegedActionException
    {
        // do as servops
        Subject servops = SSLUtil.createSubject(new File(SERVOPS_PEM));
        Subject.doAs(servops, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User user = userDAO.getUserByEmailAddress(emailAddress);
                    assertNotNull(user);
                    PersonalDetails pd =  user.personalDetails;
                    assertEquals(emailAddress, pd.email);
                    String actualName = user.getHttpPrincipal().getName();
                    assertEquals(username, actualName);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

}
