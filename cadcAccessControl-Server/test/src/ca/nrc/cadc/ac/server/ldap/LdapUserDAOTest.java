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
package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.util.Log4jInit;
import com.unboundid.ldap.sdk.DN;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;
import java.util.Random;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LdapUserDAOTest extends AbstractLdapDAOTest
{
    private static final Logger log = Logger.getLogger(LdapUserDAOTest.class);

    private static final String SERVOPS_PEM = System.getProperty("user.home") + "/.pub/proxy.pem";
    static final String testUserX500DN = "cn=cadcdaotest1,ou=cadc,o=hia,c=ca";
    static final String cadcdaotest1DN = "uid=cadcdaotest1,ou=users,ou=ds,dc=testcanfar";
    static final String cadcdaotest2DN = "uid=cadcdaotest2,ou=users,ou=ds,dc=testcanfar";
    static int nextUserNumericID = 666;

    static String testUserDN;
    static User testX500User;
    static User testMember;
    static X500Principal testUserX500Principal;
    static DNPrincipal cadcdaotest1Principal;
    static DNPrincipal cadcdaotest2Principal;
    static LdapConfig config;
    static Random ran = new Random(); // source of randomness for numeric ids


    @BeforeClass
    public static void setUpBeforeClass()
            throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);

        // get the configuration of the development server from and config files...
        config = getLdapConfig();

        testUserX500Principal = new X500Principal(testUserX500DN);
        testX500User = new User();
        testX500User.getIdentities().add(testUserX500Principal);

        testX500User.personalDetails = new PersonalDetails("CADC", "DAOTest1");
        testX500User.getIdentities().add(new HttpPrincipal("CadcDaoTest1"));
        testX500User.getIdentities().add(testUserX500Principal);
        testX500User.getIdentities().add(new NumericPrincipal(UUID.randomUUID()));

        testUserDN = "uid=cadcdaotest1," + config.getUsersDN();


        // member returned by getMember contains only the fields required by
        // the GMS
        testMember = new User();
        testMember.personalDetails = new PersonalDetails("CADC", "DAOTest1");
        testMember.getIdentities().add(testUserX500Principal);
        testMember.getIdentities().add(new HttpPrincipal("CadcDaoTest1"));

        cadcdaotest1Principal = new DNPrincipal(cadcdaotest1DN);
        cadcdaotest2Principal = new DNPrincipal(cadcdaotest2DN);
    }

    LdapUserDAO getUserDAO() throws Exception
    {
        LdapConnections connections = new LdapConnections(config);
        return new LdapUserDAO(connections){
            protected int genNextNumericId()
            {
                return nextUserNumericID;
            }
        };
    }

    String createUsername()
    {
        return "CadcDaoTestUser-" + System.currentTimeMillis();
    }

    /**
     * Test of addUser method, of class LdapUserDAO.
     */
    @Test
    public void testAddUser() throws Exception
    {
        // add user using HttpPrincipal
        final String username = createUsername();
        final HttpPrincipal userID = new HttpPrincipal(username);

        final User httpExpected = new User();
        httpExpected.getIdentities().add(userID);

        httpExpected.personalDetails = new PersonalDetails("foo", "bar");

        final UserRequest httpUserRequest = new UserRequest(httpExpected, "123456".toCharArray());

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
                    userDAO.addUser(httpUserRequest);

                    final User actual = userDAO.getUser(userID);
                    check(httpExpected, actual);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });

        // add user using X500Principal
        X500Principal x500Principal = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");

        final User x500Expected = new User();
        x500Expected.getIdentities().add(x500Principal);

        x500Expected.personalDetails = new PersonalDetails("foo", "bar");

        final UserRequest x500UserRequest = new UserRequest(x500Expected, "123456".toCharArray());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUser(x500UserRequest);

                    final User actual = userDAO.getUser(userID);
                    check(x500Expected, actual);

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
     * Test of addPendingUser method, of class LdapUserDAO.
     */
//    @Test
    public void testAddPendingUser() throws Exception
    {
        // add user using HttpPrincipal
        final String username = createUsername();
        final HttpPrincipal userID = new HttpPrincipal(username);

        final User httpExpected = new User();
        httpExpected.getIdentities().add(userID);

        PersonalDetails pd = new PersonalDetails("foo", "bar");
        pd.email = username + "@canada.ca";
        httpExpected.personalDetails = pd;

        UserRequest userRequest = new UserRequest(httpExpected, "123456".toCharArray());

        final LdapUserDAO httpUserDAO = getUserDAO();
        httpUserDAO.addPendingUser(userRequest);

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
                    final User actual = httpUserDAO.getPendingUser(userID);
                    check(httpExpected, actual);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });

        // add user using X500Principal
        final X500Principal x500Principal = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");

        final User x500Expected = new User();
        x500Expected.getIdentities().add(x500Principal);
        x500Expected.personalDetails = pd;

        userRequest = new UserRequest(x500Expected, "123456".toCharArray());

        final LdapUserDAO x500UserDAO = getUserDAO();
        x500UserDAO.addPendingUser(userRequest);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final User actual = x500UserDAO.getPendingUser(userID);
                    check(x500Expected, actual);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    // TODO testAddUser for an existing user

    /**
     * Test of getUser method, of class LdapUserDAO.
     */
//    @Test
    public void testGetUser() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(testUserX500Principal);
        subject.getPrincipals().add(cadcdaotest1Principal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getUser(testUserX500Principal);
                    check(testX500User, actual);

                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    private UserRequest createUserRequest(final HttpPrincipal userID, final String email)
    {
        final String username = userID.getName();
        final String password = "123456";

        X500Principal x500Principal = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");
        NumericPrincipal numericPrincipal = new NumericPrincipal(UUID.randomUUID());

        final User expected = new User();
        expected.getIdentities().add(userID);
        expected.getIdentities().add(x500Principal);
        expected.getIdentities().add(numericPrincipal);

        expected.personalDetails = new PersonalDetails("foo", "bar");
        expected.personalDetails.email = email;

        final UserRequest userRequest = new UserRequest(expected, password.toCharArray());
        
        return userRequest;
    }
    
    private void addUser(final HttpPrincipal userID, final UserRequest userRequest)
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
                    userDAO.addUser(userRequest);
                    
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
                    userDAO.deleteUser(userID);
                    
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
    
    /**
     * Test of getUserByEmailAddress method, of class LdapUserDAO.
     */
//    @Test
    public void testGetUserByEmailAddress() throws Exception
    {
        // create a user with the email attribute
        final String username = createUsername();
        final String emailAddress = username +"@canada.ca";
        final HttpPrincipal userID = new HttpPrincipal(username);
        final UserRequest userRequest = createUserRequest(userID, emailAddress);
        addUser(userID, userRequest);
        
        try
        {
            // case 1: only one user matches the email address
            testGetOneUserByEmailAddress(emailAddress, username);
            
            // create another user with the same email attribute
            final String username1 = createUsername();
            final HttpPrincipal userID1 = new HttpPrincipal(username1);
            final UserRequest userRequest1 = createUserRequest(userID1, emailAddress);
            addUser(userID1, userRequest1);
            
            try
            {
                // case 2: two users match the email address
                testGetOneUserByEmailAddress(emailAddress, username);
            }
            catch (PrivilegedActionException pae)
            {
                Exception e = pae.getException();
                Throwable t = e.getCause();
                assertTrue(e.getCause() instanceof UserAlreadyExistsException);
                assertTrue(e.getCause().getMessage().contains(LdapUserDAO.EMAIL_ADDRESS_CONFLICT_MESSAGE));
            }
            finally
            {
                deleteUser(userID1);
            }
        }
        finally
        {
            deleteUser(userID);
        }
        
    }
    
//    @Test
    public void testGetPendingUser() throws Exception
    {
        final String userRequestDN = "uid=CADCtestRequest,ou=userrequests,ou=ds,dc=testcanfar";

        final HttpPrincipal httpPrincipal = new HttpPrincipal("CADCtestRequest");
        final X500Principal x500Principal = new X500Principal(userRequestDN);
        final DNPrincipal dnPrincipal = new DNPrincipal(userRequestDN);

        final User pendingUser = new User();
        pendingUser.getIdentities().add(httpPrincipal);
        pendingUser.getIdentities().add(x500Principal);
        pendingUser.getIdentities().add(dnPrincipal);


        final Subject subject = new Subject();
        subject.getPrincipals().add(httpPrincipal);
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    final User actual = userDAO.getPendingUser(httpPrincipal);
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

//    @Test
    public void testApproveUser() throws Exception
    {
        String username = createUsername();

        final HttpPrincipal httpPrincipal = new HttpPrincipal(username);
        final X500Principal x500Principal = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");
        final NumericPrincipal numericPrincipal = new NumericPrincipal(UUID.randomUUID());

        final User expected = new User();
        expected.getIdentities().add(httpPrincipal);
        expected.getIdentities().add(x500Principal);
        expected.getIdentities().add(numericPrincipal);

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
                    userDAO.addPendingUser(userRequest);

                    final User actual = userDAO.approvePendingUser(expected.getHttpPrincipal());
                    assertNotNull(actual);
                    assertEquals(expected.getHttpPrincipal(), actual.getHttpPrincipal());

                    User newUser = userDAO.getUser(userRequest.getUser().getHttpPrincipal());
                    assertNotNull(newUser);
                    assertEquals(expected.getHttpPrincipal(), newUser.getHttpPrincipal());

                    try
                    {
                        userDAO.getPendingUser(userRequest.getUser().getHttpPrincipal());
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

//    @Test
    public void testUpdateUser() throws Exception
    {
        // Create a test user
        final User testUser;
        final String username = createUsername();
        final char[] password = "foo".toCharArray();

        HttpPrincipal httpPrincipal = new HttpPrincipal(username);
        testUser = new User();
        testUser.getIdentities().add(httpPrincipal);

        UUID uuid = UUID.randomUUID();
        testUser.getIdentities().add(new NumericPrincipal(uuid));
        testUser.personalDetails = new PersonalDetails("firstName", "lastName");
        final UserRequest userRequest = new UserRequest(testUser, password);

        // add the user
        Subject subject = new Subject();
        subject.getPrincipals().add(httpPrincipal);
        subject.getPrincipals().add(cadcdaotest2Principal);
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO userDAO = getUserDAO();
                    userDAO.addUser(userRequest);
                }
                catch (Exception e)
                {
                    fail("exception updating user: " + e.getMessage());
                }
                return null;
            }
        });

        // update the user
        testUser.personalDetails.email = "email2";
        testUser.personalDetails.address = "address2";
        testUser.personalDetails.institute = "institute2";
        testUser.personalDetails.city = "city2";
        testUser.personalDetails.country = "country2";

        // add a DN
        testUser.getIdentities().add(new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca"));

        // update the userexpected
        subject.getPrincipals().add(httpPrincipal);
        subject.getPrincipals().add(cadcdaotest2Principal);
        User updatedUser = (User) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
            {
                public Object run()
                    throws Exception
                {
                    try
                    {
                        final LdapUserDAO userDAO = getUserDAO();
                        return userDAO.modifyUser(testUser);
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
        check(testUser, updatedUser);
    }

    // TODO testUpdateUser for a user that doesn't exist

    /**
     * Test of deleteUser method, of class LdapUserDAO.
     */
//    @Test
    public void deleteUser() throws Exception
    {
        String userID = createUsername();

        HttpPrincipal httpPrincipal = new HttpPrincipal(userID);
        X500Principal x500Principal = new X500Principal("cn=" + userID + ",ou=cadc,o=hia,c=ca");

        final User expected = new User();
        expected.getIdentities().add(httpPrincipal);
        expected.getIdentities().add(x500Principal);
        expected.personalDetails = new PersonalDetails("foo", "bar");

        final UserRequest userRequest = new UserRequest(expected, "123456".toCharArray());

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
                    userDAO.addUser(userRequest);

                    userDAO.deleteUser(expected.getHttpPrincipal());

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
     * Test of deletePendingUser method, of class LdapUserDAO.
     */
//    @Test
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
        userDAO.addPendingUser(userRequest);

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
                    userDAO.deletePendingUser(expected.getHttpPrincipal());

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
     * Test of getMember.
     */
//    @Test
    public void testGetX500User() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(testUserX500Principal);
        subject.getPrincipals().add(cadcdaotest1Principal);

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    User actual = getUserDAO().getX500User(new DN(testUserDN));
                    check(testMember, actual);
                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });

        // should also work as a different user
        subject = new Subject();
        subject.getPrincipals().add(new HttpPrincipal("CadcDaoTest2"));

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    User actual = getUserDAO().getX500User(new DN(testUserDN));
                    check(testMember, actual);
                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }

//    @Test
    public void testGetUsers() throws Exception
    {
        // authenticated access
        Subject subject = new Subject();
        subject.getPrincipals().add(testUserX500Principal);
        subject.getPrincipals().add(cadcdaotest1Principal);

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

//    @Test
    public void testGetPendingUsers() throws Exception
    {
        // authenticated access
        Subject subject = new Subject();
        subject.getPrincipals().add(testUserX500Principal);
        subject.getPrincipals().add(cadcdaotest1Principal);

        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final Collection<User> users = getUserDAO().getPendingUsers();
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

//    @Test
    public void testDoLogin() throws Exception
    {
        final String username = createUsername();
        final String password = "123456";

        HttpPrincipal httpPrincipal = new HttpPrincipal(username);
        X500Principal x500Principal = new X500Principal("cn=" + username + ",ou=cadc,o=hia,c=ca");
        NumericPrincipal numericPrincipal = new NumericPrincipal(UUID.randomUUID());

        final User expected = new User();
        expected.getIdentities().add(httpPrincipal);
        expected.getIdentities().add(x500Principal);
        expected.getIdentities().add(numericPrincipal);

        expected.personalDetails = new PersonalDetails("foo", "bar");

        final UserRequest userRequest = new UserRequest(expected, password.toCharArray());

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
                    userDAO.addUser(userRequest);

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
                    userDAO.deleteUser(userRequest.getUser().getHttpPrincipal());

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

////    @Test
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

        final UserRequest userRequest = new UserRequest(testUser, password);

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
                    userDAO.addUser(userRequest);
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

        assertEquals(expected.personalDetails, actual.personalDetails);
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
        PersonalDetails pd1 = expected.personalDetails;
        PersonalDetails pd2 = actual.personalDetails;
        assertEquals(pd1, pd2);

        if (pd1 == null && pd2 == null)
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

}
