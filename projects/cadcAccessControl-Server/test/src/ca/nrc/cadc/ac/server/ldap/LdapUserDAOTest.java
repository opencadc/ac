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
import ca.nrc.cadc.ac.UserDetails;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.Log4jInit;
import com.unboundid.ldap.sdk.DN;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LdapUserDAOTest extends AbstractLdapDAOTest
{
    private static final Logger log = Logger.getLogger(LdapUserDAOTest.class);

    static final String testUserX509DN = "cn=cadcdaotest1,ou=cadc,o=hia,c=ca";

    static String testUserDN;
    static User<X500Principal> testUser;
    static User<HttpPrincipal> testPendingUser;
    static LdapConfig config;


    @BeforeClass
    public static void setUpBeforeClass()
            throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);

        // get the configuration of the development server from and config files...
        config = getLdapConfig();

        testPendingUser =
                new User<HttpPrincipal>(new HttpPrincipal("CADCtestRequest"));
        testPendingUser.details.add(new PersonalDetails("CADCtest", "Request"));
        testPendingUser.getIdentities().add(
                new HttpPrincipal("CADCtestRequest"));

        testUser = new User<X500Principal>(new X500Principal(testUserX509DN));
        testUser.details.add(new PersonalDetails("CADC", "DAOTest1"));
        testUser.getIdentities().add(new HttpPrincipal("CadcDaoTest1"));

        testUserDN = "uid=cadcdaotest1," + config.getUsersDN();
    }

    <T extends Principal> LdapUserDAO<T> getUserDAO() throws Exception
    {
        return new LdapUserDAO<T>(config);
    }

    String createUserID()
    {
        return "CadcDaoTestUser-" + System.currentTimeMillis();
    }

    /**
     * Test of addUser method, of class LdapUserDAO.
     */
    @Test
    public void testAddUser() throws Exception
    {
        final User<HttpPrincipal> expected =
                new User<HttpPrincipal>(new HttpPrincipal(createUserID()));
        expected.getIdentities().add(new HttpPrincipal(createUserID()));
        expected.details.add(new PersonalDetails("foo", "bar"));

        final UserRequest<HttpPrincipal> userRequest =
                new UserRequest<HttpPrincipal>(expected, "123456");

        Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getUserID());

        final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
        User<HttpPrincipal> actual = userDAO.addUser(userRequest);
        check(expected, actual);
    }

    @Test
    public void testGetPendingUser() throws Exception
    {
        final Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    final User<HttpPrincipal> actual =
                            userDAO.getPendingUser(testPendingUser.getUserID());
                    check(testPendingUser, actual);

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
     * Test of getUser method, of class LdapUserDAO.
     */
    @Test
    public void testGetUser() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO<X500Principal> userDAO = getUserDAO();
                    final User<X500Principal> actual =
                            userDAO.getUser(testUser.getUserID());
                    check(testUser, actual);

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
     * Test of getUserGroups method, of class LdapUserDAO.
     */
    @Test
    public void testGetUserGroups() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Collection<DN> groups = getUserDAO().getUserGroups(testUser.getUserID(),
                                                       false);
                    assertNotNull("Groups should not be null.", groups);

                    for (DN groupDN : groups)
                    {
                        log.debug(groupDN);
                    }

                    groups = getUserDAO().getUserGroups(testUser.getUserID(),
                                                        true);
                    assertNotNull("Groups should not be null.", groups);
                    for (DN groupDN : groups)
                    {
                        log.debug(groupDN);
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

    /**
     * Test of getUserGroups method, of class LdapUserDAO.
     */
    @Test
    public void testIsMember() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    boolean isMember = getUserDAO().isMember(testUser.getUserID(), "foo");
                    assertFalse("Membership should not exist.", isMember);

                    String  groupDN = "cn=cadcdaotestgroup1," + config.getGroupsDN();
                    isMember = getUserDAO().isMember(testUser.getUserID(),
                                                     groupDN);
                    assertTrue("Membership should exist.", isMember);

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
    @Test
    public void testGetMember() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    User<X500Principal> actual = getUserDAO().getX500User(new DN(testUserDN));
                    check(testUser, actual);
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
                    User<X500Principal> actual = getUserDAO().getX500User(new DN(testUserDN));
                    check(testUser, actual);
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
     * Test of testGetCadcUserIDs.
     */
    @Test
    public void testGetCadcUserIDs() throws Exception
    {
        Subject subject = new Subject();

        // anonymous access
        int users1 = (Integer) Subject
                .doAs(subject, new PrivilegedExceptionAction<Object>()
                {
                    public Object run() throws Exception
                    {
                        try
                        {

                            int count = getUserDAO().getCadcIDs().size();
                            assertTrue(count > 0);
                            return count;
                        }
                        catch (Exception e)
                        {
                            throw new Exception("Problems", e);
                        }
                    }
                });

        // authenticated access
        subject.getPrincipals().add(testUser.getUserID());
        int users2 = (Integer) Subject
                .doAs(subject, new PrivilegedExceptionAction<Object>()
                {
                    public Object run() throws Exception
                    {
                        try
                        {

                            int count = getUserDAO().getCadcIDs().size();
                            assertTrue(count > 0);
                            return count;
                        }
                        catch (Exception e)
                        {
                            throw new Exception("Problems", e);
                        }
                    }
                });
        assertEquals("User listing should be independent of the access type",
            users1, users2);
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
        final User<HttpPrincipal> testUser2;
        final String username = createUserID();
        final String password = "foo";
        final String newPassword = "bar";

        HttpPrincipal principal = new HttpPrincipal(username);
        testUser2 = new User<HttpPrincipal>(principal);
        testUser2.getIdentities().add(principal);
        testUser2.details.add(new PersonalDetails("firstName", "lastName"));
        final UserRequest<HttpPrincipal> userRequest =
                new UserRequest<HttpPrincipal>(testUser2, password);

        // add the user
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser2.getUserID());
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    return userDAO.newUser(userRequest);
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
                    getUserDAO().doLogin(username, password);
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
            public Object run() throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    userDAO.setPassword(testUser2, password, newPassword);
                    fail("should throw exception if subject and user are not the same");
                }
                catch (Exception ignore){}
                return null;
            }
        });

        // change the password
        subject.getPrincipals().add(testUser2.getUserID());
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    userDAO.setPassword(testUser2, password, newPassword);
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
                    getUserDAO().doLogin(username, password);
                }
                catch (Exception e)
                {
                    fail("exception during login: " + e.getMessage());
                }
                return null;
            }
        });

    }

    @Test
    public void testUpdateUser() throws Exception
    {
        // Create a test user
        final User<HttpPrincipal> testUser2;
        final String username = createUserID();
        final String password = "foo";

        HttpPrincipal principal = new HttpPrincipal(username);
        testUser2 = new User<HttpPrincipal>(principal);
        testUser2.getIdentities().add(principal);
        testUser2.details.add(new PersonalDetails("firstName", "lastName"));
        final UserRequest<HttpPrincipal> userRequest =
                new UserRequest<HttpPrincipal>(testUser2, password);

        // add the user
        Subject subject = new Subject();
        subject.getPrincipals().add(testUser2.getUserID());
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    return userDAO.newUser(userRequest);
                }
                catch (Exception e)
                {
                    fail("exception updating user: " + e.getMessage());
                }
                return null;
            }
        });

        // update the user
        for (UserDetails details : testUser2.details)
        {
            if (details instanceof PersonalDetails)
            {
                PersonalDetails pd = (PersonalDetails) details;
                pd.email = "email2";
                pd.address = "address2";
                pd.institute = "institute2";
                pd.city = "city2";
                pd.country = "country2";
            }
        }

        // anonymous access should throw exception
        subject = new Subject();
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    userDAO.modifyUser(testUser2);
                    fail("should throw exception if subject and user are not the same");
                }
                catch (Exception ignore)
                {
                }
                return null;
            }
        });

        // update the user
        subject.getPrincipals().add(testUser2.getUserID());
        User<? extends Principal> updatedUser =
            (User<? extends Principal>) Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run()
                throws Exception
            {
                try
                {
                    final LdapUserDAO<HttpPrincipal> userDAO = getUserDAO();
                    return userDAO.modifyUser(testUser2);
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
        check(testUser2, updatedUser);
    }

    private static void check(final User<? extends Principal> user1,
                              final User<? extends Principal> user2)
    {
        assertEquals(user1, user2);
        assertEquals(user1.details, user2.details);
        assertEquals(user1.details.size(), user2.details.size());
        assertEquals("Identities don't match.", user1.getIdentities(),
                     user2.getIdentities());
        for (UserDetails d1 : user1.details)
        {
            assertTrue(user2.details.contains(d1));
            if (d1 instanceof PersonalDetails)
            {
                PersonalDetails pd1 = (PersonalDetails) d1;
                boolean found = false;
                for (UserDetails d2 : user2.details)
                {
                    if (d2 instanceof PersonalDetails)
                    {
                        PersonalDetails pd2 = (PersonalDetails) d2;
                        assertEquals(pd1, pd2); // already done in contains above but just in case
                        assertEquals(pd1.address, pd2.address);
                        assertEquals(pd1.city, pd2.city);
                        assertEquals(pd1.country, pd2.country);
                        assertEquals(pd1.email, pd2.email);
                        assertEquals(pd1.institute, pd2.institute);
                        found = true;
                    }
                    assertTrue(found);
                }
            }
        }

    }

}
