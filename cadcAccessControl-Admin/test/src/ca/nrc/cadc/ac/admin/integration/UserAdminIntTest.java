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
package ca.nrc.cadc.ac.admin.integration;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.admin.ContextFactoryImpl;
import ca.nrc.cadc.ac.admin.Main;
import ca.nrc.cadc.ac.server.ldap.LdapConfig;
import ca.nrc.cadc.ac.server.ldap.LdapUserPersistence;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.util.StringUtil;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;


public class UserAdminIntTest
{
    private static final Logger log = Logger.getLogger(UserAdminIntTest.class);

    private final OutputStream output = new ByteArrayOutputStream();
    private final OutputStream error = new ByteArrayOutputStream();

    static String testCert;
    static LdapConfig config;

    @BeforeClass
    public static void setUpClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);

        testCert = System.getProperty("user.dir")
                   + "/build/test/class/cadcauthtest1.pem";

        System.setProperty(PropertiesReader.class.getName() + ".dir", "./test/");
        config = LdapConfig.getLdapConfig();
    }

    @Test
    public void listUsers() throws Exception
    {
        String[] args = new String[] { "--list" };

        doTest(args);

        log.debug("number users found: " + output.toString());
        assertTrue("output is empty", StringUtil.hasText(output.toString()));
    }

    @Test
    public void listPendingUsers() throws Exception
    {
        String[] args = new String[] { "--list-pending" };

        doTest(args);

        log.debug("number pending users found: " + output.toString());
        assertTrue("output is empty", StringUtil.hasText(output.toString()));
    }

    @Test
    public void viewUser() throws Exception
    {
        String userID = getUserID();
        boolean isPending = false;
        addUser(userID, isPending);

        String[] args = new String[] { "--view=" + userID };

        doTest(args);
        log.debug("output: " + output);

        assertTrue("output is empty", StringUtil.hasText(output.toString()));
        assertTrue("User ID not found in output.",
                   output.toString().contains(userID));
    }

    @Test
    public void viewPendingUser() throws Exception
    {
        String userID = getUserID();
        boolean isPending = true;
        addUser(userID, isPending);

        String[] args = new String[] { "--view=" + userID };

        doTest(args);
        log.debug("output: " + output);

        assertTrue("output is empty", StringUtil.hasText(output.toString()));
        assertTrue("User ID not found in output.",
                   output.toString().contains(userID));
    }

    @Test
    public void viewPendingUserNotFound() throws Exception
    {
        String userID = "foo_" + System.currentTimeMillis();

        String[] args = new String[] { "--view=" + userID };

        doTest(args);
        final String outputMessage = output.toString();
        final String errorMessage = error.toString();
        log.debug("output: " + outputMessage);

        assertTrue(outputMessage.contains("not found"));
        assertFalse("Should not have error (" + errorMessage + ")",
                    StringUtil.hasLength(errorMessage));
    }

    @Test
    public void approvePendingUser() throws Exception
    {
        String userID = getUserID();
        boolean isPending = true;
        addUser(userID, isPending);

        String[] args = new String[] { "--approve=" + userID,
                "--dn=UID=" + userID + ",OU=Users,OU=ds,DC=testcanfar"};

        doTest(args);
        log.debug("output: " + output);

        assertTrue("output is empty", StringUtil.hasText(output.toString()));
        assertTrue("User not approved.",
                   output.toString().contains("was approved"));

        // get deleted user
        getUser(userID, true, false);
        // get approved user
        getUser(userID, false, true);
    }

    @Test
    public void approvePendingUserNotFound() throws Exception
    {
        String userID = "foo_" + System.currentTimeMillis();

        String[] args = new String[] { "--approve=" + userID, 
            "--dn=UID=" + userID + ",OU=Users,OU=ds,DC=testcanfar"};

        doTest(args);

        final String outputMessage = output.toString();
        final String errorMessage = error.toString();
        log.debug("output: " + outputMessage);

        assertTrue(outputMessage.contains("not find pending user"));
        assertFalse("Should not have error (" + errorMessage + ")",
                    StringUtil.hasLength(errorMessage));
    }

    @Test
    public void rejectPendingUser() throws Exception
    {
        String userID = getUserID();
        boolean isPending = true;
        addUser(userID, isPending);

        String[] args = new String[] { "--reject=" + userID };

        doTest(args);

        final String outputMessage = output.toString();
        final String errorMessage = error.toString();
        log.debug("output: " + outputMessage);

        assertTrue("Should contain was rejected.",
                   outputMessage.contains("was rejected"));
        assertFalse("Should not have error (" + errorMessage + ")",
                    StringUtil.hasLength(errorMessage));

        getUser(userID, isPending, false);
    }

    @Test
    public void rejectPendingUserNotFound() throws Exception
    {
        String userID = "foo_" + System.currentTimeMillis();

        String[] args = new String[] { "--reject=" + userID };

        doTest(args);

        final String outputMessage = output.toString();
        final String errorMessage = error.toString();
        log.debug("output: " + outputMessage);

        assertTrue(outputMessage.contains("not found"));
        assertFalse("Should not have error (" + errorMessage + ")",
                    StringUtil.hasLength(errorMessage));
    }

    String getUserID()
    {
        return "CadcAdminIntTestUser-" + System.currentTimeMillis();
    }

    void doTest(String[] args) throws Exception
    {
        final String[] programArgs = new String[args.length + 1];
        System.arraycopy(args, 0, programArgs, 0, args.length);
        programArgs[programArgs.length - 1] = "--cert=" + testCert;

        final Main testSubject = new Main(new PrintStream(output),
                                          new PrintStream(error));
        testSubject.execute(programArgs);
    }

    void addUser(final String username, final boolean isPending)
        throws UserAlreadyExistsException, TransientException,
                PrivilegedActionException
    {
        final HttpPrincipal userID = new HttpPrincipal(username);

        String dn = "uid=" + username + "," + config.getUsersDN();
        X500Principal x500Principal = new X500Principal(dn);

        final User<Principal> expected = new User<Principal>(userID);
        expected.getIdentities().add(userID);
        expected.getIdentities().add(x500Principal);

        PersonalDetails pd = new PersonalDetails("foo", "bar");
        pd.email = username + "@canada.ca";                                      
        expected.details.add(pd);

        final UserRequest<Principal> userRequest =
            new UserRequest<Principal>(expected, "123456".toCharArray());

        Subject subject = new Subject();
        subject.getPrincipals().add(userID);
        subject.getPrincipals().add(getDNPrincipal(username, isPending));

        PrivilegedExceptionAction<Object> action =
            new PrivilegedExceptionAction<Object>()
            {
                public Object run()
                    throws Exception
                {
                    try
                    {
                        final LdapUserPersistence<Principal> userDAO = getUserPersistence();
                        if (isPending)
                        {
                            userDAO.addPendingUser(userRequest);
                            log.debug("added pending user: " + username);
                        }
                        else
                        {
                            userDAO.addUser(userRequest);
                            log.debug("added user: " + username);
                        }
                        return null;
                    }
                    catch (Exception e)
                    {
                        log.error("Exception adding user: " + e.getMessage());
                        throw new Exception("Problems", e);
                    }
                }
            };

        Subject.doAs(subject, action);
    }

    User<Principal> getUser(final String username, final boolean isPending,
                            final boolean expectedFound)
        throws PrivilegedActionException
    {
        final HttpPrincipal userID = new HttpPrincipal(username);

        Subject subject = new Subject();
        subject.getPrincipals().add(userID);
        subject.getPrincipals().add(getDNPrincipal(username, isPending));

        PrivilegedExceptionAction<User<Principal>> action =
            new PrivilegedExceptionAction<User<Principal>>()
        {
            public User<Principal> run()
                throws Exception
            {
                try
                {
                    final LdapUserPersistence<Principal> userDAO = getUserPersistence();
                    if (isPending)
                    {
                        return userDAO.getPendingUser(userID);
                    }
                    else
                    {
                        return userDAO.getUser(userID);
                    }
                }
                catch (UserNotFoundException e)
                {
                    if (expectedFound)
                    {
                        throw e;
                    }
                }
                return null;
            }
        };

        return Subject.doAs(subject, action);
    }

    <T extends Principal> LdapUserPersistence<T> getUserPersistence()
    {
        System.setProperty("java.naming.factory.initial", ContextFactoryImpl.class.getName());
        return new LdapUserPersistence<T>();
    }

    DNPrincipal getDNPrincipal(final String username, final boolean isPending)
    {
        String entryDN = "uid=" + username + ",";
        if (isPending)
        {
            entryDN = entryDN + config.getUserRequestsDN();
        }
        else
        {
            entryDN = entryDN + config.getUsersDN();
        }

        return new DNPrincipal(entryDN);
    }

}
