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
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.server.ldap.LdapConfig;
import ca.nrc.cadc.ac.server.ldap.LdapUserPersistence;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.Log4jInit;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.Subject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AdminIntTest
{
    private static final Logger log = Logger.getLogger(AdminIntTest.class);

    static final String EXEC_CMD = "./test/scripts/userAdminTest";

    static String testCert;
    static LdapConfig config;

    @BeforeClass
    public static void setUpClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);

        testCert = "build/test/class/cadcauthtest1.pem";
    }

//    @Test
    public void listUsers() throws Exception
    {
        String[] args = new String[] { "--list" };

        List<String> output = doTest(args, 0);

        log.debug("number users found: " + output.size());
        assertFalse("output is empty", output.isEmpty());
    }

//    @Test
    public void listPendingUsers() throws Exception
    {
        String[] args = new String[] { "--list-pending" };

        List<String> output = doTest(args, 0);

        log.debug("number pending users found: " + output.size());
        assertFalse("output is empty", output.isEmpty());
    }

//    @Test
    public void viewUser() throws Exception
    {
        String userID = "CadcAdmin-int-test-user-" + System.currentTimeMillis();
        boolean isPending = false;
        addUser(userID, isPending);
//
//        String[] args = new String[] { "--view=" + userID };
//
//        List<String> output = doTest(args, 0);
//
//        assertFalse("output is empty", output.isEmpty());
//
//        boolean found = false;
//        for (String line : output)
//        {
//            if (line.contains(userID))
//            {
//                found = true;
//            }
//        }
//        assertTrue("User not found", found);
    }

    @Test
    public void viewPendingUser() throws Exception
    {
        String userID = "CadcAdmin-int-test-user-" + System.currentTimeMillis();
        boolean isPending = true;
        addUser(userID, isPending);

        String[] args = new String[] { "--view=" + userID };

        List<String> output = doTest(args, 0);

        assertFalse("output is empty", output.isEmpty());

        boolean found = false;
        for (String line : output)
        {
            if (line.contains(userID))
            {
                found = true;
            }
        }
        assertTrue("User not found", found);
    }

//    @Test
    public void viewPendingUserNotFound() throws Exception
    {
        String userID = "foo-" + System.currentTimeMillis();

        String[] args = new String[] { "--view=" + userID };

        List<String> output = doTest(args, 1);

        assertTrue("output is empty", output.isEmpty());
    }

//    @Test
    public void approvePendingUser() throws Exception
    {
        String userID = "CadcAdmin-int-test-user-" + System.currentTimeMillis();
        boolean isPending = true;
        addUser(userID, isPending);

        String[] args = new String[] { "--approve=" + userID };

        List<String> output = doTest(args, 0);

        assertFalse("output is empty", output.isEmpty());

        boolean found = false;
        for (String line : output)
        {
            if (line.contains(userID))
            {
                found = true;
            }
        }
        assertTrue("User not approved", found);

        User<Principal> deletedUser = getUser(userID, true);
        assertNull("User found", deletedUser);

        User<Principal> approvedUser = getUser(userID, false);
        assertNotNull("User not found", approvedUser);
    }

//    @Test
    public void approvePendingUserNotFound() throws Exception
    {
        String userID = "foo-" + System.currentTimeMillis();

        String[] args = new String[] { "--approve=" + userID };

        List<String> output = doTest(args, 1);

        assertTrue("output is empty", output.isEmpty());
    }

//    @Test
    public void rejectPendingUser() throws Exception
    {
        String userID = "CadcAdmin-int-test-user-" + System.currentTimeMillis();
        boolean isPending = true;
        addUser(userID, isPending);

        String[] args = new String[] { "--reject=" + userID };

        List<String> output = doTest(args, 0);

        assertFalse("output is empty", output.isEmpty());

        boolean found = false;
        for (String line : output)
        {
            if (line.contains(userID))
            {
                found = true;
            }
        }
        assertTrue("User not rejected", found);

        User<Principal> deletedUser = getUser(userID, isPending);
        assertNull("User found", deletedUser);
    }

//    @Test
    public void rejectPendingUserNotFound() throws Exception
    {
        String userID = "foo-" + System.currentTimeMillis();

        String[] args = new String[] { "--reject=" + userID };

        List<String> output = doTest(args, 1);

        assertTrue("output is empty", output.isEmpty());
    }

    private List<String> doTest(String[] args, int expectedExitValue)
        throws IOException, InterruptedException
    {
        String[] exec = new String[args.length + 2];
        exec[0] = EXEC_CMD;
        exec[1] = "--cert=" + testCert;

        System.arraycopy(args, 0, exec, 2, args.length);
        for (int i = 0; i < exec.length; i++)
        {
            log.debug("arg[" + i + "] = " + exec[i]);
        }

        ProcessBuilder pb = new ProcessBuilder(exec);
        Process process = pb.start();

        int exitValue = process.waitFor();

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        List<String> output = new ArrayList<String>();
        String line;
        while ((line = reader.readLine()) != null)
        {
            output.add(line);
        }

        log.debug("Exit value: " + exitValue);
        assertEquals("exit value", expectedExitValue, exitValue);
        return output;
    }

    void addUser(final String userID, final boolean isPending)
        throws UserAlreadyExistsException, TransientException
    {
        log.debug("adding " + userID + ", " + isPending);
        HttpPrincipal httpPrincipal = new HttpPrincipal(userID);
        final User<Principal> expected = new User<Principal>(httpPrincipal);
        expected.getIdentities().add(httpPrincipal);

        expected.details.add(new PersonalDetails("foo", "bar"));

        final UserRequest<Principal> userRequest =
            new UserRequest<Principal>(expected, "123456".toCharArray());

        final LdapUserPersistence<Principal> userDAO = getUserPersistence();
        if (isPending)
        {
            userDAO.addPendingUser(userRequest);
        }
        else
        {
            userDAO.addUser(userRequest);
        }
    }

    User<Principal> getUser(final String username, final boolean isPending)
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
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        };

        return Subject.doAs(subject, action);
    }

    <T extends Principal> LdapUserPersistence<T> getUserPersistence()
    {
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
