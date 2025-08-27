/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2025.                            (c) 2025.
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

package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.client.GMSClient;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.opencadc.gms.GroupURI;


public class GmsClientIntTest
{
    private static final Logger log = Logger.getLogger(GmsClientIntTest.class);

    private static final String unknownDN = "cn=foo,o=bar";

    private User u1User;
    private User u2User;
    private User u3User;
    private User unknownUser;
    private Group unknownGroup;

    private Subject u1Subject;
    private Subject u2Subject;
    private Subject u3Subject;

    private URI serviceURI = URI.create("ivo://cadc.nrc.ca/gms");
    private GMSClient gmsClient;

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    public GmsClientIntTest()
    {
        try
        {
            File user1 = FileUtil
                    .getFileFromResource("user1.pem", GmsClientIntTest.class);
            File user2 = FileUtil
                    .getFileFromResource("user2.pem", GmsClientIntTest.class);
            File user3 = FileUtil
                    .getFileFromResource("user3.pem", GmsClientIntTest.class);
            u1Subject = SSLUtil.createSubject(user1);
            u2Subject = SSLUtil.createSubject(user2);
            u3Subject = SSLUtil.createSubject(user3);

            String user1DN = u1Subject.getPrincipals()
                    .iterator().next().getName();
            String user2DN = u2Subject.getPrincipals()
                    .iterator().next().getName();
            String user3DN = u3Subject.getPrincipals()
                    .iterator().next().getName();

            u1User = new User();
            u1User.getIdentities().add(new X500Principal(user1DN));
            u2User = new User();
            u2User.getIdentities().add(new X500Principal(user2DN));
            u3User = new User();
            u3User.getIdentities().add(new X500Principal(user3DN));

            unknownUser = new User();
            unknownUser.getIdentities().add(new X500Principal(unknownDN));
            unknownGroup = new Group(new GroupURI("ivo://cadc.nrc.ca/gms?foo"));

            log.info("serviceURI: " + serviceURI);
            this.gmsClient = new GMSClient(serviceURI);
        }
        catch (Exception unexpected)
        {
            log.error("setup failure", unexpected);
            throw new RuntimeException("setup failure", unexpected);
        }
    }

    @Test
    public void testCRUD() throws Exception
    {
        /**
         * createGroup tests
         */

        // Group with unknown user
        final GroupURI groupID1 = getGroupID("group1");

        // Group with a known user
        Group expectedGroup = new Group(groupID1);
        expectedGroup.description = "test description";

        // test createGroup
        Group actualGroup = createGroupAs(expectedGroup, u1Subject);
        assertEquals(expectedGroup, actualGroup);

        // test GroupAlreadyExistsException
        try
        {
            createGroupAs(expectedGroup, u1Subject);
            fail("existing group should throw GroupAlreadyExistsException");
        }
        catch (GroupAlreadyExistsException e)
        {
            // Good!
        }

        /**
         * getGroup tests
         */

        // test AccessControlException
        try
        {
            gmsClient.getGroup(expectedGroup.getID().getName());
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException when user has not access to the group
        try
        {
            getGroupAs(expectedGroup.getID().getName(), u2Subject);
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException when group does not exist
        try
        {
            getGroupAs("foo", u1Subject);
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        // test getGroup
        actualGroup = getExistingGroupWithDelay(groupID1.getName(), u1Subject);
        assertEquals(expectedGroup, actualGroup);

        /**
         * updateGroup tests
         */

        // Update the test group
        expectedGroup.description = "new test description";

        // test AccessControlException
        try
        {
            gmsClient.updateGroup(expectedGroup);
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        try
        {
            updateGroupAs(expectedGroup, u2Subject);
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException
        try
        {
            updateGroupAs(unknownGroup, u1Subject);
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }


        // Update the base test group
        expectedGroup.getGroupMembers().remove(expectedGroup);
        actualGroup = updateGroupAs(expectedGroup, u1Subject);
        assertEquals(expectedGroup, actualGroup);

        /**
         * addGroupMember tests
         */

        // Create a GroupMember group
        final GroupURI groupMemberID = getGroupID("groupMember");
        Group groupMember = new Group(groupMemberID);
        groupMember = createGroupAs(groupMember, u1Subject);

        // test AccessControlException
        try
        {
            gmsClient.addGroupMember(expectedGroup.getID().getName(),
                                                groupMember.getID().getName());
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        try
        {
            addGroupMemberAs(expectedGroup.getID().getName(),
                             groupMember.getID().getName(),
                    u2Subject);
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException
        try
        {
            addGroupMemberAs(expectedGroup.getID().getName(),
                             unknownGroup.getID().getName(),
                    u1Subject);
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        try
        {
            addGroupMemberAs(unknownGroup.getID().getName(),
                             groupMember.getID().getName(),
                    u1Subject);
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        // test addGroupMember
        addGroupMemberAs(expectedGroup.getID().getName(),
                         groupMember.getID().getName(),
                u1Subject);
        expectedGroup.getGroupMembers().add(groupMember);
        actualGroup = getNonEmptyGroupWithDelay(expectedGroup.getID().getName(),
                u1Subject);
        assertEquals(expectedGroup, actualGroup);

        /**
         * removeGroupMember tests
         */

        // test AccessControlException
        try
        {
            gmsClient.removeGroupMember(expectedGroup.getID().getName(),
                                                   groupMember.getID().getName());
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        try
        {
            removeGroupMemberAs(u2Subject,
                                expectedGroup.getID().getName(),
                                groupMember.getID().getName());
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException
        try
        {
            removeGroupMemberAs(u1Subject,
                                expectedGroup.getID().getName(),
                                unknownGroup.getID().getName());
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        try
        {
            removeGroupMemberAs(u1Subject,
                                unknownGroup.getID().getName(),
                                groupMember.getID().getName());
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        // test removeGroupMember
        removeGroupMemberAs(u1Subject,
                            expectedGroup.getID().getName(),
                            groupMember.getID().getName());
        expectedGroup.getGroupMembers().remove(groupMember);
        actualGroup = getEmptyGroupWithDelay(expectedGroup.getID().getName(),
                u1Subject);
        assertEquals(expectedGroup, actualGroup);

        /**
         * addUserMember tests
         */

        // test AccessControlException
        try
        {
            gmsClient.addUserMember(expectedGroup.getID().getName(),
                                               u1User.getIdentities().iterator().next());
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        try
        {
            addUserMemberAs(expectedGroup.getID().getName(),
                            u1User.getIdentities().iterator().next(),
                    u2Subject);
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException
        try
        {
            addUserMemberAs(unknownGroup.getID().getName(),
                            u1User.getIdentities().iterator().next(),
                    u1Subject);
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        // test addUserMember
        addUserMemberAs(expectedGroup.getID().getName(),
                        u1User.getIdentities().iterator().next(),
                u1Subject);
        expectedGroup.getUserMembers().add(u1User);
        actualGroup = getNonEmptyGroupWithDelay(expectedGroup.getID().getName(),
                u1Subject);
        assertEquals(expectedGroup, actualGroup);

        /**
         * removeUserMember tests
         */

        // test AccessControlException
        try
        {
            gmsClient.removeUserMember(expectedGroup.getID().getName(),
                                                  u1User.getIdentities().iterator().next());
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        try
        {
            removeUserMemberAs(u2Subject, expectedGroup.getID().getName(),
                                      u1User.getIdentities().iterator().next());
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException
        try
        {
            removeUserMemberAs(u1Subject, unknownGroup.getID().getName(),
                                      u1User.getIdentities().iterator().next());
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        // test removeUserMember
        removeUserMemberAs(u1Subject, expectedGroup.getID().getName(),
                                  u1User.getIdentities().iterator().next());
        expectedGroup.getUserMembers().remove(u1User);
        actualGroup = getEmptyGroupWithDelay(expectedGroup.getID().getName(),
                u1Subject);
        assertEquals(expectedGroup, actualGroup);

        /**
         * test deleteGroup
         */

        // test AccessControlException
        try
        {
            gmsClient.deleteGroup(expectedGroup.getID().getName());
            fail("anonymous client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        try
        {
            deleteGroupAs(expectedGroup.getID().getName(),
                    u2Subject, false);
            fail("unauthorized client should throw AccessControlException");
        }
        catch (AccessControlException e)
        {
            // Good!
        }

        // test GroupNotFoundException
        try
        {
            deleteGroupAs(unknownGroup.getID().getName(), u1Subject, false);
            fail("unkown group should throw GroupNotFoundException");
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }

        // test deleteGroup
        deleteGroupAs(expectedGroup.getID().getName(), u1Subject, true);
        try
        {
            getGroupAs(expectedGroup.getID().getName(), u1Subject);
            fail("deleteGroup did not delete the group " + expectedGroup
                    .getID());
        }
        catch (GroupNotFoundException e)
        {
            // Good!
        }
    }


    @Test
    public void testAddMembers()
    {
        final String groupName = "testAddGroupMembers-"
                                 + System.currentTimeMillis();

        try
        {
            // create a group with user 1
            GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + groupName);
            Group group = new Group(gURI);
            group.getUserMembers().add(u1User);
            createGroupAs(group, u1Subject);

            group.getUserMembers().add(u3User);
            final Principal principal =
                    this.u3User.getIdentities().iterator().next();

            Subject.doAs(u1Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    // try several times
                    int n = 1;
                    boolean success = false;
                    while (!success && n < 10) {
                        try {
                            // add delay to compensate for eventual consistency of
                            // content in multiple ldap hosts
                            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                            gmsClient.addUserMember(groupName, principal);
                            success = true;
                        } catch (Exception ex) {
                            n++;
                        }
                    }
                    return null;
                }
            });

            group = getNonEmptyGroupWithDelay(groupName, u1Subject);
            Assert.assertTrue(group.getUserMembers().size() == 2);
            Assert.assertTrue(group.getUserMembers().contains(u1User));
            Assert.assertTrue(group.getUserMembers().contains(u3User));

        }
        catch (Exception e)
        {
            log.error("Unexpected exception", e);
            Assert.fail("Unexpected exception: " + e.getMessage());
        }
        finally
        {
            try
            {
                deleteGroupAs(groupName, u1Subject, true);
            }
            catch (Exception e)
            {
                log.warn("Could not delete test group: " + groupName);
            }
        }
    }

    @Test
    public void testAdminUserPrivilegesViaUpdateNonPersistentGroup()
            throws Exception
    {
        final String groupName = "testAdminUserPrivileges-"
                                 + System.currentTimeMillis();

        try
        {
            // create a group with user 1
            GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + groupName);
            Group group = new Group(gURI);
            createGroupAs(group, u1Subject);

            // add user 2 as administrator to the group
            group = getExistingGroupWithDelay(groupName, u1Subject);
            group.getUserAdmins().add(u2User);
            group = updateGroupAs(group, u1Subject);

            // do a search and make sure the user has admin privileges
            Subject.doAs(u2Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    int n = 1;
                    boolean success = false;
                    while (!success && n < 10) {
                        try {
                            // add delay to compensate for 
                            // eventual consistency of
                            // content in multiple ldap hosts
                            // try it several times
                            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                            boolean isMember = gmsClient.isMember(groupName, Role.ADMIN);
                            Assert.assertTrue("not an admin", isMember);
                            success = true;
                        } catch (AccessControlException ex) {
                            throw ex;
                        } catch (Exception ex) {
                            n++;
                        }
                    }

                    return null;
                }
            });


            // ensure user 2 has read-write privileges
            group.getUserMembers().add(u2User);
            group = updateGroupAs(group, u2Subject);
            Assert.assertNotNull("group is null", group);

        }
        finally
        {
            try
            {
                deleteGroupAs(groupName, u1Subject, true);
            }
            catch (Exception e)
            {
                log.warn("Could not delete test group: " + groupName);
            }
        }
    }

    @Test
    public void testAdminUserPrivilegesViaUpdate() throws Exception
    {
        final String groupName = "testAdminUserPrivileges-" + System
                .currentTimeMillis();

        try
        {
            // create a group with user 1
            GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + groupName);
            Group group = new Group(gURI);
            createGroupAs(group, u1Subject);

            // add user 2 as administrator to the group
            group = getExistingGroupWithDelay(groupName, u1Subject);
            group.getUserAdmins().add(u2User);
            updateGroupAs(group, u1Subject);

            // do a search and make sure the user has admin privileges
            Subject.doAs(u2Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    int n = 1;
                    boolean success = false;
                    while (!success && n < 10) {
                        try {
                            // add delay to compensate for 
                            // eventual consistency of
                            // content in multiple ldap hosts
                            // try it several times
                            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                            boolean isMember = gmsClient.isMember(groupName, Role.ADMIN);
                            Assert.assertTrue("not an admin", isMember);
                            success = true;
                        } catch (AccessControlException ex) {
                            throw ex;
                        } catch (Exception ex) {
                            n++;
                        }
                    }

                    return null;
                }
            });

            group = getNonEmptyGroupWithDelay(groupName, u2Subject);
            Assert.assertEquals("admin count", 1, group.getUserAdmins().size());
            log.debug("Group admin 1 after update: " + group.getUserAdmins()
                    .iterator().next());

            // ensure user 2 has read-write privileges
            group.getUserMembers().add(u2User); // add self
            group = updateGroupAs(group, u2Subject);
            Assert.assertNotNull("group is null", group);

        }
        finally
        {
            try
            {
                deleteGroupAs(groupName, u1Subject, true);
            }
            catch (Exception e)
            {
                log.warn("Could not delete test group: " + groupName);
            }
        }
    }

    @Test
    public void testAdminUserPrivilegesViaAdd() throws Exception
    {
        final String groupName = "testAdminUserPrivileges-" + System
                .currentTimeMillis();

        try
        {
            

            GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + groupName);
            Group group = new Group(gURI);
            
            // create a group with user 1
            createGroupAs(group, u1Subject);

            // add user 2 as administrator to the group
            group = getExistingGroupWithDelay(groupName, u1Subject);
            group.getUserAdmins().add(u2User);
            updateGroupAs(group, u1Subject);

            // do a search and make sure the user has admin privileges
            Subject.doAs(u2Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    int n = 1;
                    boolean success = false;
                    while (!success && n < 10) {
                        try {
                            // add delay to compensate for 
                            // eventual consistency of
                            // content in multiple ldap hosts
                            // try it several times
                            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                            boolean isMember = gmsClient.isMember(groupName, Role.ADMIN);
                            Assert.assertTrue("not an admin", isMember);
                            success = true;
                        } catch (AccessControlException ex) {
                            throw ex;
                        } catch (Exception ex) {
                            n++;
                        }
                    }
                    
                    return null;
                }
            });

            group = getNonEmptyGroupWithDelay(groupName, u2Subject);
            Assert.assertEquals("admin count", 1,
                                group.getUserAdmins().size());
            log.debug("Group admin 1 after update: " + group.getUserAdmins()
                    .iterator().next());

            // changed subject from 2->1
            Subject.doAs(u1Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    // ensure user 2 has read-write privileges
                    // chanmged arg from 1->2
                    gmsClient.addUserMember(groupName, u2User.getIdentities().iterator().next());
                    return null;
                }
            });
        }
//        catch (Exception e)
//        {
//            log.error("Unexpected exception", e);
//            Assert.fail("Unexpected exception: " + e.getMessage());
//        }
        finally
        {
            try
            {
                deleteGroupAs(groupName, u1Subject, true);
            }
            catch (Exception e)
            {
                log.warn("Could not delete test group: " + groupName);
            }
        }
    }

    @Test
    public void testAdminGroupPrivilegesViaUpdate() throws Exception
    {
        final String groupName1 = "testAdminGroupPrivileges1-" + System
                .currentTimeMillis();
        final String groupName2 = "testAdminGroupPrivileges2-" + System
                .currentTimeMillis();

        try
        {
            // create a group with user 1
            log.debug("create group1");
            GroupURI gURI1 = new GroupURI(serviceURI.toString() + "?" + groupName1);
            Group group1 = new Group(gURI1);
            log.debug("create group " + group1);
            createGroupAs(group1, u1Subject);
            group1 = getExistingGroupWithDelay(groupName1, u1Subject);
            Assert.assertEquals("num members", 0, group1.getUserMembers().size());

            // create an admin group with user 1
            GroupURI gURI2 = new GroupURI(serviceURI.toString() + "?" + groupName2);
            Group group2 = new Group(gURI2);
            log.debug("create 2nd group " + group2);
            createGroupAs(group2, u1Subject);

            // add user 2 as member of group2
            group2 = getExistingGroupWithDelay(groupName2, u1Subject);
            group2.getUserMembers().add(u2User);
            log.debug("add auth2 as member of group2");
            updateGroupAs(group2, u1Subject);
            group1 = getExistingGroupWithDelay(groupName1, u1Subject);

            // add group 2 as an administrative group to group 1
            group2 = getExistingGroupWithDelay(groupName2, u1Subject);
            group1.getGroupAdmins().add(group2);
            log.debug("add group2 to group1 admin groups");
            updateGroupAs(group1, u1Subject);

            // do a search and make sure the user has admin privileges
            log.debug("check auth2 as member of group2 is an admin of group1");
            Subject.doAs(u2Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    int n = 1;
                    boolean success = false;
                    while (!success && n < 10) {
                        try {
                            // add delay to compensate for 
                            // eventual consistency of
                            // content in multiple ldap hosts
                            // try it several times
                            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                            boolean isMember = gmsClient.isMember(groupName1, Role.ADMIN);
                            Assert.assertTrue("not an admin", isMember);
                            success = true;
                        } catch (AccessControlException ex) {
                            throw ex;
                        } catch (Exception ex) {
                            n++;
                        }
                    }
                    return null;
                }
            });

            // ensure user 2 has read-write privileges
            group1 = getExistingGroupWithDelay(groupName1, u2Subject); // read
            log.debug("group1 group admins: " + Collections.singletonList(group1.getGroupAdmins()));
            group1.getUserMembers().add(u2User); // add self
            log.debug("as auth2 add auth2 as member of group1");
            updateGroupAs(group1, u2Subject); // write

            // verify that a admin user can update (despite not having read permission on an admin group)
            group1 = getNonEmptyGroupWithDelay(groupName1, u2Subject);
            group1.getUserMembers().add(u1User); // yeah, add the owner as a member
            log.debug("as auth2 add auth1 as member to group1");
            updateGroupAs(group1, u2Subject);

            group1 = getNonEmptyGroupWithDelay(groupName1, u2Subject);
            Assert.assertEquals("num members", 2, group1.getUserMembers().size());

        }
        finally
        {
            try
            {
                deleteGroupAs(groupName1, u1Subject, true);
                // delay already done by the previous statement
                deleteGroupAs(groupName2, u1Subject, false);
            }
            catch (Exception e)
            {
                log.warn("Could not delete test groups.");
            }
        }
    }

    @Test
    public void testAdminGroupPrivilegesViaAdd() throws Exception
    {
        final String groupName1 = "testAdminGroupPrivileges1-" + System
                .currentTimeMillis();
        final String groupName2 = "testAdminGroupPrivileges2-" + System
                .currentTimeMillis();

        try
        {
            GroupURI gURI1 = new GroupURI(serviceURI.toString() + "?" + groupName1);
            Group group = new Group(gURI1);
            createGroupAs(group, u1Subject);

            // create an admin group with user 1
            GroupURI gURI2 = new GroupURI(serviceURI.toString() + "?" + groupName2);
            group = new Group(gURI2);
            createGroupAs(group, u1Subject);

            // add user 2 as member of group2
            group = getExistingGroupWithDelay(groupName2, u1Subject);
            group.getUserMembers().add(u2User);
            updateGroupAs(group, u1Subject);

            // add group 2 as an administrative group to group 1
            Group group1 = getExistingGroupWithDelay(groupName1, u1Subject);
            Group group2 = getNonEmptyGroupWithDelay(groupName2, u1Subject);
            group1.getGroupAdmins().add(group2);
            updateGroupAs(group1, u1Subject);

            // do a search and make sure the user has admin privileges
            Subject.doAs(u2Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    int n = 1;
                    boolean success = false;
                    while (!success && n < 10) {
                        try {
                            // add delay to compensate for 
                            // eventual consistency of
                            // content in multiple ldap hosts
                            // try it several times
                            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                            boolean isMember = gmsClient.isMember(groupName1, Role.ADMIN);
                            Assert.assertTrue("not an admin", isMember);
                            success = true;
                        } catch (AccessControlException ex) {
                            throw ex;
                        } catch (Exception ex) {
                            n++;
                        }
                    }
                    return null;
                }
            });

            // ensure user 2 has read-write privileges
            // changed 2->1
            Subject.doAs(u1Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    // changed 1->2
                    gmsClient.addUserMember(groupName1, u2User.getIdentities().iterator().next()); // add self??
                    return null;
                }
            });

            group = getNonEmptyGroupWithDelay(groupName1, u2Subject);
            Assert.assertTrue("no memembers", group.getUserMembers()
                                                      .size() > 0);

        }
        finally
        {
            try
            {
                deleteGroupAs(groupName1, u1Subject, true);
                deleteGroupAs(groupName2, u1Subject, true);
            }
            catch (Exception e)
            {
                log.warn("Could not delete test groups.");
            }
        }
    }

    // this version number is used in the testSearchSetup method so previous setup of groups can
    // be safely re-used; if the structure changes, update this value!!!
    private static final long setupVersionNumber = 20211123140000L;

    private static final int NUM_SEARCH_GROUPS = 3;

    @Test
    public void testSearchSetup() throws Exception
    {
        doSearchSetup(true); // for jmeter load-test usage
    }

    private void jmeterSetup(boolean force) {
        if (!force)
        {
            String s = System
                    .getProperty(GmsClientIntTest.class.getName() + ".jmeter");
            if (s != null && "true".equals(s))
            {
                return; // jmeter tests call testSearchSetup once first
            }
        }
    }

    private void verifySearchSetup(String testGroupID) throws Exception {
        // verify setup
        Group testGroup = getExistingGroupWithDelay(testGroupID, u1Subject);
        Assert.assertNotNull(testGroup);
        Principal p1 = u1User.getIdentities().iterator().next();
        Principal p2 = testGroup.getOwner().getIdentities(X500Principal.class).iterator().next();
        Assert.assertTrue(AuthenticationUtil.equals(p1, p2));
        boolean containsAuthtest1 = false;
        boolean containsAuthtest2 = false;
        for (User u : testGroup.getUserMembers())
        {
            if (u1User.isConsistent(u))
                containsAuthtest1 = true;
            if (u2User.isConsistent(u))
                containsAuthtest2 = true;
        }
        Assert.assertTrue(containsAuthtest1);
        Assert.assertTrue(containsAuthtest2);

        Set<Group> adminGroups = testGroup.getGroupAdmins();
        Assert.assertNotNull(adminGroups);
        Assert.assertEquals(1, adminGroups.size());
        Group adminGroup = adminGroups.iterator().next();
        // previous get is not recursive
        adminGroup = getNonEmptyGroupWithDelay(adminGroup.getID().getName(),
                u1Subject);
        containsAuthtest1 = false;
        containsAuthtest2 = false;
        for (User u : adminGroup.getUserMembers())
        {
            if (u1User.isConsistent(u))
                containsAuthtest1 = true;
            if (u2User.isConsistent(u))
                containsAuthtest2 = true;
        }
        Assert.assertTrue(containsAuthtest1);
        Assert.assertTrue(containsAuthtest2);

        log.debug("testSearchSetup: " + testGroup.getID() + " verified");
    }

    private void doSearchSetup(boolean force) throws Exception
    {
        jmeterSetup(force);

        // this "test" makes sure some fixed test content available for testSearch
        // u1 is the owner and member
        // u2 is a member
        // u3 is not a member
        for (int i = 1; i <= NUM_SEARCH_GROUPS; i++) // create multiple test group structures
        {
            // test groups
            String id = Long.toString(setupVersionNumber + i);
            final String testGroupID = getGroupID("testSearch-test-group", id);
            final String adminGroupID = getGroupID("testSearch-admin-group", id);
            boolean hasTestGroup = false;
            boolean hasAdminGroup = false;

            try {
                // search for the group created above
                Group testGroup = getExistingGroupWithDelay(testGroupID, u1Subject);
                if (testGroup == null) {
                    // admin group
                    String agID = getGroupID("testSearch-admin-group", id);
                    GroupURI agURI = new GroupURI(serviceURI.toString() + "?" + agID);
                    Group adminGroup = new Group(agURI);
                    adminGroup.getUserMembers().add(u1User);
                    adminGroup.getUserMembers().add(u2User);
                    adminGroup = createGroupAs(adminGroup, u1Subject);
                    Assert.assertNotNull(adminGroup);
                    hasAdminGroup = true;
                    log.debug("testSearchSetup: created " + adminGroup.getID());

                    // test group
                    GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + testGroupID);
                    testGroup = new Group(gURI);
                    testGroup.getGroupAdmins().add(adminGroup);
                    testGroup.getUserMembers().add(u1User);
                    testGroup.getUserMembers().add(u2User);
                    testGroup = createGroupAs(testGroup, u1Subject);
                    log.debug("testSearchSetup: " + testGroup.getID() + " created");
                    Assert.assertNotNull(testGroup);
                    hasTestGroup = true;
                    log.debug("testSearchSetup: " + testGroupID + " exists");
                } else {
                    hasTestGroup = true;
                    hasAdminGroup = true;
                }

                // verify setup
                verifySearchSetup(testGroupID);
            } finally {
                try
                {
                    if (hasTestGroup) {
                        deleteGroupAs(testGroupID, u1Subject, true);
                    }
                    if (hasAdminGroup) {
                        deleteGroupAs(adminGroupID, u1Subject, true);
                    }
                }
                catch (Exception e)
                {
                    log.warn("Could not delete test group: " + testGroupID);
                }
            }
        }
    }


    @Test
    public void testSearch() throws Exception
    {
        jmeterSetup(false);

        // this "test" makes sure some fixed test content available for testSearch
        // u1 is the owner and member
        // u2 is a member
        // u3 is not a member
        Boolean[] hasTestGroup = new Boolean[NUM_SEARCH_GROUPS]; 
        Boolean[] hasAdminGroup = new Boolean[NUM_SEARCH_GROUPS];
        for (int i = 1; i <= NUM_SEARCH_GROUPS; i++) // create multiple test group structures
        {                             
            hasTestGroup[i-1] = false; 
            hasAdminGroup[i-1] = false;
        }

        try {                                                                                    
            for (int i = 1; i <= NUM_SEARCH_GROUPS; i++) // create multiple test group structures
            {                                                                      
                // test groups                                                       
                String id = Long.toString(setupVersionNumber + i);                   
                final String testGroupID = getGroupID("testSearch-test-group", id);  
                final String adminGroupID = getGroupID("testSearch-admin-group", id);          
                                                                                               
                // search for the group created above                                          
                Group testGroup = getExistingGroupWithDelay(testGroupID, u1Subject);
                if (testGroup == null) {                                              
                    // admin group                                                    
                    String agID = getGroupID("testSearch-admin-group", id);           
                    GroupURI agURI = new GroupURI(serviceURI.toString() + "?" + agID);
                    Group adminGroup = new Group(agURI);                         
                    adminGroup.getUserMembers().add(u1User);
                    adminGroup.getUserMembers().add(u2User);
                    adminGroup = createGroupAs(adminGroup, u1Subject);
                    Assert.assertNotNull(adminGroup);                           
                    hasAdminGroup[i-1] = true;                                  
                    log.debug("testSearchSetup: created " + adminGroup.getID());            
                                                                                            
                    // test group                                                           
                    GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + testGroupID);
                    testGroup = new Group(gURI);                      
                    testGroup.getGroupAdmins().add(adminGroup);                
                    testGroup.getUserMembers().add(u1User);
                    testGroup.getUserMembers().add(u2User);
                    testGroup = createGroupAs(testGroup, u1Subject);
                    log.debug("testSearchSetup: " + testGroup.getID() + " created");
                    Assert.assertNotNull(testGroup);                         
                    hasTestGroup[i-1] = true;                                
                    log.debug("testSearchSetup: " + testGroupID + " exists");
                } else {                      
                    hasTestGroup[i-1] = true; 
                    hasAdminGroup[i-1] = true;            
                }                                         
                                                          
                verifySearchSetup(testGroupID);
            }

            // we will target searches at one test group
            Random rnd = new Random();
            int idx = rnd.nextInt(NUM_SEARCH_GROUPS) + 1;
            String id = Long.toString(setupVersionNumber + idx);
            String testGroupID = getGroupID("testSearch-test-group", id);
            String adminGroupID = getGroupID("testSearch-admin-group", id);
    
            // search by role: owner
            Collection<Group> groups = getMembershipsAs(Role.OWNER, u1Subject);
            assertNotNull(groups);
            assertFalse(groups.isEmpty());
    
            // search by role: admin
            groups = getMembershipsAs(Role.ADMIN, u2Subject);
            assertNotNull(groups);
            assertFalse(groups.isEmpty());
            
            // search by role: member
            groups = getMembershipsAs(Role.MEMBER, u2Subject);
            assertNotNull(groups);
            assertFalse(groups.isEmpty());
    
            // search that returns nothing
            groups = getMembershipsAs(Role.MEMBER, u3Subject);
            assertNotNull(groups);
            assertTrue("found " + groups.size() + " expected 0", groups.isEmpty());
    
            // assert owner
            Group group = getMembershipAs(testGroupID, Role.OWNER, u1Subject);
            assertNotNull(group);
            assertEquals(testGroupID, group.getID().getName());
    
            // assert admin
            group = getMembershipAs(testGroupID, Role.ADMIN, u2Subject);
            assertNotNull(group);
            assertEquals(testGroupID, group.getID().getName());
    
            // assert membership: u1
            group = getMembershipAs(testGroupID, Role.MEMBER, u1Subject);
            assertNotNull(group);
            assertEquals(testGroupID, group.getID().getName());
    
            // assert membership: u2
            group = getMembershipAs(testGroupID, Role.MEMBER, u2Subject);
            assertNotNull(group);
            assertEquals(testGroupID, group.getID().getName());
        } finally {
            for (int i = 1; i <= NUM_SEARCH_GROUPS; i++) // create multiple test group structures
            {
                String id = Long.toString(setupVersionNumber + i);
                final String testGroupID = getGroupID("testSearch-test-group", id);
                final String adminGroupID = getGroupID("testSearch-admin-group", id);
                try
                {
                    if (hasTestGroup[i-1]) {
                        deleteGroupAs(testGroupID, u1Subject, true);
                    }
                    if (hasAdminGroup[i-1]) {
                        deleteGroupAs(adminGroupID, u1Subject, true);
                    }
                }
                catch (Exception e)
                {
                    log.warn("Could not delete test group: " + testGroupID);
                }
            }
        }
    }

    @Test
    public void testSearchGroupNotFound() throws Exception
    {
        String nonExistentGroupID = "nonExistentGroup-" + UUID.randomUUID().toString();

        // non existent group
        Group g = getMembershipAs(nonExistentGroupID, Role.OWNER,
                u3Subject);
        Assert.assertNull(g);

        // not a member
        g = getMembershipAs("CADC", Role.MEMBER, u3Subject);
        Assert.assertNull(g);
    }



    @Test
    public void testSearchPermissionDenied() throws Exception
    {
        doSearchSetup(false);

        // anon query
        try
        {
            gmsClient.getMemberships(Role.MEMBER);
            fail("expected AccessControlException");
        }
        catch (AccessControlException e)
        {
            log.debug("caught expected exception : " + e);
        }
    }

    @Test
    public void testAnonGroupNameSearch() throws Exception
    {
        try
        {
            gmsClient.getGroupNames();
            fail("expected AccessControlException");
        }
        catch(AccessControlException expected)
        {
            log.debug("caught expected: " + expected);
        }
    }

    @Test
    public void testAuthGroupNameSearch() throws Exception
    {
        Collection<String> groupNames =
                Subject.doAs(u3Subject,
                             new PrivilegedExceptionAction<Collection<String>>()
        {
            @Override
            public Collection<String> run() throws Exception
            {
                return gmsClient.getGroupNames();
            }
        });

        assertNotNull(groupNames);
        assertFalse(groupNames.isEmpty());
        assertTrue(groupNames.size() > 0);
    }

    @Test
    public void testListGroupsAnonymous()
    {
        try
        {
            try
            {
                gmsClient.getGroupNames();
                Assert.fail("Should have received access control exception");
            }
            catch (AccessControlException e)
            {
                // expected
            }
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testListGroupsAnonCert()
    {
        try
        {
            File file = FileUtil.getFileFromResource("anonuser.pem", GmsClientIntTest.class);
            Subject s = SSLUtil.createSubject(file);
            try
            {
                Subject.doAs(s, new PrivilegedExceptionAction<Object>()
                {
                    @Override
                    public Object run() throws Exception
                    {
                        try
                        {
                            gmsClient.getGroupNames();
                            throw new Exception("Should have received access control exception");
                        }
                        catch (AccessControlException e)
                        {
                            // expected
                            return null;
                        }
                    }
                });
            }
            catch (Exception e)
            {
                log.error("test failed", e);
                Assert.fail(e.getMessage());
            }
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testListGroupsWithAccount()
    {
        try
        {
            Subject.doAs(u1Subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    gmsClient.getGroupNames();
                    // the above should work
                    return null;
                }
            });
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testCreateGroupAnonCert()
    {
        try
        {
            File file = FileUtil.getFileFromResource("anonuser.pem", GmsClientIntTest.class);
            Subject s = SSLUtil.createSubject(file);
            try
            {
                Subject.doAs(s, new PrivilegedExceptionAction<Object>()
                {
                    @Override
                    public Object run() throws Exception
                    {
                        boolean actuallyCreated = false;
                        String groupName = "gmsClientTest-" + System.currentTimeMillis() + "1";
                        try
                        {
                            GroupURI gURI = new GroupURI(serviceURI.toString() + "?" + groupName);
                            Group group = new Group(gURI);
                            gmsClient.createGroup(group);
                            actuallyCreated = true;
                            throw new Exception("Should have received access control exception");
                        }
                        catch (AccessControlException e)
                        {
                            // expected
                            return null;
                        }
                        finally
                        {
                            if (actuallyCreated)
                            {
                                // cleanup - delete the group
                                gmsClient.deleteGroup(groupName);
                            }
                        }
                    }
                });
            }
            catch (Exception e)
            {
                log.error("test failed", e);
                Assert.fail(e.getMessage());
            }
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
    }


    private GroupURI getGroupID(final String name)
    {
        String gName = getGroupID(name, UUID.randomUUID().toString());
        return new GroupURI(serviceURI, gName);
    }

    private String getGroupID(String name, String id)
    {
        return "ac_ws-inttest-" + name + "-" + id;
    }

    private Group getEmptyGroupWithDelay(final String groupID, final Subject user) 
            throws Exception {
        Group group = null;
        int n = 1;
        boolean success = false;
        while (!success && n < 10) {
            // add delay to compensate for eventual consistency of
            // content in multiple ldap hosts;
            // try it several times
            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
            group = getGroupAs(groupID, user);
            if (group.getGroupMembers().size() == 0 && group.getUserMembers().size() == 0) {
                success = true;
            } else {
                n++;
            }
        }
        return group;
    }

    private Group getNonEmptyGroupWithDelay(final String groupID, final Subject user) 
            throws Exception {
        Group group = null;
        int n = 1;
        boolean success = false;
        while (!success && n < 10) {
            // add delay to compensate for eventual consistency of
            // content in multiple ldap hosts;
            // try it several times
            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
            group = getGroupAs(groupID, user);
            if (group.getGroupMembers().size() > 0 || group.getUserMembers().size() > 0) {
                success = true;
            } else {
                n++;
            }
        }
        return group;
    }

    private Group getExistingGroupWithDelay(final String groupID, final Subject user) 
            throws InterruptedException, AccessControlException, GroupNotFoundException, IOException {
        Group group = null;
        int n = 1;
        boolean success = false;
        while (!success && n < 10) {
            // add delay to compensate for eventual consistency of
            // content in multiple ldap hosts;
            // try it several times
            TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
            try {
                group = getGroupAs(groupID, user);
                success = true;
            } catch (AccessControlException ex) {
                throw ex;
            } catch (Exception ex) {
                n++;
            }
        }
        return group;
    }

    private Group getGroupAs(final String groupID, final Subject user)
            throws Exception
    {
        try
        {
            return Subject.doAs(user,
                new PrivilegedExceptionAction<Group>()
                {
                    @Override
                    public Group run() throws Exception
                    {
                        return gmsClient.getGroup(groupID);
                    }
                });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private Group getMembershipAs(final String groupID, final Role role,
                                  final Subject subject) throws Exception
    {
        try
        {
            return Subject.doAs(subject, new PrivilegedExceptionAction<Group>()
            {
                @Override
                public Group run() throws Exception
                {
                    return gmsClient.getMembership(groupID, role);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private Collection<Group> getMembershipsAs(final Role role,
                                               final Subject subject)
            throws Exception
    {
        try
        {
            return Subject.doAs(subject,
                new PrivilegedExceptionAction<Collection<Group>>()
                {
                    @Override
                    public Collection<Group> run() throws
                                                   Exception
                    {
                        return gmsClient.getMemberships(role);
                    }
                });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private Group createGroupAs(final Group group, final Subject subject)
            throws Exception
    {
        try
        {
            return Subject.doAs(subject, new PrivilegedExceptionAction<Group>()
            {
                @Override
                public Group run() throws Exception
                {
                    return gmsClient.createGroup(group);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private Group updateGroupAs(final Group group, final Subject subject)
            throws Exception
    {
        try
        {
            return Subject.doAs(subject, new PrivilegedExceptionAction<Group>()
            {
                @Override
                public Group run() throws Exception
                {
                    return gmsClient.updateGroup(group);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private void removeGroupMemberAs(final Subject subject,
                                     final String groupID,
                                     final String memberID)
            throws Exception
    {
        try
        {
            Subject.doAs(subject, new PrivilegedExceptionAction<Void>()
            {
                @Override
                public Void run() throws Exception
                {
                    gmsClient.removeGroupMember(groupID, memberID);

                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private void removeUserMemberAs(final Subject subject,
                                     final String groupID,
                                     final Principal memberID)
            throws Exception
    {
        try
        {
            Subject.doAs(subject, new PrivilegedExceptionAction<Void>()
            {
                @Override
                public Void run() throws Exception
                {
                    gmsClient.removeUserMember(groupID, memberID);

                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private void deleteGroupAs(final String groupName, final Subject subject,
            final boolean delay) throws Exception
    {
        try
        {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    if (delay) {
                        int n = 1;
                        boolean success = false;
                        while (!success && n < 10) {
                            try {
                                // add delay to compensate for 
                                // eventual consistency of
                                // content in multiple ldap hosts
                                // try it several times
                                TimeUnit.MILLISECONDS.sleep(20 * Math.round(Math.pow(2.0, n)));
                                gmsClient.deleteGroup(groupName);
                                success = true;
                            } catch(AccessControlException ex) {
                                throw ex;
                            } catch(Exception ex) {
                                n++;
                            }
                        }
                    } else {
                        gmsClient.deleteGroup(groupName);
                    }
                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private void addGroupMemberAs(final String groupName,
                                  final String memberName,
                                  final Subject subject) throws Exception
    {
        try
        {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    gmsClient.addGroupMember(groupName, memberName);
                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    private void addUserMemberAs(final String groupName,
                                  final Principal principal,
                                  final Subject subject) throws Exception
    {
        try
        {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    gmsClient.addUserMember(groupName, principal);
                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }
}
