/**
 * ***********************************************************************
 * ******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 * *************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 * <p>
 * (c) 2018.                            (c) 2018.
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

package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;
import java.util.UUID;
import javax.security.auth.Subject;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opencadc.auth.PosixGroup;
import org.opencadc.gms.GroupURI;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LdapGroupDAOTest extends AbstractLdapDAOTest {
    private static final Logger log = Logger.getLogger(LdapGroupDAOTest.class);

    @BeforeClass
    public static void setUpClass() {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass() {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    String getGroupID() {
        return "CadcDaoTestGroup-" + System.currentTimeMillis();
    }

    String createUsername() {
        return "CadcDaoTestUser-" + System.currentTimeMillis();
    }

    protected long uuid2long(UUID uuid) {
        return uuid.getLeastSignificantBits();
    }

    private User addUserRequest() throws Exception {
        // add user using HttpPrincipal
        final String username = createUsername();
        final HttpPrincipal userID = new HttpPrincipal(username);

        final User expectedUser = new User();
        expectedUser.getIdentities().add(userID);

        expectedUser.personalDetails = new PersonalDetails("associated", "user");
        expectedUser.personalDetails.email = username + "@canada.ca";

        UserRequest userRequest = new UserRequest(expectedUser, "123456".toCharArray());

        // Adding a new user is done anonymously
        final LdapUserDAO userDAO = getUserDAO();
        userDAO.addUserRequest(userRequest);

        final DNPrincipal dnPrincipal = new DNPrincipal("uid=" + username + "," + config.getUserRequestsDN());
        Subject subject = new Subject();
        subject.getPrincipals().add(dnPrincipal);

        // do everything as owner
        final User newUser = (User) Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            public Object run()
                    throws Exception {
                try {
                    return userDAO.getUserRequest(userID);
                } catch (Exception e) {
                    throw new Exception("Problems", e);
                }
            }
        });

        return newUser;
    }

    private Group addUserAssociatedGroup(final User newUser, final Group expectGroup) throws Exception {
        Group newGroup = (Group) Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                try {
                    final int numericID = (int) uuid2long(newUser.getID().getUUID());
                    getGroupDAO().addUserAssociatedGroup(expectGroup, numericID);

                    Group actualGroup = getGroupDAO().getUserAssociatedGroup(expectGroup.getID().getName(), true);
                    log.info("addGroup: " + expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);

                    return actualGroup;
                } catch (Exception e) {
                    log.error("unexpected exception", e);
                    throw new Exception("Problems", e);
                }
            }
        });

        return newGroup;
    }

    @Test
    public void testDeactivationReactivation() throws Exception {
        // create the test group
        User newUser = addUserRequest();

        // add group associated with the above user
        Group expectGroup = new Group(new GroupURI("ivo://example.net/gms?" + newUser.getHttpPrincipal().getName()));
        setField(expectGroup, cadcDaoTest1_AugmentedUser, "owner");
        expectGroup.getUserMembers().add(newUser);
        Group group = addUserAssociatedGroup(newUser, expectGroup);

        // test group reactivation
        LdapGroupDAO groupDAO = getGroupDAO();
        boolean activated = groupDAO.reactivateGroup(group);
        Assert.assertTrue("failed to activate group", activated);

        // test group deactivation
        boolean deactivated = groupDAO.deactivateGroup(group);
        Assert.assertTrue("failed to deactivate group", deactivated);

        String groupName = group.getID().getName();
        groupDAO.deleteUserAssociatedGroup(groupName);
        try {
            groupDAO.getGroup(groupName, false);
            fail("Failed to delete user associated group.");
        } catch (GroupNotFoundException expectedException) {
            // success
        } finally {
            // clean up, delete the userRequest
            getUserDAO().deleteUserRequest(newUser.getHttpPrincipal());
        }
    }

    @Test
    public void testAddUserAssociatedGroup() throws Exception {
        // add user using HttpPrincipal
        User newUser = addUserRequest();

        // add group associated with the above user
        Group expectGroup = new Group(new GroupURI("ivo://example.net/gms?" + newUser.getHttpPrincipal().getName()));
        setField(expectGroup, cadcDaoTest1_AugmentedUser, "owner");
        expectGroup.getUserMembers().add(newUser);
        addUserAssociatedGroup(newUser, expectGroup);
    }

    @Test
    public void testDeleteUserAssociatedGroup() throws Exception {
        // add user using HttpPrincipal
        User newUser = addUserRequest();

        // add group associated with the above user
        Group expectGroup = new Group(new GroupURI("ivo://example.net/gms?" + newUser.getHttpPrincipal().getName()));
        setField(expectGroup, cadcDaoTest1_AugmentedUser, "owner");
        expectGroup.getUserMembers().add(newUser);
        addUserAssociatedGroup(newUser, expectGroup);

        // delete the user associated group
        LocalAuthority localAuthority = new LocalAuthority();
        URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());
        GroupURI groupID = new GroupURI(gmsServiceURI.toString() + "?" + newUser.getHttpPrincipal().getName());
        getGroupDAO().deleteUserAssociatedGroup(groupID.getName());
        try {
            getGroupDAO().getGroup(groupID.getName(), false);
            fail("Failed to delete user associated group.");
        } catch (GroupNotFoundException expectedException) {
            // success
        } finally {
            // clean up, delete the userRequest
            getUserDAO().deleteUserRequest(newUser.getHttpPrincipal());
        }
    }

    @Test
    public void testOneGroup() throws Exception {
        // do everything as owner
        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                try {
                    // authority as specified in src/test/resources/LocalAuthority
                    Group expectGroup = new Group(new GroupURI("ivo://example.net/gms?" + getGroupID()));
                    setField(expectGroup, cadcDaoTest1_AugmentedUser, "owner");
                    getGroupDAO().addGroup(expectGroup);
                    Group actualGroup = getGroupDAO().getGroup(expectGroup.getID().getName(), true);
                    log.info("addGroup: " + expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);

                    Thread.sleep(3L);
                    Group otherGroup = new Group(new GroupURI("ivo://example.net/gms?" + getGroupID()));
                    setField(otherGroup, cadcDaoTest1_AugmentedUser, "owner");
                    getGroupDAO().addGroup(otherGroup);
                    otherGroup = getGroupDAO().getGroup(otherGroup.getID().getName(), true);
                    log.info("addGroup: " + otherGroup.getID());

                    // modify group fields
                    // description
                    expectGroup.description = "Happy testing";
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.description = null;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // userMembers
                    expectGroup.getUserMembers().add(cadcDaoTest2_User);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // test adding the same user but with two different
                    // Principals. The duplicate should be ignored
                    // the the returned result should contain only
                    // one entry (the dn one)
                    User duplicateIdentity = new User();
                    duplicateIdentity.getIdentities().add(cadcDaoTest2_User.getHttpPrincipal());
                    expectGroup.getUserMembers().add(cadcDaoTest2_User);
                    expectGroup.getUserMembers().add(duplicateIdentity);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    //expectGroup.getUserMembers().remove(duplicateIdentity);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.getUserMembers().remove(cadcDaoTest2_User);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // groupMembers
                    expectGroup.getGroupMembers().add(otherGroup);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.getGroupMembers().remove(otherGroup);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.description = "Happy testing";
                    expectGroup.getUserMembers().add(cadcDaoTest2_User);
                    expectGroup.getGroupMembers().add(otherGroup);

                    // userAdmins
                    expectGroup.getUserAdmins().add(cadcDaoTest3_User);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.getUserAdmins().remove(cadcDaoTest3_User);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // groupAdmins
                    Group adminGroup = new Group(new GroupURI("ivo://example.net/gms?" + getGroupID()));
                    setField(adminGroup, cadcDaoTest1_AugmentedUser, "owner");
                    getGroupDAO().addGroup(adminGroup);
                    adminGroup = getGroupDAO().getGroup(adminGroup.getID().getName(), true);
                    expectGroup.getGroupAdmins().add(adminGroup);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.getGroupAdmins().remove(adminGroup);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // test adding the same user admin but with two different
                    // Principals. The duplicate should be ignored
                    // the the returned result should contain only
                    // one entry (the dn one)
                    expectGroup.getUserAdmins().add(cadcDaoTest2_User);
                    expectGroup.getUserAdmins().add(duplicateIdentity);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    //expectGroup.getUserAdmins().remove(duplicateIdentity);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // delete the group
                    getGroupDAO().deleteGroup(expectGroup.getID().getName());
                    try {
                        getGroupDAO().getGroup(expectGroup.getID().getName(), false);
                        fail("get on deleted group should throw exception");
                    } catch (GroupNotFoundException ignore) {
                    }
                    log.info("deleted group: " + expectGroup.getID());

                    // reactivate the group
                    Group reactGroup = new Group(expectGroup.getID());
                    setField(reactGroup, cadcDaoTest1_AugmentedUser, "owner");
                    getGroupDAO().addGroup(reactGroup);
                    log.info("create (reactivate) group: " + expectGroup.getID());
                    actualGroup = getGroupDAO().getGroup(expectGroup.getID().getName(), true);
                    assertTrue(actualGroup.getUserMembers().isEmpty());
                    assertTrue(actualGroup.getGroupMembers().isEmpty());
                    assertTrue(actualGroup.getUserAdmins().isEmpty());
                    assertTrue(actualGroup.getGroupAdmins().isEmpty());
                    Assert.assertTrue(actualGroup.getProperties().isEmpty());

                    // create another group and make expected group
                    // member of that group. Delete expected group after
                    // authority as specified in src/test/resources/LocalAuthority
                    Group expectGroup2 = new Group(new GroupURI("ivo://example.net/gms?" + getGroupID()));
                    setField(expectGroup2, cadcDaoTest1_AugmentedUser, "owner");
                    expectGroup2.getGroupAdmins().add(actualGroup);
                    expectGroup2.getGroupMembers().add(actualGroup);
                    getGroupDAO().addGroup(expectGroup2);
                    Group actualGroup2 = getGroupDAO().getGroup(expectGroup2.getID().getName(), true);
                    log.debug("addGroup: " + expectGroup2.getID());
                    assertGroupsEqual(expectGroup2, actualGroup2);

                    // delete the group
                    getGroupDAO().deleteGroup(actualGroup.getID().getName());

                    // should not be member of admin of expectGroup2
                    expectGroup2.getGroupAdmins().remove(actualGroup);
                    expectGroup2.getGroupMembers().remove(actualGroup);
                    actualGroup2 = getGroupDAO().getGroup(expectGroup2.getID().getName(), true);
                    log.debug("addGroup: " + expectGroup2.getID());
                    assertGroupsEqual(expectGroup2, actualGroup2);

                    return null;
                } catch (Exception e) {
                    log.error("unexpected exception", e);
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    //    @Test
    public void testGetGroupNames() throws Exception {
        final String groupID = getGroupID();
        final String testGroup1ID = groupID + ".1";
        final String testGroup2ID = groupID + ".2";

        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                try {
                    // authority as specified in src/test/resources/LocalAuthority
                    Group testGroup1 = new Group(new GroupURI("ivo://example.net/gms?" + testGroup1ID));
                    getGroupDAO().addGroup(testGroup1);
                    testGroup1 = getGroupDAO().getGroup(testGroup1.getID().getName(), true);
                    log.debug("add group: " + testGroup1ID);

                    Group testGroup2 = new Group(new GroupURI("ivo://example.net/gms?" + testGroup2ID));
                    getGroupDAO().addGroup(testGroup2);
                    testGroup2 = getGroupDAO().getGroup(testGroup2.getID().getName(), true);
                    log.debug("add group: " + testGroup2ID);
                    //Thread.sleep(1000); // sleep to let memberof plugin do its work
                } catch (Exception e) {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                try {
                    Collection<PosixGroup> groups = getGroupDAO().getGroupNames();

                    log.debug("testGetGroupNames groups found: " + groups.size());
                    assertNotNull(groups);
                    assertTrue(groups.size() >= 2);

                    boolean found1 = false;
                    boolean found2 = false;
                    for (PosixGroup name : groups) {
                        log.debug("group: " + name);
                        if (name.getGroupURI().getName().equals(testGroup1ID)) {
                            found1 = true;
                        }
                        if (name.getGroupURI().getName().equals(testGroup2ID)) {
                            found2 = true;
                        }
                    }
                    if (!found1) {
                        fail("Admin group " + testGroup1ID + " not found");
                    }
                    if (!found2) {
                        fail("Admin group " + testGroup2ID + " not found");
                    }
                } catch (Exception e) {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                try {
                    getGroupDAO().deleteGroup(testGroup1ID);
                    getGroupDAO().deleteGroup(testGroup2ID);
                } catch (Exception e) {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }

    //    @Test
    public void testGetGroupExceptions() throws Exception {
        final String groupID = getGroupID();

        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                try {
                    getGroupDAO().getGroup(groupID, false);
                    fail("getGroup with unknown group should throw " +
                            "GroupNotFoundException");
                } catch (GroupNotFoundException ignore) {
                }

                try {
                    getGroupDAO().getGroup(groupID, true);
                    fail("getGroup with unknown group should throw " +
                            "GroupNotFoundException");
                } catch (GroupNotFoundException ignore) {
                }

                // authority as specified in src/test/resources/LocalAuthority
                getGroupDAO().addGroup(new Group(new GroupURI("ivo://example.net/gms?" + groupID)));
                return null;
            }
        });
    }

    //    @Test
    public void testModifyGroupExceptions() throws Exception {
        final String groupID = getGroupID();

        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                //getGroupDAO().addGroup(new Group(groupID, cadcDaoTest1_User));
                try {
                    // authority as specified in src/test/resources/LocalAuthority
                    getGroupDAO().modifyGroup(new Group(new GroupURI("ivo://example.net/gms?" + "fooBOGUSASFgomsi")));
                    fail("modifyGroup with unknown user should throw " +
                            "GroupNotFoundException");
                } catch (GroupNotFoundException ignore) {
                }

                return null;
            }
        });
    }

    //    @Test
    public void testDeleteGroupExceptions() throws Exception {
        final String groupID = getGroupID();

        Subject.doAs(cadcDaoTest1_Subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                getGroupDAO().deleteGroup(groupID); // should silently succeed
                return null;
            }
        });
    }

    private void assertGroupsEqual(Group gr1, Group gr2) {
        if ((gr1 == null) && (gr2 == null)) {
            return;
        }
        assertEquals(gr1, gr2);
        assertEquals(gr1.getID(), gr2.getID());
        assertEquals(gr1.description, gr2.description);

        assertEquals(gr1.getOwner(), gr2.getOwner());

        assertEquals(gr1.getGroupMembers(), gr2.getGroupMembers());
        assertEquals(gr1.getGroupMembers().size(), gr2.getGroupMembers().size());
        for (Group gr : gr1.getGroupMembers()) {
            assertTrue(gr2.getGroupMembers().contains(gr));
        }

        assertEquals(gr1.getUserMembers().size(), gr2.getUserMembers().size());
        assertTrue(gr1.getUserMembers().containsAll(gr2.getUserMembers()));
        assertTrue(gr2.getUserMembers().containsAll(gr1.getUserMembers()));
        for (User user : gr1.getUserMembers()) {
            assertTrue(gr2.getUserMembers().contains(user));
        }

        assertEquals(gr1.getGroupAdmins(), gr2.getGroupAdmins());
        assertEquals(gr1.getGroupAdmins().size(), gr2.getGroupAdmins().size());
        for (Group gr : gr1.getGroupAdmins()) {
            assertTrue(gr2.getGroupAdmins().contains(gr));
        }

        assertEquals(gr1.getUserAdmins().size(), gr2.getUserAdmins().size());
        for (User user : gr1.getUserAdmins()) {
            assertTrue(gr2.getUserAdmins().contains(user));
        }

        assertEquals(gr1.getProperties(), gr2.getProperties());
        for (GroupProperty prop : gr1.getProperties()) {
            assertTrue(gr2.getProperties().contains(prop));
        }
    }

}
