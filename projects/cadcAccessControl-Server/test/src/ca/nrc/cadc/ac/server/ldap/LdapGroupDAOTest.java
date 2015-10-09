/**
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
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.AccessControlException;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.Log4jInit;

public class LdapGroupDAOTest extends AbstractLdapDAOTest
{
    private static final Logger log = Logger.getLogger(LdapGroupDAOTest.class);

    static String daoTestUid1 = "cadcdaotest1";
    static String daoTestUid2 = "cadcdaotest2";
    static String daoTestUid3 = "cadcdaotest3";

    static String daoTestDN1 = "cn=" + daoTestUid1 + ",ou=cadc,o=hia,c=ca";
    static String daoTestDN2 = "cn=" + daoTestUid2 + ",ou=cadc,o=hia,c=ca";
    static String daoTestDN3 = "cn=" + daoTestUid3 + ",ou=cadc,o=hia,c=ca";
    static String unknownDN = "cn=foo,ou=cadc,o=hia,c=ca";

    static String daoTestEntryDN1 = "uid=cadcdaotest1,ou=users,ou=ds,dc=testcanfar";
    static String daoTestEntryDN2 = "uid=cadcdaotest2,ou=users,ou=ds,dc=testcanfar";

    static DNPrincipal daoDNPrincipal1;
    static DNPrincipal daoDNPrincipal2;

    static X500Principal daoTestPrincipal1;
    static X500Principal daoTestPrincipal2;
    static X500Principal daoTestPrincipal3;
    static X500Principal unknownPrincipal;

    static User<X500Principal> daoTestUser1;
    static User<X500Principal> daoTestUser2;
    static User<X500Principal> daoTestUser3;
    static User<X500Principal> unknownUser;

    static Subject daoTestUser1Subject;
    static Subject daoTestUser2Subject;
    static Subject anonSubject;

    static LdapConfig config;

    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);

        // get the configuration of the development server from and config files...
        config = getLdapConfig();

        daoTestPrincipal1 = new X500Principal(daoTestDN1);
        daoTestPrincipal2 = new X500Principal(daoTestDN2);
        daoTestPrincipal3 = new X500Principal(daoTestDN3);
        unknownPrincipal = new X500Principal(unknownDN);

        daoDNPrincipal1 = new DNPrincipal(daoTestEntryDN1);
        daoDNPrincipal2 = new DNPrincipal(daoTestEntryDN2);

        daoTestUser1 = new User<X500Principal>(daoTestPrincipal1);
        daoTestUser2 = new User<X500Principal>(daoTestPrincipal2);
        daoTestUser3 = new User<X500Principal>(daoTestPrincipal3);
        unknownUser = new User<X500Principal>(unknownPrincipal);

        daoTestUser1Subject = new Subject();
        daoTestUser1Subject.getPrincipals().add(daoTestUser1.getUserID());
        daoTestUser1Subject.getPrincipals().add(daoDNPrincipal1);

        daoTestUser2Subject = new Subject();
        daoTestUser2Subject.getPrincipals().add(daoTestUser2.getUserID());
        daoTestUser2Subject.getPrincipals().add(daoDNPrincipal2);

        anonSubject = new Subject();
        anonSubject.getPrincipals().add(unknownUser.getUserID());
    }

    LdapGroupDAO<X500Principal> getGroupDAO() throws Exception
    {
        LdapConnections connections = new LdapConnections(config);
        return new LdapGroupDAO<X500Principal>(connections,
                new LdapUserDAO<X500Principal>(connections));
    }

    String getGroupID()
    {
        return "CadcDaoTestGroup-" + System.currentTimeMillis();
    }

    @Test
    public void testOneGroup() throws Exception
    {
        // do everything as owner
        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group expectGroup = new Group(getGroupID(), daoTestUser1);
                    getGroupDAO().addGroup(expectGroup);
                    Group actualGroup = getGroupDAO().getGroup(expectGroup.getID());
                    log.debug("addGroup: " + expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);

                    Group otherGroup = new Group(getGroupID(), daoTestUser1);
                    getGroupDAO().addGroup(otherGroup);
                    otherGroup = getGroupDAO().getGroup(otherGroup.getID());
                    log.debug("addGroup: " + otherGroup.getID());

                    // modify group fields
                    // description
                    expectGroup.description = "Happy testing";
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.description = null;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // userMembers
                    expectGroup.getUserMembers().add(daoTestUser2);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // test adding the same user but with two different
                    // Principals. The duplicate should be ignored
                    // the the returned result should contain only
                    // one entry (the dn one)
                    User<HttpPrincipal> duplicateIdentity =
                            new User<HttpPrincipal>(new HttpPrincipal(daoTestUid2));
                    expectGroup.getUserMembers().add(daoTestUser2);
                    expectGroup.getUserMembers().add(duplicateIdentity);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    expectGroup.getUserMembers().remove(duplicateIdentity);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.getUserMembers().remove(daoTestUser2);
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
                    expectGroup.getUserMembers().add(daoTestUser2);
                    expectGroup.getGroupMembers().add(otherGroup);

                    // userAdmins
                    expectGroup.getUserAdmins().add(daoTestUser3);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // groupAdmins
                    Group adminGroup = new Group(getGroupID(), daoTestUser1);
                    getGroupDAO().addGroup(adminGroup);
                    adminGroup = getGroupDAO().getGroup(adminGroup.getID());
                    expectGroup.getGroupAdmins().add(adminGroup);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // test adding the same user admin but with two different
                    // Principals. The duplicate should be ignored
                    // the the returned result should contain only
                    // one entry (the dn one)
                    expectGroup.getUserAdmins().add(daoTestUser2);
                    expectGroup.getUserAdmins().add(duplicateIdentity);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    expectGroup.getUserAdmins().remove(duplicateIdentity);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // delete the group
                    getGroupDAO().deleteGroup(expectGroup.getID());
                    try
                    {
                        getGroupDAO().getGroup(expectGroup.getID());
                        fail("get on deleted group should throw exception");
                    }
                    catch (GroupNotFoundException ignore) {}

                    // reactivate the group
                    getGroupDAO().addGroup(expectGroup);
                    actualGroup = getGroupDAO().getGroup(expectGroup.getID());
                    // add group no longer returns an object
                    //assertTrue(actualGroup instanceof ActivatedGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // get the activated group
                    actualGroup = getGroupDAO().getGroup(expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);

                    // create another group and make expected group
                    // member of that group. Delete expected group after
                    Group expectGroup2 = new Group(getGroupID(), daoTestUser1);
                    expectGroup2.getGroupAdmins().add(expectGroup);
                    expectGroup2.getGroupMembers().add(expectGroup);
                    getGroupDAO().addGroup(expectGroup2);
                    Group actualGroup2 = getGroupDAO().getGroup(expectGroup2.getID());
                    log.debug("addGroup: " + expectGroup2.getID());
                    assertGroupsEqual(expectGroup2, actualGroup2);

                    // delete the group
                    getGroupDAO().deleteGroup(expectGroup.getID());
                    // now expectGroup should not be member of admin of
                    // expectGroup2
                    expectGroup2.getGroupAdmins().remove(expectGroup);
                    expectGroup2.getGroupMembers().remove(expectGroup);
                    actualGroup2 = getGroupDAO().getGroup(expectGroup2.getID());
                    log.debug("addGroup: " + expectGroup2.getID());
                    assertGroupsEqual(expectGroup2, actualGroup2);

                    return null;
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    throw new Exception("Problems", e);
                }
            }
        });
    }

    @Test
    public void testSearchOwnerGroups() throws Exception
    {
        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    String groupID = getGroupID();
                    Group testGroup = new Group(groupID, daoTestUser1);
                    getGroupDAO().addGroup(testGroup);
                    testGroup = getGroupDAO().getGroup(testGroup.getID());

                    Collection<Group> groups =
                            getGroupDAO().getGroups(daoTestUser1.getUserID(),
                                                    Role.OWNER, null);
                    assertNotNull(groups);

                    boolean found = false;
                    for (Group group : groups)
                    {
                        if (group.getID().equals(group.getID()))
                        {
                            found = true;
                        }
                    }
                    if (!found)
                    {
                        fail("Group for owner not found");
                    }

                    groups = getGroupDAO().getGroups(daoTestUser1.getUserID(),
                                                     Role.OWNER, groupID);
                    assertNotNull(groups);
                    assertEquals(1, groups.size());
                    assertTrue(groups.iterator().next().equals(testGroup));

                    getGroupDAO().deleteGroup(groupID);
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }

    @Test
    public void testSearchMemberGroups() throws Exception
    {
        final String groupID = getGroupID();
        final String testGroup1ID = groupID + ".1";
        final String testGroup2ID = groupID + ".2";

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group testGroup1 = new Group(testGroup1ID, daoTestUser1);
                    testGroup1.getUserMembers().add(daoTestUser2);
                    getGroupDAO().addGroup(testGroup1);
                    testGroup1 = getGroupDAO().getGroup(testGroup1.getID());
                    log.debug("add group: " + testGroup1ID);

                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    testGroup2.getUserMembers().add(daoTestUser2);
                    getGroupDAO().addGroup(testGroup2);
                    testGroup2 = getGroupDAO().getGroup(testGroup2.getID());
                    log.debug("add group: " + testGroup2ID);
                    Thread.sleep(1000); //sleep to let memberof plugin in LDAP do its work
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(daoTestUser2Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Collection<Group> groups =
                            getGroupDAO().getGroups(daoTestUser2.getUserID(),
                                                    Role.MEMBER, null);

                    assertNotNull(groups);
                    assertTrue(groups.size() >= 2);

                    log.debug("testSearchMemberGroups groups found: " + groups.size());
                    boolean found1 = false;
                    boolean found2 = false;
                    for (Group group : groups)
                    {
                        log.debug("member group: " + group.getID());
                        if (group.getID().equals(testGroup1ID))
                        {
                            found1 = true;
                        }
                        if (group.getID().equals(testGroup2ID))
                        {
                            found2 = true;
                        }
                    }
                    if (!found1)
                    {
                        fail("Test group 1 not found");
                    }
                    if (!found2)
                    {
                        fail("Test group 2 not found");
                    }

                    groups = getGroupDAO().getGroups(daoTestUser2.getUserID(),
                                                     Role.MEMBER, testGroup1ID);
                    assertNotNull(groups);
                    assertTrue(groups.size() == 1);
                    assertTrue(groups.iterator().next().getID().equals(testGroup1ID));
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().deleteGroup(testGroup1ID);
                    getGroupDAO().deleteGroup(testGroup2ID);
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }

    @Test
    public void testSearchAdminGroups() throws Exception
    {
        final String groupID = getGroupID();
        final String testGroup1ID = groupID + ".1";
        final String testGroup2ID = groupID + ".2";

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group testGroup1 = new Group(testGroup1ID, daoTestUser1);
                    testGroup1.getUserAdmins().add(daoTestUser2);
                    getGroupDAO().addGroup(testGroup1);
                    testGroup1 = getGroupDAO().getGroup(testGroup1.getID());
                    log.debug("add group: " + testGroup1ID);

                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    testGroup2.getUserAdmins().add(daoTestUser2);
                    getGroupDAO().addGroup(testGroup2);
                    testGroup2 = getGroupDAO().getGroup(testGroup2.getID());
                    log.debug("add group: " + testGroup2ID);
                    Thread.sleep(1000); // sleep to let memberof plugin do its work
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(daoTestUser2Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Collection<Group> groups =
                            getGroupDAO().getGroups(daoTestUser2.getUserID(),
                                                    Role.ADMIN, null);

                    log.debug("testSearchAdminGroups groups found: " + groups.size());
                    assertNotNull(groups);
                    assertTrue(groups.size() >= 2);

                    boolean found1 = false;
                    boolean found2 = false;
                    for (Group group : groups)
                    {
                        log.debug("admin group: " + group.getID());
                        if (group.getID().equalsIgnoreCase(testGroup1ID))
                        {
                            found1 = true;
                        }
                        if (group.getID().equalsIgnoreCase(testGroup2ID))
                        {
                            found2 = true;
                        }
                    }
                    if (!found1)
                    {
                        fail("Admin group " + testGroup1ID + " not found");
                    }
                    if (!found2)
                    {
                        fail("Admin group " + testGroup2ID + " not found");
                    }

                    groups = getGroupDAO().getGroups(daoTestUser2.getUserID(),
                                                     Role.ADMIN, testGroup1ID);
                    assertNotNull(groups);
                    assertTrue(groups.size() == 1);
                    assertTrue(groups.iterator().next().getID().equals(testGroup1ID));
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().deleteGroup(testGroup1ID);
                    getGroupDAO().deleteGroup(testGroup2ID);
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }

    @Test
    public void testGetGroupNames() throws Exception
    {
        final String groupID = getGroupID();
        final String testGroup1ID = groupID + ".1";
        final String testGroup2ID = groupID + ".2";

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group testGroup1 = new Group(testGroup1ID, daoTestUser1);
                    getGroupDAO().addGroup(testGroup1);
                    testGroup1 = getGroupDAO().getGroup(testGroup1.getID());
                    log.debug("add group: " + testGroup1ID);

                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    getGroupDAO().addGroup(testGroup2);
                    testGroup2 = getGroupDAO().getGroup(testGroup2.getID());
                    log.debug("add group: " + testGroup2ID);
                    //Thread.sleep(1000); // sleep to let memberof plugin do its work
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Collection<String> groups = getGroupDAO().getGroupNames();

                    log.debug("testGetGroupNames groups found: " + groups.size());
                    assertNotNull(groups);
                    assertTrue(groups.size() >= 2);

                    boolean found1 = false;
                    boolean found2 = false;
                    for (String name : groups)
                    {
                        log.debug("group: " + name);
                        if (name.equals(testGroup1ID))
                        {
                            found1 = true;
                        }
                        if (name.equals(testGroup2ID))
                        {
                            found2 = true;
                        }
                    }
                    if (!found1)
                    {
                        fail("Admin group " + testGroup1ID + " not found");
                    }
                    if (!found2)
                    {
                        fail("Admin group " + testGroup2ID + " not found");
                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().deleteGroup(testGroup1ID);
                    getGroupDAO().deleteGroup(testGroup2ID);
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }

    @Test
    public void testAddGroupExceptions() throws Exception
    {
        Subject.doAs(anonSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().addGroup(new Group(getGroupID(), daoTestUser1));
                    fail("addGroup with anonymous access should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().addGroup(new Group("foo", unknownUser));
                    fail("addGroup with unknown user should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}

                String groupID = getGroupID();
                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                Group group = getGroupDAO().getGroup(groupID);

                try
                {
                    getGroupDAO().addGroup(group);
                    fail("addGroup with existing group should throw " +
                         "GroupAlreadyExistsException");
                }
                catch (GroupAlreadyExistsException ignore) {}

                getGroupDAO().deleteGroup(group.getID());
                return null;
            }
        });
    }

    @Test
    public void testGetGroupExceptions() throws Exception
    {
        final String groupID = getGroupID();

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().getGroup(groupID);
                    fail("getGroup with unknown group should throw " +
                         "GroupNotFoundException");
                }
                catch (GroupNotFoundException ignore) {}

                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                return null;
            }
        });

        Subject.doAs(anonSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().getGroup(groupID);
                    fail("getGroup with anonymous access should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().getGroup(groupID);
                    //fail("getGroup with anonymous access should throw " +
                    //     "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });

        // All access ACI's will allow anonymous access
//        Subject.doAs(daoTestUser2Subject, new PrivilegedExceptionAction<Object>()
//        {
//            public Object run() throws Exception
//            {
//                try
//                {
//                    getGroupDAO().getGroup(groupID);
//                    fail("getGroup with anonymous access should throw " +
//                         "AccessControlException");
//                }
//                catch (AccessControlException ignore) {}
//                return null;
//            }
//        });
    }

    @Test
    public void testModifyGroupExceptions() throws Exception
    {
        final String groupID = getGroupID();

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                try
                {
                    getGroupDAO().modifyGroup(new Group("foo", daoTestUser1));
                    fail("modifyGroup with unknown user should throw " +
                         "GroupNotFoundException");
                }
                catch (GroupNotFoundException ignore) {}

                return null;
            }
        });

        Subject.doAs(anonSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().getGroup(groupID);
                    fail("getGroup with anonymous access should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().deleteGroup(groupID);
                return null;
            }
        });
    }

    @Test
    public void testDeleteGroupExceptions() throws Exception
    {
        final String groupID = getGroupID();

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().deleteGroup(groupID);
                    fail("deleteGroup with unknown group should throw " +
                         "GroupNotFoundException");
                }
                catch (GroupNotFoundException ignore) {}

                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                return null;
            }
        });

        Subject.doAs(anonSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().deleteGroup(groupID);
                    fail("deleteGroup with anonymous access should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().deleteGroup(groupID);
                return null;
            }
        });
    }

    @Test
    public void testSearchGroupsExceptions() throws Exception
    {
        final String groupID = getGroupID();

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));

                try
                {
                    getGroupDAO().getGroups(unknownPrincipal, Role.OWNER,
                                               groupID);
                    fail("searchGroups with unknown user should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}

                return null;
            }
        });

        Subject.doAs(anonSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().getGroups(daoTestPrincipal1, Role.OWNER,
                                               groupID);
                    fail("searchGroups with anonymous access should throw " +
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });

        //
        // change the user
//        Subject.doAs(daoTestUser2Subject, new PrivilegedExceptionAction<Object>()
//        {
//            public Object run() throws Exception
//            {
//                try
//                {
//                    Group group = getGroupDAO().getGroup(groupID);
//                    assertTrue(group == null);
//
//                    fail("searchGroups with un-authorized user should throw " +
//                         "AccessControlException");
//                }
//                catch (AccessControlException ignore)
//                {
//
//                }
//
//                return null;
//            }
//        });

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().deleteGroup(groupID);
                return null;
            }
        });
    }

    private void assertGroupsEqual(Group gr1, Group gr2)
    {
        if ((gr1 == null) && (gr2 == null))
        {
            return;
        }
        assertEquals(gr1, gr2);
        assertEquals(gr1.getID(), gr2.getID());
        assertEquals(gr1.description, gr2.description);
        assertEquals(gr1.getOwner(), gr2.getOwner());

        assertEquals(gr1.getGroupMembers(), gr2.getGroupMembers());
        assertEquals(gr1.getGroupMembers().size(), gr2.getGroupMembers().size());
        for (Group gr : gr1.getGroupMembers())
        {
            assertTrue(gr2.getGroupMembers().contains(gr));
        }

        assertEquals(gr1.getUserMembers(), gr2.getUserMembers());
        assertEquals(gr1.getUserMembers().size(), gr2.getUserMembers()
                .size());
        for (User<?> user : gr1.getUserMembers())
        {
            assertTrue(gr2.getUserMembers().contains(user));
        }

        assertEquals(gr1.getGroupAdmins(), gr2.getGroupAdmins());
        assertEquals(gr1.getGroupAdmins().size(), gr2.getGroupAdmins().size());
        for (Group gr : gr1.getGroupAdmins())
        {
            assertTrue(gr2.getGroupAdmins().contains(gr));
        }

        assertEquals(gr1.getUserAdmins(), gr2.getUserAdmins());
        assertEquals(gr1.getUserAdmins().size(), gr2.getUserAdmins()
                .size());
        for (User<?> user : gr1.getUserAdmins())
        {
            assertTrue(gr2.getUserAdmins().contains(user));
        }

        assertEquals(gr1.getProperties(), gr2.getProperties());
        for (GroupProperty prop : gr1.getProperties())
        {
            assertTrue(gr2.getProperties().contains(prop));
        }
    }

}
