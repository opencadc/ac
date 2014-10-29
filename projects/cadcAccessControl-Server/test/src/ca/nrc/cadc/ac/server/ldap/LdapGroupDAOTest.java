/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2014.                            (c) 2014.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 * 
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import static org.junit.Assert.assertEquals;
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

import ca.nrc.cadc.ac.ActivatedGroup;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.util.Log4jInit;
import static org.junit.Assert.assertNotNull;

public class LdapGroupDAOTest
{
    private static final Logger log = Logger.getLogger(LdapGroupDAOTest.class);
    
    static String adminDN = "uid=webproxy,ou=SpecialUsers,dc=canfar,dc=net";
//    static String usersDN = "ou=Users,ou=ds,dc=canfar,dc=net";
//    static String groupsDN = "ou=Groups,ou=ds,dc=canfar,dc=net";
    
    static String daoTestDN1 = "cn=cadcdaotest1,ou=cadc,o=hia,c=ca";
    static String daoTestDN2 = "cn=cadcdaotest2,ou=cadc,o=hia,c=ca";
    static String daoTestDN3 = "cn=cadcdaotest3,ou=cadc,o=hia,c=ca";
    static String unknownDN = "cn=foo,ou=cadc,o=hia,c=ca";
    
    static X500Principal daoTestPrincipal1;
    static X500Principal daoTestPrincipal2;
    static X500Principal daoTestPrincipal3;
    static X500Principal unknownPrincipal;
    static X500Principal adminPrincipal;
    
    static User<X500Principal> daoTestUser1;
    static User<X500Principal> daoTestUser2;
    static User<X500Principal> daoTestUser3;
    static User<X500Principal> unknownUser;
    static User<X500Principal> adminUser;
    
    static Subject daoTestUser1Subject;
    static Subject daoTestUser2Subject;
    static Subject anonSubject;

    final LdapConfig config = new TestLDAPConfig();
    
    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);
        
        daoTestPrincipal1 = new X500Principal(daoTestDN1);
        daoTestPrincipal2 = new X500Principal(daoTestDN2);
        daoTestPrincipal3 = new X500Principal(daoTestDN3);
        unknownPrincipal = new X500Principal(unknownDN);
        adminPrincipal = new X500Principal(adminDN);

        daoTestUser1 = new User<X500Principal>(daoTestPrincipal1);
        daoTestUser2 = new User<X500Principal>(daoTestPrincipal2);
        daoTestUser3 = new User<X500Principal>(daoTestPrincipal3);
        unknownUser = new User<X500Principal>(unknownPrincipal);
        adminUser = new User<X500Principal>(adminPrincipal);
        
        daoTestUser1Subject = new Subject();
        daoTestUser1Subject.getPrincipals().add(daoTestUser1.getUserID());
        
        daoTestUser2Subject = new Subject();
        daoTestUser2Subject.getPrincipals().add(daoTestUser2.getUserID());
        
        anonSubject = new Subject();
        anonSubject.getPrincipals().add(unknownUser.getUserID());
    }

    LdapGroupDAO<X500Principal> getGroupDAO()
    {
        return new LdapGroupDAO<X500Principal>(config,
                new LdapUserDAO<X500Principal>(config));
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
                    Group actualGroup = getGroupDAO().addGroup(expectGroup);
                    log.debug("addGroup: " + expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    Group otherGroup = new Group(getGroupID(), daoTestUser1);
                    otherGroup = getGroupDAO().addGroup(otherGroup);
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
                    
                    // delete the group
                    expectGroup.description = "Happy testing";
                    expectGroup.getUserMembers().add(daoTestUser2);
                    expectGroup.getGroupMembers().add(otherGroup);
                    
                    getGroupDAO().deleteGroup(expectGroup.getID());
                    try
                    {
                        getGroupDAO().getGroup(expectGroup.getID());
                        fail("get on deleted group should throw exception");
                    }
                    catch (GroupNotFoundException ignore) {}
                    
                    // reactivate the group
                    actualGroup = getGroupDAO().addGroup(expectGroup);
                    assertTrue(actualGroup instanceof ActivatedGroup);
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    // get the activated group
                    actualGroup = getGroupDAO().getGroup(expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    // delete the group
                    getGroupDAO().deleteGroup(expectGroup.getID());
                    
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
                    testGroup = getGroupDAO().addGroup(testGroup);
                    
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
                    testGroup1 = getGroupDAO().addGroup(testGroup1);
                    log.debug("add group: " + testGroup1ID);
                    
                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    testGroup2.getUserMembers().add(daoTestUser2);
                    testGroup2 = getGroupDAO().addGroup(testGroup2);
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
                    testGroup1 = getGroupDAO().addGroup(testGroup1);
                    log.debug("add group: " + testGroup1ID);
                    
                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    testGroup2.getUserAdmins().add(daoTestUser2);
                    testGroup2 = getGroupDAO().addGroup(testGroup2);
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
                    testGroup1 = getGroupDAO().addGroup(testGroup1);
                    log.debug("add group: " + testGroup1ID);

                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    testGroup2 = getGroupDAO().addGroup(testGroup2);
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

        Subject.doAs(daoTestUser2Subject, new PrivilegedExceptionAction<Object>()
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
                
                Group group = getGroupDAO().addGroup(new Group(getGroupID(), 
                                                     daoTestUser1));
                
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
                         "UserNotFoundException");
                }
                catch (UserNotFoundException ignore) {}
                
                try
                {
                    getGroupDAO().getGroups(daoTestPrincipal1, Role.OWNER, 
                                               "foo");
                    fail("searchGroups with unknown user should throw " + 
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
        assertEquals(gr1.getProperties(), gr2.getProperties());
        for (GroupProperty prop : gr1.getProperties())
        {
            assertTrue(gr2.getProperties().contains(prop));
        }
    }
    
}
