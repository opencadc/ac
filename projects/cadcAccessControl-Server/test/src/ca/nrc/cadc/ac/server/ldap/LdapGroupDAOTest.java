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

import ca.nrc.cadc.ac.ActivatedGroup;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.util.Log4jInit;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;
import java.util.Set;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;

public class LdapGroupDAOTest
{
    private static final Logger log = Logger.getLogger(LdapGroupDAOTest.class);
    
    static String server = "mach275.cadc.dao.nrc.ca";
    static int port = 389;
    static String adminDN = "uid=webproxy,ou=webproxy,ou=topologymanagement,o=netscaperoot";
    static String adminPW = "go4it";
    static String userBaseDN = "ou=Users,ou=ds,dc=canfartest,dc=net";
    static String groupBaseDN = "ou=Groups,ou=ds,dc=canfartest,dc=net";
    //static String userBaseDN = "ou=Users,ou=ds,dc=canfar,dc=net";
    //static String groupBaseDN = "ou=Groups,ou=ds,dc=canfar,dc=net";
    
    static String daoTestDN1 = "cn=cadcdaotest1,ou=cadc,o=hia,c=ca";
    static String daoTestDN2 = "cn=cadcdaotest2,ou=cadc,o=hia,c=ca";
    static String unknownDN = "cn=foo,ou=cadc,o=hia,c=ca";
    
    static X500Principal daoTestPrincipal1;
    static X500Principal daoTestPrincipal2;
    static X500Principal unknownPrincipal;
    static X500Principal adminPrincipal;
    
    static User<X500Principal> daoTestUser1;
    static User<X500Principal> daoTestUser2;
    static User<X500Principal> unknownUser;
    static User<X500Principal> adminUser;
    
    static Subject authSubject;
    static Subject anonSubject;
    
    static LdapConfig config;
    
    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);
        
        daoTestPrincipal1 = new X500Principal(daoTestDN1);
        daoTestPrincipal2 = new X500Principal(daoTestDN2);
        unknownPrincipal = new X500Principal(unknownDN);
        adminPrincipal = new X500Principal(adminDN);

        daoTestUser1 = new User<X500Principal>(daoTestPrincipal1);
        daoTestUser2 = new User<X500Principal>(daoTestPrincipal2);
        unknownUser = new User<X500Principal>(unknownPrincipal);
        adminUser = new User<X500Principal>(adminPrincipal);
        
        authSubject = new Subject();
        authSubject.getPrincipals().add(daoTestUser1.getUserID());
        
        anonSubject = new Subject();
        anonSubject.getPrincipals().add(unknownUser.getUserID());
    
        config = new LdapConfig(server, port, adminDN, adminPW, userBaseDN, groupBaseDN);
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
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
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

                    // groupRead
                    expectGroup.groupRead = otherGroup;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    expectGroup.groupRead = null;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // groupWrite
                    expectGroup.groupWrite = otherGroup;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    expectGroup.groupWrite = null;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // publicRead
                    expectGroup.publicRead = true;
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    expectGroup.publicRead = false;
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
                    expectGroup.groupRead = otherGroup;
                    expectGroup.groupWrite = otherGroup;
                    expectGroup.publicRead = true;
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
    
    // TODO: add test passing in groupID
    @Test
    public void testSearchOwnerGroups() throws Exception
    {
        // do everything as owner
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group testGroup = new Group(getGroupID(), daoTestUser1);
                    testGroup = getGroupDAO().addGroup(testGroup);
                    
                    Collection<Group> groups = 
                        getGroupDAO().searchGroups(daoTestUser1.getUserID(), 
                                                   Role.OWNER, null);

                    boolean found = false;
                    for (Group group : groups)
                    {
                        if (!group.getOwner().equals(daoTestUser1))
                        {
                            fail("returned group with wrong owner");
                        }
                        if (group.getID().equals(group.getID()))
                        {
                            found = true;
                        }
                    }
                    if (!found)
                    {
                        fail("Group for owner not found");
                    }
                    getGroupDAO().deleteGroup(testGroup.getID());
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }
    
    // TODO: add test passing in groupID
//    @Test
    public void testSearchMemberGroups() throws Exception
    {
        // do everything as owner
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {   
                    Group memberGroup = new Group(getGroupID(), daoTestUser2);
                    memberGroup = getGroupDAO().addGroup(memberGroup);
                    log.debug("member group: " + memberGroup.getID());
                    
                    Group testGroup = new Group(getGroupID(), daoTestUser1);
                    testGroup.getGroupMembers().add(memberGroup);
                    testGroup = getGroupDAO().addGroup(testGroup);
                    log.debug("test group: " + testGroup.getID());
                    
                    Collection<Group> groups = 
                        getGroupDAO().searchGroups(daoTestUser2.getUserID(), 
                                                   Role.MEMBER, null);
                    
                    log.debug("# groups found: " + groups.size());
                    boolean found = false;
                    for (Group group : groups)
                    {
                        log.debug("found group: " + group.getID());
                        if (group.equals(testGroup))
                        {
                            log.debug("found test group: " + group.getID());
                            Set<Group> members = group.getGroupMembers();

                            log.debug("#test group members: " + members.size());
                            for (Group member : members)
                            {
                                if (member.equals(memberGroup))
                                {
                                    found = true;
                                }
                            }
                        }
                    }
                    if (!found)
                    {
                        fail("Group member not found");
                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }
    
    // TODO: add test passing in groupID
//    @Test
    public void testSearchRWGroups() throws Exception
    {
        // do everything as owner
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {             
                    Group rwGroup = new Group(getGroupID(), daoTestUser2);
                    rwGroup = getGroupDAO().addGroup(rwGroup);
                    log.debug("rw group: " + rwGroup.getID());
                    
                    Group testGroup = new Group(getGroupID(), daoTestUser1);
                    testGroup.groupRead = rwGroup;
                    testGroup.groupWrite = rwGroup;
                    testGroup = getGroupDAO().addGroup(testGroup);
                    log.debug("test group: " + testGroup.getID());
                    
                    Collection<Group> groups = 
                        getGroupDAO().searchGroups(daoTestUser2.getUserID(), 
                                                   Role.RW, null);
                    System.out.println("# groups found: " + groups.size());
                    
                    boolean found = false;
                    for (Group group : groups)
                    {
                        System.out.println("found group: " + group.getID());
                        // get the group to get the owner 
                        // (not returned for RW groups)
                        group = getGroupDAO().getGroup(group.getID());
                        if (!group.getOwner().equals(daoTestUser2))
                        {
                            fail("returned group with wrong owner");
                        }
                        if (group.getID().equals(testGroup.getID()))
                        {
                            found = true;
                        }
                    }
                    if (!found)
                    {
                        fail("");
                    }
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {                    
                    getGroupDAO().addGroup(new Group("foo", unknownUser));
                    fail("addGroup with unknown user should throw " + 
                         "UserNotFoundException");
                }
                catch (UserNotFoundException ignore) {}
                
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {   
                getGroupDAO().deleteGroup(groupID);
                return null;
            }
        });
    }
    
    @Test
    public void testModifyGroupExceptions() throws Exception
    {        
        final String groupID = getGroupID();
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                
//                try
//                {
//                    getGroupDAO().modifyGroup(new Group(groupID, unknownUser));
//                    fail("modifyGroup with unknown user should throw " + 
//                         "UserNotFoundException");
//                }
//                catch (UserNotFoundException ignore) {}
                
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
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
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                
                try
                {
                    getGroupDAO().searchGroups(unknownPrincipal, Role.OWNER, 
                                               groupID);
                    fail("searchGroups with unknown user should throw " + 
                         "UserNotFoundException");
                }
                catch (UserNotFoundException ignore) {}
                
                try
                {
                    getGroupDAO().searchGroups(daoTestPrincipal1, Role.OWNER, 
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
                    getGroupDAO().searchGroups(daoTestPrincipal1, Role.OWNER, 
                                               groupID);
                    fail("searchGroups with anonymous access should throw " + 
                         "AccessControlException");
                }
                catch (AccessControlException ignore) {}
                return null;
            }
        });
        
        Subject.doAs(authSubject, new PrivilegedExceptionAction<Object>()
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
        assertEquals(gr1.getGroupMembers().size(), gr2.getGroupMembers()
                .size());
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
        assertEquals(gr1.publicRead, gr2.publicRead);
        assertEquals(gr1.groupRead, gr2.groupRead);
        assertEquals(gr1.groupWrite, gr2.groupWrite);
        assertEquals(gr1.groupWrite, gr2.groupWrite);
        assertEquals(gr1.getProperties(), gr2.getProperties());
        for (GroupProperty prop : gr1.getProperties())
        {
            assertTrue(gr2.getProperties().contains(prop));
        }
    }
    
}
