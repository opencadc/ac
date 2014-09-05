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
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.util.Log4jInit;
import java.util.Collection;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;

public class LdapGroupDAOTest
{
    private static final Logger log = Logger.getLogger(LdapGroupDAOTest.class);
    
    static User<X500Principal> cadctest;
    static User<X500Principal> authtest1;
    static User<X500Principal> authtest2;
    static User<X500Principal> regtest1;
    
    static LdapConfig config;
    
    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);

        cadctest = new User<X500Principal>(
                new X500Principal("CN=CADCtest_636,OU=CADC,O=HIA,C=CA"));
        authtest1 = new User<X500Principal>(
                new X500Principal("cn=cadc authtest1 10627,ou=cadc,o=hia"));
        authtest2 = new User<X500Principal>(
                new X500Principal("cn=cadc authtest2 10635,ou=cadc,o=hia"));
        regtest1 = new User<X500Principal>(
                new X500Principal("CN=CADC Regtest1 10577,OU=CADC,O=HIA"));
    
        config = new LdapConfig("mach275.cadc.dao.nrc.ca", 389,
            "uid=webproxy,ou=administrators,ou=topologymanagement,o=netscaperoot",
            "go4it", "ou=Users,ou=ds,dc=canfar,dc=net",
            "ou=TestGroups,ou=ds,dc=canfar,dc=net",
            "ou=DeletedGroups,ou=ds,dc=canfar,dc=net");
    }

    LdapGroupDAO<X500Principal> getGroupDAO()
    {
        return new LdapGroupDAO<X500Principal>(config,
                new LdapUserDAO<X500Principal>(config));
    }
    
    String getGroupID()
    {
        return "acs-daotest-group1-" + System.currentTimeMillis();
    }

    @Test
    public void testOneGroup() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(authtest1.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group expectGroup = new Group(getGroupID(), authtest1);
                    Group actualGroup = getGroupDAO().addGroup(expectGroup);
                    log.debug("addGroup: " + expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);
                    
                    Group otherGroup = new Group(getGroupID(), authtest1);
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

                    // groupWrite
                    expectGroup.groupWrite = otherGroup;
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
                    expectGroup.getUserMembers().add(authtest2);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    expectGroup.getUserMembers().remove(authtest2);
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
    
//    @Test
    public void testSearchOwnerGroups() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(authtest1.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    Group expectGroup = new Group(getGroupID(), authtest1);
                    Group actualGroup = getGroupDAO().addGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);
                    System.out.println("new group: " + expectGroup.getID());
                    
                    Collection<Group> groups = 
                        getGroupDAO().searchGroups(authtest1.getUserID(), 
                                                   Role.OWNER, null);
                    System.out.println("# groups found: " + groups.size());
                    boolean found = false;
                    for (Group group : groups)
                    {
                        System.out.println("found group: " + group.getID());
                        if (!group.getOwner().equals(authtest1))
                        {
                            fail("returned group with wrong owner");
                        }
                        if (group.getID().equals(expectGroup.getID()))
                        {
                            found = true;
                        }
                    }
                    if (!found)
                    {
                        fail("");
                    }
                    getGroupDAO().deleteGroup(expectGroup.getID());
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }
    
//    @Test
    public void testSearchMemberGroups() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(cadctest.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {                    
                    Collection<Group> groups = 
                        getGroupDAO().searchGroups(cadctest.getUserID(), 
                                                   Role.MEMBER, null);
                    System.out.println("# groups found: " + groups.size());
//                    boolean found = false;
//                    for (Group group : groups)
//                    {
//                        System.out.println("found group: " + group.getID());
//                        if (!group.getOwner().equals(cadctest))
//                        {
//                            fail("returned group with wrong owner");
//                        }
//                        if (group.getID().equals(groupID1))
//                        {
//                            found = true;
//                        }
//                    }
//                    if (!found)
//                    {
//                        fail("");
//                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
                return null;
            }
        });
    }
    
//    @Test
    public void testSearchRWGroups() throws Exception
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(authtest1.getUserID());

        // do everything as owner
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {                    
                    Collection<Group> groups = 
                        getGroupDAO().searchGroups(authtest1.getUserID(), 
                                                   Role.RW, null);
                    System.out.println("# groups found: " + groups.size());
//                    boolean found = false;
//                    for (Group group : groups)
//                    {
//                        System.out.println("found group: " + group.getID());
//                        if (!group.getOwner().equals(authtest1))
//                        {
//                            fail("returned group with wrong owner");
//                        }
//                        if (group.getID().equals(groupID1))
//                        {
//                            found = true;
//                        }
//                    }
//                    if (!found)
//                    {
//                        fail("");
//                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
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
