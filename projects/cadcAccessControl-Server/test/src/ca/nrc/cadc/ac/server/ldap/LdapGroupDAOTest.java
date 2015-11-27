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
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import org.junit.Assert;

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
    static String daoTestEntryDN3 = "uid=cadcdaotest3,ou=users,ou=ds,dc=testcanfar";

    static DNPrincipal daoDNPrincipal1;
    static DNPrincipal daoDNPrincipal2;
    static DNPrincipal daoDNPrincipal3;

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
        daoTestUser1.getIdentities().add(daoDNPrincipal1);
        daoTestUser2 = new User<X500Principal>(daoTestPrincipal2);
        daoTestUser2.getIdentities().add(daoDNPrincipal2);
        daoTestUser3 = new User<X500Principal>(daoTestPrincipal3);
        daoTestUser3.getIdentities().add(daoDNPrincipal3);
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
                    Group actualGroup = getGroupDAO().getGroup(expectGroup.getID(), true);
                    log.info("addGroup: " + expectGroup.getID());
                    assertGroupsEqual(expectGroup, actualGroup);

                    Group otherGroup = new Group(getGroupID(), daoTestUser1);
                    getGroupDAO().addGroup(otherGroup);
                    otherGroup = getGroupDAO().getGroup(otherGroup.getID(), true);
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

                    expectGroup.getUserAdmins().remove(daoTestUser3);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // groupAdmins
                    Group adminGroup = new Group(getGroupID(), daoTestUser1);
                    getGroupDAO().addGroup(adminGroup);
                    adminGroup = getGroupDAO().getGroup(adminGroup.getID(), true);
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
                    expectGroup.getUserAdmins().add(daoTestUser2);
                    expectGroup.getUserAdmins().add(duplicateIdentity);
                    actualGroup = getGroupDAO().modifyGroup(expectGroup);
                    expectGroup.getUserAdmins().remove(duplicateIdentity);
                    assertGroupsEqual(expectGroup, actualGroup);

                    // delete the group
                    getGroupDAO().deleteGroup(expectGroup.getID());
                    try
                    {
                        getGroupDAO().getGroup(expectGroup.getID(), false);
                        fail("get on deleted group should throw exception");
                    }
                    catch (GroupNotFoundException ignore) {}
                    log.info("deleted group: " + expectGroup.getID());

                    // reactivate the group
                    Group reactGroup = new Group(expectGroup.getID(), expectGroup.getOwner());
                    getGroupDAO().addGroup(reactGroup);
                    log.info("create (reactivate) group: " + expectGroup.getID());
                    actualGroup = getGroupDAO().getGroup(expectGroup.getID(), true);
                    assertTrue(actualGroup.getUserMembers().isEmpty());
                    assertTrue(actualGroup.getGroupMembers().isEmpty());
                    assertTrue(actualGroup.getUserAdmins().isEmpty());
                    assertTrue(actualGroup.getGroupAdmins().isEmpty());
                    Assert.assertTrue(actualGroup.getProperties().isEmpty());

                    // create another group and make expected group
                    // member of that group. Delete expected group after
                    Group expectGroup2 = new Group(getGroupID(), daoTestUser1);
                    expectGroup2.getGroupAdmins().add(actualGroup);
                    expectGroup2.getGroupMembers().add(actualGroup);
                    getGroupDAO().addGroup(expectGroup2);
                    Group actualGroup2 = getGroupDAO().getGroup(expectGroup2.getID(), true);
                    log.debug("addGroup: " + expectGroup2.getID());
                    assertGroupsEqual(expectGroup2, actualGroup2);

                    // delete the group
                    getGroupDAO().deleteGroup(actualGroup.getID());
                    
                    // should not be member of admin of expectGroup2
                    expectGroup2.getGroupAdmins().remove(actualGroup);
                    expectGroup2.getGroupMembers().remove(actualGroup);
                    actualGroup2 = getGroupDAO().getGroup(expectGroup2.getID(), true);
                    log.debug("addGroup: " + expectGroup2.getID());
                    assertGroupsEqual(expectGroup2, actualGroup2);

                    return null;
                }
                catch (Exception e)
                {
                    log.error("unexpected exception", e);
                    throw new Exception("Problems", e);
                }
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
                    testGroup1 = getGroupDAO().getGroup(testGroup1.getID(), true);
                    log.debug("add group: " + testGroup1ID);

                    Group testGroup2 = new Group(testGroup2ID, daoTestUser1);
                    getGroupDAO().addGroup(testGroup2);
                    testGroup2 = getGroupDAO().getGroup(testGroup2.getID(), true);
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
    public void testGetGroupExceptions() throws Exception
    {
        final String groupID = getGroupID();

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                try
                {
                    getGroupDAO().getGroup(groupID, false);
                    fail("getGroup with unknown group should throw " +
                         "GroupNotFoundException");
                }
                catch (GroupNotFoundException ignore) {}
                
                try
                {
                    getGroupDAO().getGroup(groupID, true);
                    fail("getGroup with unknown group should throw " +
                         "GroupNotFoundException");
                }
                catch (GroupNotFoundException ignore) {}

                getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                return null;
            }
        });
    }

    @Test
    public void testModifyGroupExceptions() throws Exception
    {
        final String groupID = getGroupID();

        Subject.doAs(daoTestUser1Subject, new PrivilegedExceptionAction<Object>()
        {
            public Object run() throws Exception
            {
                //getGroupDAO().addGroup(new Group(groupID, daoTestUser1));
                try
                {
                    getGroupDAO().modifyGroup(new Group("fooBOGUSASFgomsi",
                                                        daoTestUser1));
                    fail("modifyGroup with unknown user should throw " +
                         "GroupNotFoundException");
                }
                catch (GroupNotFoundException ignore) {}

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
                getGroupDAO().deleteGroup(groupID); // should silently succeed
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
