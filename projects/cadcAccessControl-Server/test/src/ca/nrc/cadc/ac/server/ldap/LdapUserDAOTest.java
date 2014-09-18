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

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.util.Log4jInit;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jburke
 */
public class LdapUserDAOTest
{
    private static final Logger log = Logger.getLogger(LdapUserDAOTest.class);
    
    static String server = "mach275.cadc.dao.nrc.ca";
    static int port = 389;
    static String adminDN = "uid=webproxy,ou=Webproxy,ou=topologymanagement,o=netscaperoot";
    static String adminPW = "go4it";
    static String usersDN = "ou=Users,ou=ds,dc=canfartest,dc=net";
    static String groupsDN = "ou=Groups,ou=ds,dc=canfartest,dc=net";
    static String adminGroupsDN = "ou=adminGroups,ou=ds,dc=canfartest,dc=net";
//    static String userBaseDN = "ou=Users,ou=ds,dc=canfar,dc=net";
//    static String groupBaseDN = "ou=Groups,ou=ds,dc=canfar,dc=net";
    
    static final String testUserDN = "cn=cadcdaotest1,ou=cadc,o=hia,c=ca";
    
    static User<X500Principal> testUser;
    static LdapConfig config;
    
    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);
        
        testUser = new User<X500Principal>(new X500Principal(testUserDN));
    
        config = new LdapConfig(server, port, adminDN, adminPW, usersDN, groupsDN, adminGroupsDN);
    }

    LdapUserDAO<X500Principal> getUserDAO()
    {
        return new LdapUserDAO<X500Principal>(config);
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
                    User actual = getUserDAO().getUser(testUser.getUserID());
                    assertEquals(testUser, actual);
                    
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
//    @Test
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
                    Collection<Group> groups = getUserDAO().getUserGroups(testUser.getUserID());
                    assertNotNull(groups);
                    assertTrue(!groups.isEmpty());
                    for (Group group : groups)
                        log.debug(group);
                    
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
//    @Test
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
                    assertFalse(isMember);
                    
                    String groupID = "cn=cadcdaotestgroup,cn=groups,ou=ds,dc=canfartest,dc=net";
                    isMember = getUserDAO().isMember(testUser.getUserID(), groupID);
                    assertTrue(isMember);
                    
                    return null;
                }
                catch (Exception e)
                {
                    throw new Exception("Problems", e);
                }
            }
        });
    }
    
}
