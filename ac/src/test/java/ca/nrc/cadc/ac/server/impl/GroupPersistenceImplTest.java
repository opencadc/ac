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
*  $Revision: 5 $
*
************************************************************************
*/

package ca.nrc.cadc.ac.server.impl;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.net.URI;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opencadc.gms.GroupURI;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.IdentityManagerImpl;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import java.security.AccessControlException;
import org.junit.Ignore;

/**
 *
 * @author pdowler
 */
public class GroupPersistenceImplTest
{
    private static final Logger log = Logger.getLogger(GroupPersistenceImplTest.class);

    private static final String ALLOWED_USER_PREFIX = "ALLOWED_USER-";
    private static final String ALLOWED_GROUP_PREFIX = "ALLOWED_USER_AND_GROUP-";

    private static HttpPrincipal allowedPrincipal;
    private static Subject allowedSubject;
    private static Group allowedGroup;
    private static Subject deniedSubject;
    private static String configPath;

    @BeforeClass
    public static void beforeClass() throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);

        File conf = FileUtil.getFileFromResource(GroupPersistenceImpl.CONFIG_FILE, GroupPersistenceImplTest.class);

        allowedPrincipal = new HttpPrincipal("allowed-user");
        allowedSubject = new Subject();
        allowedSubject.getPrincipals().add(allowedPrincipal);

        HttpPrincipal dp = new HttpPrincipal("denied-user");
        deniedSubject = new Subject();
        deniedSubject.getPrincipals().add(dp);

        LocalAuthority localAuthority = new LocalAuthority();
        URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());

        allowedGroup = new Group(new GroupURI(gmsServiceURI + "?allowed-group"));

        configPath = conf.getParent(); // build.xml copies it into same place
        log.info("config path: " + configPath);
        System.setProperty(PropertiesReader.class.getName() + ".dir", configPath);
    }

    @Test
    @Ignore
    public void testGetAuthUserAndGroup()
    {
        try
        {
            System.setProperty("java.naming.factory.initial", TestContextFactory.class.getName());

            GroupPersistenceImpl impl = new GroupPersistenceImpl();

            GroupPersistenceImpl.AuthUserAndGroup auth;

            try
            {
                auth = impl.getAuthUserAndGroup(null);
                fail("null group name should throw exception");
            }
            catch (IllegalArgumentException expected) {}

            auth = impl.getAuthUserAndGroup("foo");
            assertNull("should be null for unknown group name", auth);

            auth = impl.getAuthUserAndGroup(ALLOWED_USER_PREFIX + "123");
            assertNotNull("should not be null", auth);
            assertNotNull(auth.authUser);
            assertEquals(auth.authUser, allowedPrincipal);
            assertNull(auth.authGroup);

            auth = impl.getAuthUserAndGroup(ALLOWED_GROUP_PREFIX + "123");
            assertNotNull("should not be null", auth);
            assertNotNull(auth.authUser);
            assertEquals(auth.authUser, allowedPrincipal);
            assertNotNull(auth.authGroup);
            assertEquals(auth.authGroup, allowedGroup);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    @Ignore
    public void testValidateGroupWithUser()
    {
        try
        {
            System.setProperty("java.naming.factory.initial", TestContextFactory.class.getName());

            GroupPersistenceImpl impl = new GroupPersistenceImpl();

            // non-matching group names
            GroupPersistenceImpl.AuthUserAndGroup authUserAndGroup;
            authUserAndGroup = impl.validateGroupName(allowedSubject, "some-group");
            assertNull("auth user is not null", authUserAndGroup);

            authUserAndGroup = impl.validateGroupName(deniedSubject, "some-group");
            assertNull("auth user is not null", authUserAndGroup);

            // matching DENY-
            try
            {
                impl.validateGroupName(allowedSubject, "DENY-123");
                fail("denied group prefix should throw AccessControlException");
            }
            catch(AccessControlException expected)
            {
                log.debug("caught expected exception: " + expected);
            }

            try
            {
                impl.validateGroupName(deniedSubject, "deny-123");
                fail("denied group prefix should throw AccessControlException");
            }
            catch(AccessControlException expected)
            {
                log.debug("caught expected exception: " + expected);
            }

            try
            {
                impl.validateGroupName(deniedSubject, "Deny-123");
                fail("denied group prefix should throw AccessControlException");
            }
            catch(AccessControlException expected)
            {
                log.debug("caught expected exception: " + expected);
            }

            // matching ALLOWED_USER-
            authUserAndGroup = impl.validateGroupName(allowedSubject, "ALLOWED_USER-123");
            assertNotNull("auth user is null", authUserAndGroup);
            assertEquals("", new HttpPrincipal("allowed-user"), authUserAndGroup.authUser);


            // denied user
            impl = new GroupPersistenceImpl()
            {
                @Override
                boolean isMember(String groupID) throws UserNotFoundException, GroupNotFoundException, TransientException
                {
                    return true;
                }
            };

            try
            {
                impl.validateGroupName(deniedSubject, "ALLOWED_USER-123");
                fail("denied subject should throw AccessControlException");
            }
            catch(AccessControlException expected)
            {
                log.debug("caught expected exception: " + expected);
            }
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    @Ignore
    public void testValidateGroupWithGroup()
    {
        try
        {
            System.setProperty("java.naming.factory.initial", TestContextFactory.class.getName());

            // non-matching ALLOWED_USER_AND_GROUP-
            GroupPersistenceImpl impl = new GroupPersistenceImpl()
            {
                @Override
                boolean isMember(String groupID)
                    throws UserNotFoundException, GroupNotFoundException, TransientException
                {
                    return false;
                }
            };

            try
            {
                impl.validateGroupName(deniedSubject, "ALLOWED_USER_AND_GROUP-123");
                fail("subject not in group should throw exception");
            }
            catch (AccessControlException expected) {}

            // matching ALLOWED_USER_AND_GROUP-
            impl = new GroupPersistenceImpl()
            {
                @Override
                boolean isMember(String groupID)
                    throws UserNotFoundException, GroupNotFoundException, TransientException
                {
                    return true;
                }
            };

            GroupPersistenceImpl.AuthUserAndGroup authUserAndGroup =
                impl.validateGroupName(deniedSubject, "ALLOWED_USER_AND_GROUP-123");
            assertNotNull("auth user is null", authUserAndGroup);
            assertEquals("", new HttpPrincipal("allowed-user"), authUserAndGroup.authUser);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    @Ignore
    public void testAddGroupWithoutReservedPrefix()
    {
        try
        {
            System.setProperty("java.naming.factory.initial", TestContextFactory.class.getName());

            final GroupPersistenceImpl impl = new GroupPersistenceImpl()
            {
                Group g;

                @Override
                AuthUserAndGroup validateGroupName(Subject caller, String gname)
                    throws GroupAlreadyExistsException, UserNotFoundException, TransientException
                {
                    return null;
                }

                @Override
                Group superAddGroup(final Group group)
                    throws GroupAlreadyExistsException, TransientException,
                    UserNotFoundException, GroupNotFoundException
                {
                    return g = group;
                }

                @Override
                Group superGetGroup(final Group group)
                    throws GroupAlreadyExistsException, TransientException,
                    UserNotFoundException, GroupNotFoundException
                {
                    return g;
                }
            };

            LocalAuthority localAuthority = new LocalAuthority();
            URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());

            final Group expected = new Group(new GroupURI(gmsServiceURI + "?foo"));

            Group actual = Subject.doAs(allowedSubject, new PrivilegedExceptionAction<Group>()
            {
                @Override
                public Group run() throws Exception
                {
                    impl.addGroup(expected);
                    return impl.superGetGroup(expected);
                }
            });

            assertNotNull("group is null", actual);
            assertEquals("groups do not match", expected, actual);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    @Ignore
    public void testAddGroupWithReservedPrefix()
    {
        try
        {
            System.setProperty("java.naming.factory.initial", TestContextFactory.class.getName());

            final IdentityManagerImpl mockIM = EasyMock.createMock(IdentityManagerImpl.class);
            mockIM.augmentSubject(allowedSubject);
            EasyMock.expectLastCall().once();
            EasyMock.replay(mockIM);

            final GroupPersistenceImpl impl = new GroupPersistenceImpl()
            {
                Group g;

                @Override
                AuthUserAndGroup validateGroupName(Subject caller, String gname)
                    throws GroupAlreadyExistsException, UserNotFoundException, TransientException
                {
                    AuthUserAndGroup auth = new AuthUserAndGroup();
                    auth.authUser = allowedPrincipal;
                    return auth;
                }

                @Override
                Group superAddGroup(final Group group)
                    throws GroupAlreadyExistsException, TransientException,
                    UserNotFoundException, GroupNotFoundException
                {
                    return g = group;
                }

                @Override
                Group superGetGroup(final Group group)
                    throws GroupAlreadyExistsException, TransientException,
                    UserNotFoundException, GroupNotFoundException
                {
                    return g;
                }

                @Override
                IdentityManagerImpl getIdentityManager()
                {
                    return mockIM;
                }
            };

            LocalAuthority localAuthority = new LocalAuthority();
            URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());
            final Group expected = new Group(new GroupURI(URI.create(gmsServiceURI + "?ALLOWED_USER-123")));

            Group actual = Subject.doAs(allowedSubject, new PrivilegedExceptionAction<Group>()
            {
                @Override
                public Group run() throws Exception
                {
                    impl.addGroup(expected);
                    return impl.superGetGroup(expected);
                }
            });

            assertNotNull("group is null", actual);
            assertEquals("groups do not match", expected, actual);

            EasyMock.verify(mockIM);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    @Ignore
    public void testAddGroupGroupAlreadyExistsException()
    {
        try
        {
            System.setProperty("java.naming.factory.initial", TestContextFactory.class.getName());

            final IdentityManagerImpl mockIM = EasyMock.createMock(IdentityManagerImpl.class);
            mockIM.augmentSubject(allowedSubject);
            EasyMock.expectLastCall().once();
            EasyMock.replay(mockIM);

            final GroupPersistenceImpl impl = new GroupPersistenceImpl()
            {
                @Override
                AuthUserAndGroup validateGroupName(Subject caller, String gname)
                    throws GroupAlreadyExistsException, UserNotFoundException, TransientException
                {
                    AuthUserAndGroup auth = new AuthUserAndGroup();
                    auth.authUser = allowedPrincipal;
                    return auth;
                }

                @Override
                Group superAddGroup(final Group group)
                    throws GroupAlreadyExistsException, TransientException,
                    UserNotFoundException, GroupNotFoundException
                {
                    throw new GroupAlreadyExistsException("group exists");
                }

                @Override
                IdentityManagerImpl getIdentityManager()
                {
                    return mockIM;
                }
            };

            LocalAuthority localAuthority = new LocalAuthority();
            URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());

            final Group expected = new Group(new GroupURI(gmsServiceURI + "?ALLOWED_USER-123"));

            Subject.doAs(allowedSubject, new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    try
                    {
                        impl.addGroup(expected);
                        fail("should have thrown GroupAlreadyExistsException");
                    }
                    catch (GroupAlreadyExistsException e)
                    {
                        assertEquals("wrong message", "group exists", e.getMessage());
                    }
                    return null;
                }
            });

            EasyMock.verify(mockIM);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            fail("unexpected exception: " + unexpected);
        }
    }

}
