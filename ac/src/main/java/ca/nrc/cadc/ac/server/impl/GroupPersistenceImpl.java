/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2011.                            (c) 2011.
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

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.IdentityManagerImpl;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapGroupPersistence;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.ObjectUtil;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.util.StringUtil;
import java.net.URISyntaxException;
import java.security.AccessControlException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;

/**
 *
 * @author pdowler
 */
public class GroupPersistenceImpl extends LdapGroupPersistence
{
    private static final Logger log = Logger.getLogger(GroupPersistenceImpl.class);

    public static final String CONFIG_FILE = "ac-group-names.properties";

    private static User ARCHIVE_GROUP_OWNER;

    static
    {
        ARCHIVE_GROUP_OWNER = new User();
        ARCHIVE_GROUP_OWNER.getIdentities().add(new HttpPrincipal(("cadcops")));
        ARCHIVE_GROUP_OWNER.personalDetails = new PersonalDetails("cadc", "ops");
    }

    private final MultiValuedProperties config;

    public GroupPersistenceImpl()
    {
        super();
        PropertiesReader pr = new PropertiesReader(CONFIG_FILE);
        this.config = pr.getAllProperties();
        super.setDetailSelector(new ArchiveGroupDetailSelector(config.keySet()));
    }
    
    // for mock gest support
    IdentityManagerImpl getIdentityManager() {
        return new IdentityManagerImpl();
    }

    @Override
    public Group addGroup(final Group group)
        throws GroupAlreadyExistsException, TransientException,
               AccessControlException, UserNotFoundException,
               GroupNotFoundException
    {
        Subject caller  = AuthenticationUtil.getCurrentSubject();
        AuthUserAndGroup authUserAndGroup = validateGroupName(caller, group.getID().getName());
        if (authUserAndGroup == null)
        {
            return superAddGroup(group);
        }
        else
        {
            Subject authSubject = new Subject();
            authSubject.getPrincipals().add(authUserAndGroup.authUser);
            IdentityManagerImpl im = getIdentityManager();
            im.augmentSubject(authSubject);

            // make the owner of the group be the one in the
            // subject
            User owner = new User();
            owner.getIdentities().add(authUserAndGroup.authUser);
            ObjectUtil.setField(group, owner, "owner");

            if (authUserAndGroup.authGroup != null)
            {
                group.getGroupAdmins().add(authUserAndGroup.authGroup);
            }

            try
            {
                Group addedGroup = Subject.doAs(authSubject, new PrivilegedExceptionAction<Group>()
                {
                    @Override
                    public Group run() throws Exception
                    {
                        return superAddGroup(group);
                    }
                });
                
                return addedGroup;
            }
            catch (PrivilegedActionException e)
            {
                Throwable cause = e.getCause();
                if (cause != null)
                {
                    if (cause instanceof GroupAlreadyExistsException)
                    {
                        throw new GroupAlreadyExistsException(cause.getMessage());
                    }
                    else if (cause instanceof AccessControlException)
                    {
                        throw new AccessControlException(cause.getMessage());
                    }
                    else if (cause instanceof UserNotFoundException)
                    {
                        throw new UserNotFoundException(cause.getMessage());
                    }
                    else if (cause instanceof GroupNotFoundException)
                    {
                        throw new GroupNotFoundException(cause.getMessage());
                    }
                }
                throw new TransientException(e.getMessage());
            }
        }
    }

    @Override
    public Collection<Group> getGroups(Role role, String groupID)
        throws UserNotFoundException, GroupNotFoundException,
               TransientException, AccessControlException
    {
        Collection<Group> groups = super.getGroups(role, groupID);
        for (Group g : groups)
        {
            if (g.getOwner() == null)
            {
                ObjectUtil.setField(g, ARCHIVE_GROUP_OWNER, "owner");
            }
        }
        return groups;
    }

    // package access for unit-tests
    Group superAddGroup(final Group group)
        throws GroupAlreadyExistsException, TransientException,
        UserNotFoundException, GroupNotFoundException
    {
        return GroupPersistenceImpl.super.addGroup(group);
    }

    // package access for unit-tests
    Group superGetGroup(final Group group)
        throws GroupAlreadyExistsException, TransientException,
        UserNotFoundException, GroupNotFoundException
    {
        return GroupPersistenceImpl.super.getGroup(group.getID().getName());
    }

    AuthUserAndGroup validateGroupName(Subject caller, String groupName)
        throws GroupAlreadyExistsException, GroupNotFoundException,
               UserNotFoundException, TransientException
    {
        Set<HttpPrincipal> ps = caller.getPrincipals(HttpPrincipal.class);
        String username = null;
        HttpPrincipal httpPrincipal = null;
        if (!ps.isEmpty())
        {
            httpPrincipal = ps.iterator().next();
            username = httpPrincipal.getName();
        }

        log.debug("validateGroupName: " + username + " " + groupName);
        if (config == null)
            throw new RuntimeException("CONFIG ERROR: failed to read " + CONFIG_FILE);

        AuthUserAndGroup authUserAndGroup = getAuthUserAndGroup(groupName);
        if (authUserAndGroup != null)
        {
            log.debug("Auth user and group: " + authUserAndGroup);
            if (authUserAndGroup.authUser == null && authUserAndGroup.authGroup == null)
            {
                throw new AccessControlException("reserved group name prefix: " + authUserAndGroup.prefix);
            }

            log.debug(("validate user: " + username));
            if (username.equals(authUserAndGroup.authUser.getName()))
            {
                log.debug("config: " + authUserAndGroup.prefix + "=" + username +
                          " allows creation of: " + groupName);
            }
            else if (authUserAndGroup.authGroup != null && isMember(authUserAndGroup.authGroup.getID().getName()))
            {
                log.debug("config: " + authUserAndGroup.prefix + "=" +
                          authUserAndGroup.authGroup.getID() +
                          " allows creation of: " + groupName);
            }
            else
            {
                throw new AccessControlException("reserved group name prefix: " + authUserAndGroup.prefix);
            }
        }
        return authUserAndGroup;
    }

    AuthUserAndGroup getAuthUserAndGroup(final String groupName)
    {
        if (groupName == null || groupName.isEmpty())
        {
            throw new IllegalArgumentException("group name cannot be null or empty");
        }
        AuthUserAndGroup authUserAndGroup = null;
        for (String prefix : config.keySet())
        {
            if (StringUtil.startsWithCaseInsensitive(groupName, prefix))
            {
                authUserAndGroup = new AuthUserAndGroup();
                authUserAndGroup.prefix = prefix;

                List<String> properties = config.getProperty(prefix);
                if (!properties.isEmpty())
                {
                    String property = properties.get(0).trim();
                    if (!property.isEmpty())
                    {
                        String[] values = property.split("\\s+");
                        log.debug("auth user and group: " + Arrays.asList(values));

                        authUserAndGroup.authUser = new HttpPrincipal(values[0]);
                        if (values.length == 2)
                        {
                            try                            {
                                authUserAndGroup.authGroup = new Group(new GroupURI(values[1]));
                            } catch (URISyntaxException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }
                }
            }
        }
        return authUserAndGroup;
    }

    protected UserPersistence getUserPersistence()
    {
        PluginFactory pluginFactory = new PluginFactory();
        return pluginFactory.createUserPersistence();
    }

    boolean isMember(final String groupID)
        throws UserNotFoundException, GroupNotFoundException, TransientException
    {
        Collection<Group> groups = super.getGroups(Role.MEMBER, groupID);
        if (groups != null && !groups.isEmpty())
        {
            return true;
        }
        return false;
    }

    class AuthUserAndGroup
    {
        public String prefix;
        public HttpPrincipal authUser;
        public Group authGroup;

        public AuthUserAndGroup() {}

        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append("For prefix: " + prefix);
            sb.append(" authUser: " + authUser);
            sb.append(" authGroup: " + authGroup);
            return sb.toString();
        }
    }

}
