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

import java.lang.reflect.Field;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.ac.server.GroupDetailSelector;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.net.TransientException;

public class LdapGroupPersistence extends LdapPersistence implements GroupPersistence
{
    private static final Logger log =
            Logger.getLogger(LdapGroupPersistence.class);

    private GroupDetailSelector detailSelector;

    public LdapGroupPersistence()
    {
        super();
    }

    public void setDetailSelector(GroupDetailSelector gds)
    {
        this.detailSelector = gds;
    }

    /**
     * No-op.  UserPersistence will shutdown the
     * connection pool.
     */
    public void destroy()
    {
    }

    public Collection<String> getGroupNames()
        throws TransientException, AccessControlException
    {
        // current policy: group names visible to all authenticated users
        Subject caller = AuthenticationUtil.getCurrentSubject();
        if (caller == null || AuthMethod.ANON.equals(AuthenticationUtil.getAuthMethod(caller)))
            throw new AccessControlException("Caller is not authenticated");

        LdapGroupDAO groupDAO = null;
        LdapUserDAO userDAO = null;
        LdapConnections conns = new LdapConnections(this);
        try
        {
            userDAO = new LdapUserDAO(conns);
            groupDAO = new LdapGroupDAO(conns, userDAO);
            Collection<String> ret = groupDAO.getGroupNames();
            return ret;
        }
        finally
        {
            conns.releaseConnections();
        }
    }

    public Group getGroup(String groupName)
        throws GroupNotFoundException, TransientException,
               AccessControlException
    {
        Subject callerSubject = AuthenticationUtil.getCurrentSubject();
        boolean allowed = isMember(callerSubject, groupName) || isAdmin(callerSubject, groupName);

        LdapGroupDAO groupDAO = null;
        LdapUserDAO userDAO = null;
        LdapConnections conns = new LdapConnections(this);
        try
        {
            userDAO = new LdapUserDAO(conns);
            groupDAO = new LdapGroupDAO(conns, userDAO);
            Group ret = groupDAO.getGroup(groupName, true);
            if (allowed || isOwner(callerSubject, ret))
                return ret;
            throw new AccessControlException("permission denied");
        }
        finally
        {
            conns.releaseConnections();
        }
    }

    public void addGroup(Group group)
        throws GroupAlreadyExistsException, TransientException,
               AccessControlException, UserNotFoundException,
               GroupNotFoundException
    {
        Subject caller = AuthenticationUtil.getCurrentSubject();
        Principal userID = getUser(caller);

        LdapConnections conns = new LdapConnections(this);
        try
        {
            LdapUserDAO userDAO = new LdapUserDAO(conns);
            User owner = userDAO.getAugmentedUser(userID);
            setField(group, owner, "owner");
            LdapGroupDAO groupDAO = new LdapGroupDAO(conns, userDAO);
            groupDAO.addGroup(group);
        }
        finally
        {
            conns.releaseConnections();
        }
    }

    public void deleteGroup(String groupName)
        throws GroupNotFoundException, TransientException,
               AccessControlException
    {
        Subject callerSubject = AuthenticationUtil.getCurrentSubject();

        LdapGroupDAO groupDAO = null;
        LdapUserDAO userDAO = null;
        LdapConnections conns = new LdapConnections(this);
        try
        {
            userDAO = new LdapUserDAO(conns);
            groupDAO = new LdapGroupDAO(conns, userDAO);
            Group g = groupDAO.getGroup(groupName, false);
            if (isOwner(callerSubject, g))
                groupDAO.deleteGroup(groupName);
            else
                throw new AccessControlException("permission denied");
        }
        finally
        {
            conns.releaseConnections();
        }
    }

    public void modifyGroup(Group group)
        throws GroupNotFoundException, TransientException,
               AccessControlException, UserNotFoundException
    {
        Subject callerSubject = AuthenticationUtil.getCurrentSubject();
        boolean allowed = isAdmin(callerSubject, group.getID());

        LdapGroupDAO groupDAO = null;
        LdapUserDAO userDAO = null;
        LdapConnections conns = new LdapConnections(this);
        try
        {
            userDAO = new LdapUserDAO(conns);
            groupDAO = new LdapGroupDAO(conns, userDAO);
            if (!allowed)
            {
                Group g = groupDAO.getGroup(group.getID(), false);
                if (isOwner(callerSubject, g))
                    allowed = true;
            }
            if (allowed)
                // TODO: pass g into the modify so it doesn't have to do another get
                groupDAO.modifyGroup(group);
            else
                throw new AccessControlException("permission denied");
        }
        finally
        {
            conns.releaseConnections();
        }
    }

    /**
     *
     * @param role
     * @param groupID check membership in a specific group or null to get all groups
     * @return
     * @throws UserNotFoundException
     * @throws GroupNotFoundException
     * @throws TransientException
     * @throws AccessControlException
     */
    public Collection<Group> getGroups(Role role, String groupID)
        throws UserNotFoundException, GroupNotFoundException,
               TransientException, AccessControlException
    {
        Subject caller = AuthenticationUtil.getCurrentSubject();

        LdapConnections conns = new LdapConnections(this);
        try
        {
            LdapUserDAO userDAO = new LdapUserDAO(conns);
            LdapGroupDAO  groupDAO = new LdapGroupDAO(conns, userDAO);

            if ( Role.OWNER.equals(role))
            {
                DNPrincipal p = getInternalID(caller);
                Collection<Group> ret = groupDAO.getOwnerGroups(p, groupID);
                return ret;
            }
            else
            {
                List<Group> groups = getGroupCache(caller, role);
                log.debug("getGroups  " + role + ": " + groups.size());
                Collection<Group> ret = new ArrayList<Group>(groups.size());
                Iterator<Group> i = groups.iterator();
                while ( i.hasNext() )
                {
                    Group g = i.next();
                    if (groupID == null || g.getID().equalsIgnoreCase(groupID))
                    {
                        if (detailSelector != null && detailSelector.isDetailedSearch(g, role))
                        {
                            try
                            {
                                Group g2 = groupDAO.getGroup(g.getID(), false);
                                log.debug("role " + role + " loaded: " + g2);
                                ret.add(g2);
                            }
                            catch(GroupNotFoundException contentBug)
                            {
                                log.error("group: " + g.getID() + " in cache but not found", contentBug);
                                // skip and continue so user gets something
                            }
                        }
                        else
                            ret.add(g);
                    }
                }
                return ret;
            }
        }
        catch(TransientException ex)
        {
            log.error("getGroups fail", ex);
            throw ex;
        }
        finally
        {
            conns.releaseConnections();
        }
    }

    // GroupMemberships cache created by AuthenticatorImpl
    private List<Group> getGroupCache(Subject caller, Role role)
    {
        if (caller == null || AuthMethod.ANON.equals(AuthenticationUtil.getAuthMethod(caller)))
            throw new AccessControlException("Caller is not authenticated");

        Set<GroupMemberships> gset = caller.getPrivateCredentials(GroupMemberships.class);
        if (gset == null || gset.isEmpty())
            throw new RuntimeException("BUG: no GroupMemberships cache in Subject");
        GroupMemberships gms = gset.iterator().next();
        return gms.getMemberships(role);
    }

    // true if the current subject is a member: using GroupMemberships cache
    private boolean isMember(Subject caller, String groupName)
    {
        List<Group> groups = getGroupCache(caller, Role.MEMBER);
        for (Group g : groups)
        {
            if (g.getID().equalsIgnoreCase(groupName))
                return true;
        }
        return false;
    }

    private boolean isAdmin(Subject caller, String groupName)
    {
        List<Group> groups = getGroupCache(caller, Role.ADMIN);
        for (Group g : groups)
        {
            if (g.getID().equalsIgnoreCase(groupName))
                return true;
        }
        return false;
    }

    private boolean isOwner(Subject caller, Group g)
    {
        if (caller == null || AuthMethod.ANON.equals(AuthenticationUtil.getAuthMethod(caller)))
            throw new AccessControlException("Caller is not authenticated");

        // check owner
        for (Principal pc : caller.getPrincipals())
        {
            for (Principal po : g.getOwner().getIdentities())
            {
                if (AuthenticationUtil.equals(pc, po))
                    return true;
            }
        }
        return false;
    }

    private DNPrincipal getInternalID(Subject caller)
    {
        if (caller == null || AuthMethod.ANON.equals(AuthenticationUtil.getAuthMethod(caller)))
            throw new AccessControlException("Caller is not authenticated");

        Set<DNPrincipal> ds = caller.getPrincipals(DNPrincipal.class);
        if (ds.isEmpty())
            return null;
        return ds.iterator().next();
    }

    private Principal getUser(Subject caller)
    {
        if (caller == null || AuthMethod.ANON.equals(AuthenticationUtil.getAuthMethod(caller)))
            throw new AccessControlException("Caller is not authenticated");

        Set<GroupMemberships> gset = caller.getPrivateCredentials(GroupMemberships.class);
        if (gset == null || gset.isEmpty())
            throw new RuntimeException("BUG: no GroupMemberships cache in Subject");
        GroupMemberships gms = gset.iterator().next();
        return gms.getUserID();
    }

    // set private field using reflection
    private void setField(Object object, Object value, String name)
    {
        try
        {
            Field field = object.getClass().getDeclaredField(name);
            field.setAccessible(true);
            field.set(object, value);
        }
        catch (NoSuchFieldException e)
        {
            final String error = object.getClass().getSimpleName() +
                " field " + name + "not found";
            throw new RuntimeException(error, e);
        }
        catch (IllegalAccessException e)
        {
            final String error = "unable to update " + name + " in " +
                object.getClass().getSimpleName();
            throw new RuntimeException(error, e);
        }
    }
}
