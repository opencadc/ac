/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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
import java.net.URI;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;

import ca.nrc.cadc.ac.ActivatedGroup;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.GroupDetailSelector;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.StringUtil;

public class LdapGroupDAO extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapGroupDAO.class);

    // LDAP Group attributes
    protected static final String LDAP_DESCRIPTION = "description";
    protected static final String LDAP_GROUP_OF_UNIQUE_NAMES = "groupofuniquenames";
    protected static final String LDAP_MODIFY_TIMESTAMP = "modifytimestamp";
    protected static final String LDAP_OWNER = "owner";
    protected static final String LDAP_UNIQUE_MEMBER = "uniquemember";
    protected static final String LDAP_POSIX_GROUP = "posixgroup";

    private static final String[] PUB_GROUP_ATTRS = new String[]
            {
                    LDAP_ENTRYDN, LDAP_CN
            };
    private static final String[] GROUP_ATTRS = new String[]
            {
                    LDAP_ENTRYDN, LDAP_CN, LDAP_NSACCOUNTLOCK, LDAP_OWNER,
                    LDAP_MODIFY_TIMESTAMP, LDAP_DESCRIPTION
            };
    private static final String[] GROUP_AND_MEMBER_ATTRS = new String[]
            {
                    LDAP_ENTRYDN, LDAP_CN, LDAP_NSACCOUNTLOCK, LDAP_OWNER,
                    LDAP_MODIFY_TIMESTAMP, LDAP_DESCRIPTION, LDAP_UNIQUE_MEMBER
            };

    private LdapUserDAO userDAO;

    // this gets filled by the LdapgroupPersistence
    GroupDetailSelector searchDetailSelector;

    public LdapGroupDAO(LdapConnections connections, LdapUserDAO userPersist)
    {
        super(connections);
        if (userPersist == null)
        {
            throw new IllegalArgumentException(
                    "User persistence instance required");
        }
        this.userDAO = userPersist;
    }

    /**
     * Persists a group with the specified gidNumber assigned to the posixGroup.
     *
     * @param group The group to create
     * @param gidNumber gidNumber to be assigned to the posixGroup
     * @return A Group instance
     * @throws GroupAlreadyExistsException If a group with the same ID already
     *                                     exists.
     * @throws TransientException          If an temporary, unexpected problem occurred.
     * @throws UserNotFoundException       If owner or a member not valid user.
     * @throws GroupNotFoundException
     */
    public Group addUserAssociatedGroup(Group group, long gidNumber)
            throws GroupAlreadyExistsException, TransientException,
                   UserNotFoundException, AccessControlException 
    {
        try {
            return addGroup(group, gidNumber);
        } catch(GroupNotFoundException ex) {
            throw new IllegalStateException("BUG: GroupMembers in group should be empty");
        }
    }
    
    /**
     * Persists a group.
     *
     * @param group The group to create
     * @return A Group instance
     * @throws GroupAlreadyExistsException If a group with the same ID already
     *                                     exists.
     * @throws TransientException          If an temporary, unexpected problem occurred.
     * @throws UserNotFoundException       If owner or a member not valid user.
     * @throws GroupNotFoundException
     */
    public Group addGroup(final Group group)
            throws GroupAlreadyExistsException, TransientException,
                   UserNotFoundException, AccessControlException,
                   GroupNotFoundException
    {
        return addGroup(group, null);
    }

    private Group addGroup(final Group group, Long gidNumber)
            throws GroupAlreadyExistsException, TransientException,
                   UserNotFoundException, AccessControlException,
                   GroupNotFoundException
    {
        if (!group.getProperties().isEmpty())
        {
            throw new UnsupportedOperationException(
                    "Support for groups properties not available");
        }

        try
        {
            Set<DNPrincipal> ds = group.getOwner().getIdentities(DNPrincipal.class);
            if (ds.isEmpty())
                throw new RuntimeException("BUG: User does not have an internal DNPrincipal");
            DNPrincipal dnp = ds.iterator().next();
            DN ownerDN = new DN(dnp.getName());
            
            // access the same server within this method
            LDAPConnection ldapRWConnection = getReadWriteConnection();

            if (!reactivateGroup(group))
            {
                // add group to groups tree
                LDAPResult result = addGroup(getGroupDN(group.getID().getName()),
                                             group.getID().getName(), ownerDN,
                                             group.description,
                                             group.getUserMembers(),
                                             group.getGroupMembers(),
                                             gidNumber,
                                             ldapRWConnection);
                LdapDAO.checkLdapResult(result.getResultCode());

                // add group to admin groups tree
                result = addGroup(getAdminGroupDN(group.getID().getName()),
                                  group.getID().getName(), ownerDN,
                                  group.description,
                                  group.getUserAdmins(),
                                  group.getGroupAdmins(),
                                  gidNumber,
                                  ldapRWConnection);
                LdapDAO.checkLdapResult(result.getResultCode());
            }
            
            return getGroup(group.getID().getName(), true, ldapRWConnection);
        }
        catch (LDAPException e)
        {
            logger.debug("addGroup Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
            throw new RuntimeException("Unexpected LDAP exception", e);
        }
    }

    private LDAPResult addGroup(final DN groupDN, final String groupID,
                                final DN ownerDN, final String description,
                                final Set<User> users,
                                final Set<Group> groups,
                                Long gidNumber,
                                LDAPConnection ldapRWConnection)
            throws UserNotFoundException, LDAPException, TransientException,
                   AccessControlException, GroupNotFoundException
    {
        // add new group
        List<Attribute> attributes = new ArrayList<Attribute>();
        Attribute ownerAttribute = new Attribute(LDAP_OWNER, ownerDN.toNormalizedString());
        attributes.add(ownerAttribute);
        attributes.add(new Attribute(LDAP_OBJECT_CLASS, LDAP_GROUP_OF_UNIQUE_NAMES));
        attributes.add(new Attribute(LDAP_OBJECT_CLASS, LDAP_INET_USER));
        attributes.add(new Attribute(LDAP_OBJECT_CLASS, LDAP_POSIX_GROUP));
        attributes.add(new Attribute(LDAP_CN, groupID));
        if (gidNumber == null) {
            attributes.add(new Attribute(LDAP_GID_NUMBER, String.valueOf(this.genNextNumericId())));
        } else {
            attributes.add(new Attribute(LDAP_GID_NUMBER, String.valueOf(gidNumber)));
            attributes.add(new Attribute(LDAP_NSACCOUNTLOCK, "true"));
        }

        if (StringUtil.hasText(description))
        {
            attributes.add(new Attribute(LDAP_DESCRIPTION, description));
        }

        // access the same server within this method
        List<String> members = new ArrayList<String>();
        for (User userMember : users)
        {
            DN memberDN = this.userDAO.getUserDN(userMember, ldapRWConnection);
            members.add(memberDN.toNormalizedString());
        }
        for (Group groupMember : groups)
        {
            final String groupMemberID = groupMember.getID().getName();
            if (!checkGroupExists(groupMemberID, ldapRWConnection))
            {
                throw new GroupNotFoundException(groupMemberID);
            }
            DN memberDN = getGroupDN(groupMemberID);
            members.add(memberDN.toNormalizedString());
        }
        if (!members.isEmpty())
        {
            attributes.add(
                new Attribute(LDAP_UNIQUE_MEMBER,
                              (String[]) members.toArray(new String[members.size()])));
        }

        AddRequest addRequest = new AddRequest(groupDN, attributes);

        logger.debug("addGroup: " + groupDN);
        return ldapRWConnection.add(addRequest);
    }
   
    /**
     * Checks whether group name available for the user or already in use.
     *
     * @param group
     * @return activated group or null if group does not exists
     * @throws AccessControlException
     * @throws UserNotFoundException
     * @throws GroupNotFoundException
     * @throws TransientException
     * @throws GroupAlreadyExistsException
     */
    public boolean reactivateGroup(final Group group)
            throws AccessControlException, UserNotFoundException,
                   TransientException, GroupAlreadyExistsException
    {
        try
        {
            // check group name exists
            Filter filter = Filter.createEqualityFilter(LDAP_CN, group.getID().getName());

            DN groupDN = getGroupDN(group.getID().getName());
            SearchRequest searchRequest =
                    new SearchRequest(groupDN.toNormalizedString(), SearchScope.BASE,
                                      filter, new String[]{LDAP_NSACCOUNTLOCK});

            SearchResultEntry searchResult =
                    getReadWriteConnection().searchForEntry(searchRequest);

            if (searchResult == null)
            {
                return false;
            }

            if (searchResult.getAttributeValue(LDAP_NSACCOUNTLOCK) == null)
            {
                throw new GroupAlreadyExistsException("Group already exists " + group.getID());
            }

            // activate group
            try
            {
                modifyGroup(group, true);
                return true;
            }
            catch (GroupNotFoundException e)
            {
                throw new RuntimeException(
                        "BUG: group to modify does not exist" + group.getID());
            }
        }
        catch (LDAPException e)
        {
            logger.debug("reactivateGroup Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
            throw new RuntimeException("Unexpected LDAP exception", e);
        }
    }


    /**
     * Get all group names.
     *
     * @return A collection of strings
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public Collection<String> getGroupNames()
            throws TransientException
    {
        try
        {
            Filter filter = Filter
                    .createNOTFilter(Filter.createPresenceFilter(LDAP_NSACCOUNTLOCK));
            filter = Filter.createANDFilter(filter, Filter.create("(cn=*)"));

            final List<String> groupNames = new LinkedList<String>();
            SearchRequest searchRequest = new SearchRequest(
                    new SearchResultListener()
                    {
                        long t1 = System.currentTimeMillis();

                        public void searchEntryReturned(SearchResultEntry sre)
                        {
                            String gname = sre.getAttributeValue(LDAP_CN);
                            groupNames.add(gname);

                            long t2 = System.currentTimeMillis();
                            long dt = t2 - t1;
                            if (groupNames.size() == 1)
                            {
                                logger.debug("first row: " + dt + "ms");
                                t1 = t2;
                            }
                            if ((groupNames.size() % 100) == 0)
                            {
                                logger.debug("found: " + groupNames.size() +
                                             " " + dt + "ms");
                                t1 = t2;
                            }
                        }

                        public void searchReferenceReturned(SearchResultReference srr)
                        {
                            throw new UnsupportedOperationException("Not supported yet.");
                        }
                    }, config.getGroupsDN(), SearchScope.ONE, filter, PUB_GROUP_ATTRS);

            SearchResult searchResult = null;
            try
            {
                Profiler profiler = new Profiler(LdapGroupDAO.class);
                LDAPInterface con = getReadOnlyConnection();
                profiler.checkpoint("getGroupNames.getConnection");
                searchResult = con.search(searchRequest);
                profiler.checkpoint("getGroupNames.search");
            }
            catch (LDAPSearchException e)
            {
                logger.debug("Could not find groups root", e);
                LdapDAO.checkLdapResult(e.getResultCode());
                if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT)
                {
                    throw new IllegalStateException("Could not find groups root");
                }

                throw new IllegalStateException("unexpected failure", e);
            }

            LdapDAO.checkLdapResult(searchResult.getResultCode());
//            profiler.checkpoint("checkLdapResult");

            return groupNames;
        }
        catch (LDAPException e1)
        {
            logger.debug("getGroupNames Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
            throw new IllegalStateException("Unexpected exception: " +
                                            e1.getMatchedDN(), e1);
        }
    }


    /**
     * Get the group with members.
     *
     * @param groupID The Group unique ID.
     * @return A Group instance
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     */
    public Group getGroup(final String groupID, boolean complete)
            throws GroupNotFoundException, TransientException,
                   AccessControlException
    {
        return getGroup(groupID, complete, getReadOnlyConnection());
    }
    
    private Group getGroup(final String groupID, boolean complete, final LDAPConnection ldapConn)
            throws GroupNotFoundException, TransientException,
                   AccessControlException
    {
        String[] attrs = GROUP_ATTRS;
        if (complete)
            attrs = GROUP_AND_MEMBER_ATTRS;

        Group group = getGroup(getGroupDN(groupID), groupID, attrs, ldapConn);

        if (complete)
        {
            Group adminGroup = getGroup(getAdminGroupDN(groupID), null, GROUP_AND_MEMBER_ATTRS, ldapConn);
            group.getGroupAdmins().addAll(adminGroup.getGroupMembers());
            group.getUserAdmins().addAll(adminGroup.getUserMembers());
        }

        return group;
    }
    
    // groupID is here so exceptions and logging have plain groupID instead of DN
    private Group getGroup(final DN groupDN, final String xgroupID, String[] attributes, final LDAPConnection ldapConn)
            throws GroupNotFoundException, TransientException,
                   AccessControlException
    {
        logger.debug("getGroup: " + groupDN + " attrs: " + attributes.length);
        String loggableGroupID = xgroupID;
        if (loggableGroupID == null)
        {
            // member or admin group: same name, internal tree
            loggableGroupID = groupDN.toString();
        }
        
        Profiler profiler = new Profiler(LdapGroupDAO.class);

        try
        {
            Filter filter = Filter.createNOTFilter(Filter.createPresenceFilter(LDAP_NSACCOUNTLOCK));
            filter = Filter.createANDFilter(filter,
                    Filter.createEqualityFilter(LDAP_ENTRYDN, groupDN.toNormalizedString()));

            SearchRequest searchRequest =
                    new SearchRequest(groupDN.toNormalizedString(),
                                      SearchScope.BASE, filter, attributes);

            SearchResultEntry searchEntry = ldapConn.searchForEntry(searchRequest);
            
            profiler.checkpoint("getGroup.getReadOnlyConnection");

            if (searchEntry == null)
            {
                String msg = "Group not found " + loggableGroupID + " cause: null";
                logger.debug(msg);
                throw new GroupNotFoundException(loggableGroupID);
            }

            Group ldapGroup = createGroupFromSearchResult(searchEntry, attributes, ldapConn);
            
            profiler.checkpoint("getGroup.createGroupFromSearchResult");

            if (searchEntry.getAttributeValues(LDAP_UNIQUE_MEMBER) != null)
            {
                for (String member : searchEntry
                        .getAttributeValues(LDAP_UNIQUE_MEMBER))
                {
                    DN memberDN = new DN(member);
                    if (memberDN.isDescendantOf(config.getUsersDN(), false))
                    {
                        User user;
                        try
                        {
                            user = userDAO.getUser(new DNPrincipal(member), ldapConn);
                            ldapGroup.getUserMembers().add(user);
                        }
                        catch (UserNotFoundException e)
                        {
                            // ignore as we do not cleanup deleted users
                            // from groups they belong to
                        }
                    }
                    else if (memberDN.isDescendantOf(config.getGroupsDN(), false))
                    {
                        try
                        {
                            ldapGroup.getGroupMembers()
                                    .add(getGroup(memberDN, null, PUB_GROUP_ATTRS, ldapConn));
                        }
                        catch (GroupNotFoundException e)
                        {
                            // ignore as we are not cleaning up
                            // deleted groups from the group members
                        }
                    }
                    else
                    {
                        throw new RuntimeException(
                                "BUG: unknown member DN type: " + memberDN);
                    }
                }
            }
            
            profiler.checkpoint("getGroup.addMembers");

            return ldapGroup;
        }
        catch (LDAPException e1)
        {
            logger.debug("getGroup Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
            throw new RuntimeException("BUG: checkLdapResult didn't throw an exception");
        }
    }

    /**
     * Modify the given group.
     *
     * @param group The group to update. It must be an existing group
     * @return The newly updated group.
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws UserNotFoundException  If owner or group members not valid users.
     */
    public Group modifyGroup(final Group group)
            throws GroupNotFoundException, TransientException,
                   AccessControlException, UserNotFoundException
    {
        String groupID = group.getID().getName();
        //group must exists first
        // ensure that we use the same LDAP server
        getGroup(getGroupDN(groupID), groupID, PUB_GROUP_ATTRS, getReadWriteConnection());
        return modifyGroup(group, false);
    }

    private Group modifyGroup(final Group group, boolean withActivate)
            throws UserNotFoundException, TransientException,
                   AccessControlException, GroupNotFoundException
    {
        if (!group.getProperties().isEmpty())
        {
            throw new UnsupportedOperationException(
                    "Support for groups properties not available");
        }

        List<Modification> mods = new ArrayList<Modification>();
        List<Modification> adminMods = new ArrayList<Modification>();
        if (withActivate)
        {
            mods.add(new Modification(ModificationType.DELETE, LDAP_NSACCOUNTLOCK));
            adminMods.add(new Modification(ModificationType.DELETE, LDAP_NSACCOUNTLOCK));
        }

        if (StringUtil.hasText(group.description))
        {
            mods.add(new Modification(ModificationType.REPLACE, LDAP_DESCRIPTION,
                                      group.description));
        }
        else
        {
            mods.add(new Modification(ModificationType.REPLACE, LDAP_DESCRIPTION));
        }

        LDAPConnection ldapRWConn = getReadWriteConnection();
        try
        {
            Set<String> newMembers = new HashSet<String>();
            for (User member : group.getUserMembers())
            {
                DN memberDN = userDAO.getUserDN(member, ldapRWConn);
                newMembers.add(memberDN.toNormalizedString());
            }
            for (Group gr : group.getGroupMembers())
            {
                if (!checkGroupExists(gr.getID().getName(), ldapRWConn))
                {
                    throw new GroupNotFoundException(gr.getID().getName());
                }
                DN grDN = getGroupDN(gr.getID().getName());
                newMembers.add(grDN.toNormalizedString());
            }

            Set<String> newAdmins = new HashSet<String>();
            for (User member : group.getUserAdmins())
            {
                DN memberDN = userDAO.getUserDN(member, ldapRWConn);
                newAdmins.add(memberDN.toNormalizedString());
            }
            for (Group gr : group.getGroupAdmins())
            {
                if (!checkGroupExists(gr.getID().getName(), ldapRWConn))
                {
                    throw new GroupNotFoundException(gr.getID().getName());
                }
                DN grDN = getGroupDN(gr.getID().getName());
                newAdmins.add(grDN.toNormalizedString());
            }

            // modify the admin group
            adminMods.add(
                new Modification(ModificationType.REPLACE, LDAP_UNIQUE_MEMBER,
                                 (String[]) newAdmins.toArray(new String[newAdmins.size()])));

            ModifyRequest adminModify =
                    new ModifyRequest(getAdminGroupDN(group.getID().getName()), adminMods);

            LdapDAO.checkLdapResult(ldapRWConn.modify(adminModify).getResultCode());

            // modify the group itself
            mods.add(
                new Modification(ModificationType.REPLACE, LDAP_UNIQUE_MEMBER,
                                 (String[]) newMembers.toArray(new String[newMembers.size()])));

            ModifyRequest modifyRequest =
                new ModifyRequest(getGroupDN(group.getID().getName()), mods);

            LdapDAO.checkLdapResult(ldapRWConn.modify(modifyRequest).getResultCode());
        }
        catch (LDAPException e1)
        {
            logger.debug("Modify Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }
        try
        {
            if (withActivate)
            {
                return new ActivatedGroup(getGroup(group.getID().getName(), true, ldapRWConn));
            }
            else
            {
                return getGroup(group.getID().getName(), true, ldapRWConn);
            }
        }
        catch (GroupNotFoundException e)
        {
            throw new RuntimeException("BUG: modified group not found (" +
                                        group.getID() + ")");
        }
    }

    /**
     * Deletes the group.
     *
     * @param groupID The group to delete
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     */
    public void deleteGroup(final String groupID)
            throws GroupNotFoundException, TransientException,
                   AccessControlException
    {
        deleteGroup(getGroupDN(groupID), groupID, false);
        deleteGroup(getAdminGroupDN(groupID), groupID, true);
    }

    private void deleteGroup(final DN groupDN, final String groupID,
                             final boolean isAdmin)
            throws GroupNotFoundException, TransientException,
                   AccessControlException
    {
        LDAPConnection ldapRWConn = getReadWriteConnection();
        ModifyRequest clearMembers = new ModifyRequest(groupDN,
                new Modification(ModificationType.DELETE, LDAP_UNIQUE_MEMBER));

        try
        {
            logger.debug("clearMembers " + groupDN);
            LDAPResult result = ldapRWConn.modify(clearMembers);
            LdapDAO.checkLdapResult(result.getResultCode(), true);
        }
        catch (LDAPException e1)
        {
            logger.debug("clear members fail: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode(), true);
        }

        ModifyRequest deleteGroup = new ModifyRequest(groupDN,
                new Modification(ModificationType.ADD, LDAP_NSACCOUNTLOCK, "true"));

        try
        {
            logger.debug("deleteGroup " + groupDN);
            LDAPResult result = ldapRWConn.modify(deleteGroup);
            LdapDAO.checkLdapResult(result.getResultCode());
        }
        catch (LDAPException e1)
        {
            logger.debug("delete group fail: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }

        try
        {
            Group g = getGroup(getGroupDN(groupID), null, GROUP_ATTRS, ldapRWConn);
            throw new RuntimeException("BUG: group not deleted " + g.getID());
        }
        catch (GroupNotFoundException ignore)
        {
        }
    }

    public Collection<Group> getOwnerGroups(final DNPrincipal owner, final String groupID)
            throws TransientException, AccessControlException
    {
        Collection<Group> ret = new ArrayList<Group>();
        try
        {
            DN userDN = new DN(owner.getName());

            Filter filter = Filter.createNOTFilter(Filter.createPresenceFilter(LDAP_NSACCOUNTLOCK));

            filter = Filter.createANDFilter(filter,
                    Filter.createEqualityFilter(LDAP_OWNER, userDN.toNormalizedString()));

            if (groupID != null)
            {
                DN groupDN = getGroupDN(groupID);
                filter = Filter.createANDFilter(filter,
                    Filter.createEqualityFilter(LDAP_ENTRYDN, groupDN.toNormalizedString()));
            }

            SearchRequest searchRequest = new SearchRequest(
                    config.getGroupsDN(), SearchScope.SUB, filter, GROUP_ATTRS);

            LDAPConnection ldapROConn = getReadOnlyConnection();
            SearchResult results = getReadOnlyConnection().search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                ret.add(createGroupFromSearchResult(result, GROUP_ATTRS, ldapROConn));
            }
        }
        catch (LDAPException e1)
        {
            logger.debug("getOwnerGroups Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }
        return ret;
    }

    private Group createGroupFromSearchResult(SearchResultEntry result, String[] attributes, final LDAPConnection ldapConn)
            throws LDAPException, TransientException
    {
        if (result.getAttribute(LDAP_NSACCOUNTLOCK) != null)
        {
            throw new RuntimeException("BUG: found group with nsaccountlock set: " +
                                        result.getAttributeValue(LDAP_ENTRYDN));
        }

        String entryDN = result.getAttributeValue(LDAP_ENTRYDN);
        String groupName = result.getAttributeValue(LDAP_CN);
        LocalAuthority localAuthority = new LocalAuthority();
        URI gmsServiceID = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());
        if (attributes == PUB_GROUP_ATTRS)
        {
            GroupURI groupID = new GroupURI(gmsServiceID.toString() + "?" + groupName);
            return new Group(groupID);
        }

        String ownerDN = result.getAttributeValue(LDAP_OWNER);
        if (ownerDN == null)
        {
            throw new AccessControlException(groupName);
        }
        try
        {
            User owner = userDAO.getUser(new DNPrincipal(ownerDN), ldapConn);
            GroupURI groupID = new GroupURI(gmsServiceID.toString() + "?" + groupName);
            Group group = new Group(groupID);
            setField(group, owner, LDAP_OWNER);
            if (result.hasAttribute(LDAP_DESCRIPTION))
            {
                group.description = result.getAttributeValue(LDAP_DESCRIPTION);
            }
            if (result.hasAttribute(LDAP_MODIFY_TIMESTAMP))
            {
                group.lastModified = result.getAttributeValueAsDate(LDAP_MODIFY_TIMESTAMP);
            }
            return group;
        }
        catch (UserNotFoundException ex)
        {
            throw new RuntimeException("Invalid state: owner does not exist: " +
                                        ownerDN + " group: " + entryDN);
        }
    }

    /**
     * @param groupID
     * @return the Distinguished Name of the group
     */
    protected DN getGroupDN(final String groupID) throws TransientException
    {
        try
        {
            return new DN("cn=" + groupID + "," + config.getGroupsDN());
        }
        catch (LDAPException e)
        {
            logger.debug("getGroupDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }

    /**
     * @param groupID
     * @return the Distinguished Name of the admin group
     */
    protected DN getAdminGroupDN(final String groupID) throws TransientException
    {
        try
        {
            return new DN("cn=" + groupID + "," + config.getAdminGroupsDN());
        }
        catch (LDAPException e)
        {
            logger.debug("getAdminGroupDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }

    private boolean checkGroupExists(String groupID, LDAPConnection ldapConn)
            throws LDAPException, TransientException
    {
        try
        {
            Group g = getGroup(getGroupDN(groupID), groupID, PUB_GROUP_ATTRS, ldapConn);
            return true;
        }
        catch (GroupNotFoundException ex)
        {
            return false;
        }
        finally
        {
        }
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
