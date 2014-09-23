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

import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.ActivatedGroup;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.net.TransientException;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import java.util.HashSet;

public class LdapGroupDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapGroupDAO.class);
    
    private LdapUserDAO<T> userPersist;

    public LdapGroupDAO(LdapConfig config, LdapUserDAO<T> userPersist)
    {
        super(config);
        if (userPersist == null)
        {
            throw new IllegalArgumentException(
                    "User persistence instance required");
        }
        this.userPersist = userPersist;
    }

    /**
     * Creates the group.
     * 
     * @param group The group to create
     * 
     * @return created group
     * 
     * @throws GroupAlreadyExistsException If a group with the same ID already 
     *                                     exists.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws UserNotFoundException If owner or a member not valid user.
     */
    public Group addGroup(final Group group)
        throws GroupAlreadyExistsException, TransientException,
               UserNotFoundException, AccessControlException
    {
        if (group.getOwner() == null)
        {
            throw new IllegalArgumentException("Group owner must be specified");
        }
        
        if (!isCreatorOwner(group.getOwner()))
        {
            throw new AccessControlException("Group owner must be creator");
        }

        try
        {
            getGroup(group.getID());
            throw new GroupAlreadyExistsException(group.getID());
        }
        catch (GroupNotFoundException ex)
        {
            try
            {        
                if (!group.getProperties().isEmpty())
                {
                    throw new UnsupportedOperationException(
                            "Support for groups properties not available");
                }
                
                try
                {
                    getInactiveGroup(group);
                    return reactivateGroup(group);
                }
                catch (GroupNotFoundException e)
                {
                    // ignore
                }
                
                DN ownerDN = userPersist.getUserDN(group.getOwner());
                
                // add group to groups tree
                LDAPResult result = addGroup(getGroupDN(group.getID()), 
                                             group.getID(), ownerDN, 
                                             group.description, 
                                             group.getUserMembers(), 
                                             group.getGroupMembers());
                
                // add group to admin groups tree
                result = addGroup(getAdminGroupDN(group.getID()), 
                                  group.getID(), ownerDN, 
                                  group.description, 
                                  group.getUserMembers(), 
                                  group.getGroupMembers());
                
                try
                {
                    return getGroup(group.getID());
                }
                catch (GroupNotFoundException e)
                {
                    throw new RuntimeException("BUG: new group not found");
                }
            }
            catch (LDAPException e)
            {
                e.printStackTrace();
                throw new RuntimeException(e);
            } 
        }
    }
    
    private LDAPResult addGroup(final DN groupDN, final String groupID,
                                final DN ownerDN, final String description, 
                                final Set<User<? extends Principal>> users, 
                                final Set<Group> groups)
        throws UserNotFoundException, LDAPException
    {
        // add new group
        List<Attribute> attributes = new ArrayList<Attribute>();
        Attribute ownerAttribute = 
                        new Attribute("owner", ownerDN.toNormalizedString());
        attributes.add(ownerAttribute);
        attributes.add(new Attribute("objectClass", "groupofuniquenames"));
        attributes.add(new Attribute("cn", groupID));
        
        if (description != null)
        {
            attributes.add(new Attribute("description", description));
        }

        List<String> members = new ArrayList<String>();
        for (User<? extends Principal> userMember : users)
        {
            DN memberDN = this.userPersist.getUserDN(userMember);
            members.add(memberDN.toNormalizedString());
        }
        for (Group groupMember : groups)
        {
            DN memberDN = getGroupDN(groupMember.getID());
            members.add(memberDN.toNormalizedString());
        }
        if (!members.isEmpty())
        {
            attributes.add(new Attribute("uniquemember", 
                (String[]) members.toArray(new String[members.size()])));
        }

        AddRequest addRequest = new AddRequest(groupDN, attributes);

        addRequest.addControl(
                new ProxiedAuthorizationV2RequestControl(
                        "dn:" + getSubjectDN().toNormalizedString()));

        return getConnection().add(addRequest);
    }
    
    private Group getInactiveGroup(final Group group)
        throws AccessControlException, UserNotFoundException,
        GroupNotFoundException
    {
        Group inactiveGroup;
        try
        {
            inactiveGroup = getInactiveGroup(
                    getGroupDN(group.getID()), group.getID());

            if (inactiveGroup == null)
            {
                return null;
            }

            if (!group.getOwner().equals(inactiveGroup.getOwner()))
            {
                throw new AccessControlException(
                        "Inactive group not owned be requestor");
            }

            Group inactiveAdminGroup = getInactiveGroup(
                    getAdminGroupDN(group.getID()), group.getID());

            if (inactiveAdminGroup == null)
            {
                throw new RuntimeException(
                        "BUG: adminGroup not found for group " + group.getID());
            }

            if (!group.getOwner().equals(inactiveAdminGroup.getOwner()))
            {
                throw new RuntimeException(
                        "Bug: adminGroup owner doesn't match "
                                + "group owner for group " + group.getID());
            }
            return inactiveGroup;
        } 
        catch (LDAPException e)
        {
            // TODO Auto-generated catch block
            throw new RuntimeException("BUG: LDAP Exception: ", e);
        }
    }
    
    private Group getInactiveGroup(final DN groupDN, final String groupID)
        throws UserNotFoundException, LDAPException, GroupNotFoundException
    {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("cn", groupID),
                Filter.createEqualityFilter("nsaccountlock", "true"));

        SearchRequest searchRequest = 
                new SearchRequest(groupDN.toNormalizedString(), SearchScope.SUB,
                                  filter, new String[] {"cn", "owner"});

        searchRequest.addControl(
                new ProxiedAuthorizationV2RequestControl("dn:" + 
                        getSubjectDN().toNormalizedString()));

        SearchResultEntry searchResult = 
                getConnection().searchForEntry(searchRequest);
        
        if (searchResult == null)
        {
            String msg = "Inactive Group not found " + groupID;
            logger.debug(msg);
            throw new GroupNotFoundException(msg);
        }

        String groupCN = searchResult.getAttributeValue("cn");
        DN groupOwner = searchResult.getAttributeValueAsDN("owner");

        User<X500Principal> owner = userPersist.getMember(groupOwner);

        return new Group(groupCN, owner);
    }
    
    private Group reactivateGroup(final Group group)
        throws UserNotFoundException, LDAPException, TransientException, 
               AccessControlException, GroupNotFoundException
    {
        return modifyGroup(group, true);
    }

    /**
     * Get the group with the given Group ID.
     * 
     * @param groupID The Group unique ID.
     * 
     * @return A Group instance
     * 
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException  If an temporary, unexpected problem occurred.
     */
    public Group getGroup(final String groupID)
        throws GroupNotFoundException, TransientException,
               AccessControlException
    {
        return getGroup(groupID, true);
    }
    
    public Group getGroup(final String groupID, final boolean withMembers)
        throws GroupNotFoundException, TransientException,
               AccessControlException
    {
        Group group = getGroup(getGroupDN(groupID), groupID, true);
        
        Group adminGroup = getAdminGroup(getAdminGroupDN(groupID), groupID, 
                                         true);
        
        group.getGroupAdmins().addAll(adminGroup.getGroupMembers());
        group.getUserAdmins().addAll(adminGroup.getUserMembers());
        return group;
    }
    
    private Group getGroup(final DN groupDN, final String groupID, 
                           final boolean withMembers)
        throws GroupNotFoundException, TransientException, 
               AccessControlException
    {
        String [] attributes = new String[] {"entrydn", "cn", "description", 
                                             "owner", "uniquemember", 
                                             "modifytimestamp"};
        return getGroup(groupDN, groupID, withMembers, attributes);
    }
    
    private Group getAdminGroup(final DN groupDN, final String groupID, 
                                final boolean withMembers)
        throws GroupNotFoundException, TransientException, 
               AccessControlException
    {
        String [] attributes = new String[] {"entrydn", "cn", "owner",
                                             "uniquemember"};
        return getGroup(groupDN, groupID, withMembers, attributes);
    }

    private Group getGroup(final DN groupDN, final String groupID, 
                           final boolean withMembers, final String[] attributes)
        throws GroupNotFoundException, TransientException, 
               AccessControlException
    {
        try
        {
            Filter filter = Filter.createANDFilter(
                    Filter.createEqualityFilter("cn", groupID),
                    Filter.createNOTFilter(
                        Filter.createEqualityFilter("nsaccountlock", "TRUE")));
            
            SearchRequest searchRequest = 
                    new SearchRequest(groupDN.toNormalizedString(), 
                                      SearchScope.SUB, filter, attributes);

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            SearchResultEntry searchResult = 
                    getConnection().searchForEntry(searchRequest);
            
            if (searchResult == null)
            {
                String msg = "Group not found " + groupID;
                logger.debug(msg);
                throw new GroupNotFoundException(groupID);
            }
            
            String groupCN = searchResult.getAttributeValue("cn");
            DN groupOwner = searchResult.getAttributeValueAsDN("owner");
            
            User<X500Principal> owner;
            try
            {
                owner = userPersist.getMember(groupOwner);
            }
            catch (UserNotFoundException e)
            {
                throw new RuntimeException("BUG: group owner not found");
            }
            
            Group ldapGroup = new Group(groupCN, owner);
            if (searchResult.hasAttribute("description"))
            {
                ldapGroup.description = 
                        searchResult.getAttributeValue("description");
            }
            if (searchResult.hasAttribute("modifytimestamp"))
            {
                ldapGroup.lastModified = 
                        searchResult.getAttributeValueAsDate("modifytimestamp");
            }

            if (withMembers)
            {
                if (searchResult.getAttributeValues("uniquemember") != null)
                {
                    for (String member : searchResult
                            .getAttributeValues("uniquemember"))
                    {
                        DN memberDN = new DN(member);
                        if (memberDN.isDescendantOf(config.getUsersDN(), false))
                        {
                            User<X500Principal> user;
                            try
                            {
                                user = userPersist.getMember(memberDN);
                            }
                            catch (UserNotFoundException e)
                            {
                                throw new RuntimeException(
                                    "BUG: group member not found");
                            }
                            ldapGroup.getUserMembers().add(user);
                        }
                        else if (memberDN.isDescendantOf(config.getGroupsDN(),
                                                         false))
                        {
                            ldapGroup.getGroupMembers().add(new Group(
                                memberDN.getRDNString().replace("cn=", "")));
                        }
                        else
                        {
                            throw new RuntimeException(
                                "BUG: unknown member DN type: " + memberDN);
                        }
                    }
                }
            }
            
            return ldapGroup;
        }
        catch (LDAPException e1)
        {
            // TODO check which LDAP exceptions are transient and which
            // ones are
            // access control
            throw new TransientException("Error getting the group", e1);
        }
    }

    /**
     * Modify the given group.
     *
     * @param group The group to update. It must be an existing group
     * 
     * @return The newly updated group.
     * 
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws UserNotFoundException If owner or group members not valid users.
     */
    public Group modifyGroup(final Group group)
        throws GroupNotFoundException, TransientException,
               AccessControlException, UserNotFoundException
    {
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
        
        // check if group exists
        if (withActivate)
        {
            getInactiveGroup(group);
        }
        else
        {
            getGroup(group.getID());
        }

        List<Modification> mods = new ArrayList<Modification>();
        List<Modification> adminMods = new ArrayList<Modification>();
        if (withActivate)
        {
            mods.add(new Modification(ModificationType.DELETE, "nsaccountlock"));
            adminMods.add(new Modification(ModificationType.DELETE, "nsaccountlock"));
        }

        if (group.description == null)
        {
            mods.add(new Modification(ModificationType.REPLACE, "description"));
        }
        else
        {
            mods.add(new Modification(ModificationType.REPLACE, "description", group.description));
        }

        List<String> newMembers = new ArrayList<String>();
        for (User<?> member : group.getUserMembers())
        {
            DN memberDN;
            try
            {
                memberDN = userPersist.getUserDN(member);
            } 
            catch (LDAPException e)
            {
                throw new UserNotFoundException("User not found "
                        + member.getUserID());
            }
            newMembers.add(memberDN.toNormalizedString());
        }
        for (Group gr : group.getGroupMembers())
        {
                DN grDN = getGroupDN(gr.getID());
                newMembers.add(grDN.toNormalizedString());
        }
        List<String> newAdmins = new ArrayList<String>();
        for (User<?> member : group.getUserAdmins())
        {
            DN memberDN;
            try
            {
                memberDN = userPersist.getUserDN(member);
            }
            catch (LDAPException e)
            {
                throw new UserNotFoundException(
                        "User not found " + member.getUserID());
            }
            newAdmins.add(memberDN.toNormalizedString());
        }
        for (Group gr : group.getGroupAdmins())
        {
            DN grDN = getGroupDN(gr.getID());
            newMembers.add(grDN.toNormalizedString());
        }

        mods.add(new Modification(ModificationType.REPLACE, "uniquemember", 
                (String[]) newMembers.toArray(new String[newMembers.size()])));
        adminMods.add(new Modification(ModificationType.REPLACE, "uniquemember", 
                (String[]) newAdmins.toArray(new String[newAdmins.size()])));
        
        // modify admin group first
        ModifyRequest modifyRequest = new ModifyRequest(getAdminGroupDN(group.getID()), adminMods);
        try
        {
            modifyRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl(
                            "dn:" + getSubjectDN().toNormalizedString()));
            LDAPResult result = getConnection().modify(modifyRequest);
        }
        catch (LDAPException e1)
        {
            throw new RuntimeException("LDAP problem", e1);
        }
        // modify the group itself now
        modifyRequest = new ModifyRequest(getGroupDN(group.getID()), mods);
        try
        {
            modifyRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl(
                            "dn:" + getSubjectDN().toNormalizedString()));
            LDAPResult result = getConnection().modify(modifyRequest);
        }
        catch (LDAPException e1)
        {
            throw new RuntimeException("LDAP problem", e1);
        }
        try
        {
            if (withActivate)
            {
                return new ActivatedGroup(getGroup(group.getID()));
            }
            else
            {
                return getGroup(group.getID());
            }
        }
        catch (GroupNotFoundException e)
        {
            throw new RuntimeException(
                    "BUG: modified group not found (" + group.getID() + ")");
        }
    }

    /**
     * Deletes the group.
     * 
     * @param groupID The group to delete
     * 
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
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
        Group group = getGroup(groupDN, groupID, false);
        List<Modification> modifs = new ArrayList<Modification>();
        modifs.add(new Modification(ModificationType.ADD, "nsaccountlock", "true"));
        
        if (isAdmin)
        {
            if (!group.getGroupAdmins().isEmpty() || 
                !group.getUserAdmins().isEmpty())
            {
                modifs.add(new Modification(ModificationType.DELETE, "uniquemember"));
            }
        }
        else
        {
            if (!group.getGroupMembers().isEmpty() || 
                !group.getUserMembers().isEmpty())
            {
                modifs.add(new Modification(ModificationType.DELETE, "uniquemember"));
            }
        }

        ModifyRequest modifyRequest = new ModifyRequest(groupDN, modifs);
        try
        {
            modifyRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl(
                            "dn:" + getSubjectDN().toNormalizedString()));
            LDAPResult result = getConnection().modify(modifyRequest);
        }
        catch (LDAPException e1)
        {
            throw new RuntimeException("LDAP problem", e1);
        }
        
        try
        {
            getGroup(group.getID());
            throw new RuntimeException("BUG: group not deleted " + 
                                       group.getID());
        }
        catch (GroupNotFoundException ignore) {}
    }
    
    /**
     * Obtain a Collection of Groups that fit the given query.
     * 
     * @param userID The userID.
     * @param role Role of the user, either owner, member, or read/write.
     * @param groupID The Group ID.
     * 
     * @return Collection of Groups
     *         matching GROUP_READ_ACI.replace(ACTUAL_GROUP_TOKEN,
     *         readGrDN.toNormalizedString()) the query, or empty
     *         Collection. Never null.
     * @throws TransientException  If an temporary, unexpected problem occurred.
     * @throws UserNotFoundException
     * @throws GroupNotFoundException
     */
    public Collection<Group> getGroups(final T userID, final Role role, 
                                       final String groupID)
        throws TransientException, AccessControlException,
               GroupNotFoundException, UserNotFoundException
    {
        User<T> user = new User<T>(userID);
        DN userDN;
        try
        {   
            userDN = userPersist.getUserDN(user);
        }
        catch (LDAPException e)
        {
            // TODO check which LDAP exceptions are transient and which
            // ones are
            // access control
            throw new TransientException("Error getting user", e);
        }
        
        Collection<DN> groupDNs = new HashSet<DN>();
        if (role == Role.OWNER)
        {
            groupDNs.addAll(getOwnerGroups(user, userDN, groupID));
        }
        else if (role == Role.MEMBER)
        {
            groupDNs.addAll(getMemberGroups(user, userDN, groupID, false));
        }
        else if (role == Role.ADMIN)
        {
            groupDNs.addAll(getMemberGroups(user, userDN, groupID, true));
        }
        
        Collection<Group> groups = new HashSet<Group>();
        try
        {
            for (DN groupDN : groupDNs)
            {
                groups.add(getGroup(groupDN));
            }
        }
        catch (LDAPException e)
        {
            throw new TransientException("Error getting group", e);
        }
        return groups;
    }
    
    protected Collection<DN> getOwnerGroups(final User<T> user, 
                                            final DN userDN,
                                            final String groupID)
        throws TransientException, AccessControlException,
               GroupNotFoundException, UserNotFoundException
    {
        try
        {                           
            Filter filter = Filter.createEqualityFilter("owner", 
                                                        userDN.toString());
            if (groupID != null)
            {
                getGroup(groupID);
                filter = Filter.createANDFilter(filter, 
                                Filter.createEqualityFilter("cn", groupID));
            }
            
            SearchRequest searchRequest =  new SearchRequest(
                    config.getGroupsDN(), SearchScope.SUB, filter, "entrydn");
            
            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));
            
            Collection<DN> groupDNs = new HashSet<DN>();
            SearchResult results = getConnection().search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                String entryDN = result.getAttributeValue("entrydn");
                groupDNs.add(new DN(entryDN));
            }
            return groupDNs; 
        }
        catch (LDAPException e1)
        {
            // TODO check which LDAP exceptions are transient and which
            // ones are
            // access control
            throw new TransientException("Error getting groups", e1);
        }
    }
    
    protected Collection<DN> getMemberGroups(final User<T> user, 
                                             final DN userDN, 
                                             final String groupID,
                                             final boolean isAdmin)
        throws TransientException, AccessControlException,
               GroupNotFoundException, UserNotFoundException
    {
        Collection<DN> groups = new HashSet<DN>();
        if (groupID != null)
        {
            DN groupDN;
            if (isAdmin)
            {
                groupDN = getAdminGroupDN(groupID);
            }
            else
            {
                groupDN = getGroupDN(groupID);
            }
            if (userPersist.isMember(user.getUserID(),
                                     groupDN.toNormalizedString()))
            {
                groups.add(groupDN);
            }
        }
        else
        {
            Collection<DN> memberGroupDNs = 
                    userPersist.getUserGroups(user.getUserID(), isAdmin);
            groups.addAll(memberGroupDNs);
            logger.debug("# groups found: " + memberGroupDNs.size());
        }
        return groups;
    }
    
    /**
     * Returns a group based on its LDAP DN. The returned group is bare
     * (contains only group ID, description, modifytimestamp).
     * 
     * @param groupDN
     * @return
     * @throws com.unboundid.ldap.sdk.LDAPException
     * @throws ca.nrc.cadc.ac.GroupNotFoundException
     */
    protected Group getGroup(final DN groupDN)
        throws LDAPException, GroupNotFoundException
    {
        SearchResultEntry searchResult = 
                getConnection().getEntry(groupDN.toNormalizedString(),
                                new String[] {"cn", "description"});

        if (searchResult == null)
        {
            String msg = "Group not found " + groupDN;
            logger.debug(msg);
            throw new GroupNotFoundException(groupDN.toNormalizedString());
        }

        Group group = new Group(searchResult.getAttributeValue("cn"));
        group.description = searchResult.getAttributeValue("description");
        return group;
    }

    /**
     * 
     * @param groupID
     * @return 
     */
    protected DN getGroupDN(final String groupID)
    {
        try
        {
            return new DN("cn=" + groupID + "," + config.getGroupsDN());
        }
        catch (LDAPException e)
        {
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }
    
    /**
     * 
     * @param groupID
     * @return 
     */
    protected DN getAdminGroupDN(final String groupID)
    {
        try
        {
            return new DN("cn=" + groupID + "," + config.getAdminGroupsDN());
        }
        catch (LDAPException e)
        {
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }
    
    /**
     * 
     * @param owner
     * @return
     * @throws UserNotFoundException 
     */
    protected boolean isCreatorOwner(final User<? extends Principal> owner)
        throws UserNotFoundException
    {
        try
        {
            User<X500Principal> subjectUser = 
                    userPersist.getMember(getSubjectDN());
            if (subjectUser.equals(owner))
            {
                return true;
            }
            return false;
        }
        catch (LDAPException e)
        {
            throw new RuntimeException(e);
        }
    }

}
