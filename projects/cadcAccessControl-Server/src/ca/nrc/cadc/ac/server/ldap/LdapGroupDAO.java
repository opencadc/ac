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
import java.util.Date;
import java.util.List;

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
import java.util.Set;

public class LdapGroupDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapGroupDAO.class);
    
    private static final String ACTUAL_GROUP_TOKEN = "<ACTUAL_GROUP>";
    private static final String GROUP_READ_ACI = "(targetattr = \"*\") " + 
            "(version 3.0;acl \"Group Read\";allow (read,compare,search)" + 
            "(groupdn = \"ldap:///<ACTUAL_GROUP>\");)";
    private static final String GROUP_WRITE_ACI = "(targetattr = \"*\") " + 
            "(version 3.0;acl \"Group Write\";allow " + 
            "(read,compare,search,selfwrite,write,add)" + 
            "(groupdn = \"ldap:///<ACTUAL_GROUP>\");)";
    
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
    public Group addGroup(Group group)
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
                
                Group inactiveGroup = getInactiveGroup(group);
                if (inactiveGroup != null)
                {
                    return reactiveGroup(group, inactiveGroup);
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
        throws AccessControlException, UserNotFoundException, LDAPException
    {
        Group inactiveGroup = 
                getInactiveGroup(getGroupDN(group.getID()).toNormalizedString(), 
                                 group.getID());

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
                        getAdminGroupDN(group.getID()).toNormalizedString(), 
                        group.getID());
        
        if (inactiveAdminGroup == null)
        {
            throw new RuntimeException("BUG: adminGroup not found for group " +
                                       group.getID());
        }
        
        if (!group.getOwner().equals(inactiveAdminGroup.getOwner()))
        {
            throw new RuntimeException("Bug: adminGroup owner doesn't match " +
                                       "group owner for group " + 
                                       group.getID());
        }
        
        return inactiveGroup;
    }
    
    private Group getInactiveGroup(final String groupDN, final String groupID)
        throws UserNotFoundException, LDAPException
    {
        Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("cn", groupID),
                Filter.createEqualityFilter("nsaccountlock", "true"));

        SearchRequest searchRequest = 
                new SearchRequest(groupDN, SearchScope.SUB, filter, 
                                  new String[] {"cn", "owner"});

        searchRequest.addControl(
                new ProxiedAuthorizationV2RequestControl("dn:" + 
                        getSubjectDN().toNormalizedString()));

        SearchResultEntry searchResult = 
                getConnection().searchForEntry(searchRequest);
        
        if (searchResult == null)
        {
            String msg = "Inactive Group not found " + groupID;
            logger.debug(msg);
            return null;
        }

        String groupCN = searchResult.getAttributeValue("cn");
        DN groupOwner = searchResult.getAttributeValueAsDN("owner");

        User<X500Principal> owner = userPersist.getMember(groupOwner);

        return new Group(groupCN, owner);
    }
    
    private Group reactiveGroup(final Group newGroup, final Group inactiveGroup)
        throws UserNotFoundException, LDAPException, TransientException
    {
        Group group = reactiveGroup(getGroupDN(newGroup.getID()), newGroup, 
                                    inactiveGroup);
        Group adminGroup = reactiveGroup(getGroupDN(newGroup.getID()), newGroup, 
                                         inactiveGroup);
        return group;
    }
    
    private Group reactiveGroup(final DN groupDN, final Group newGroup, 
                                final Group inactiveGroup)
        throws UserNotFoundException, LDAPException, TransientException
    {
        List<Modification> mods = new ArrayList<Modification>();
        mods.add(new Modification(ModificationType.DELETE, "nsaccountlock"));

        Group modifiedGroup = modifyGroup(groupDN, newGroup, inactiveGroup, 
                                          mods);
        Group activatedGroup = new ActivatedGroup(modifiedGroup.getID(),
                                                  modifiedGroup.getOwner());
        activatedGroup.description = modifiedGroup.description;
        activatedGroup.getProperties().addAll(modifiedGroup.getProperties());
        activatedGroup.getGroupMembers().addAll(modifiedGroup.getGroupMembers());
        activatedGroup.getUserMembers().addAll(modifiedGroup.getUserMembers());
        activatedGroup.getGroupAdmins().addAll(modifiedGroup.getGroupAdmins());
        activatedGroup.getUserAdmins().addAll(modifiedGroup.getUserAdmins());
        return activatedGroup;
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
                           final boolean withMembers, String[] attributes)
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
                                user = userPersist.getMember(memberDN, false);
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
                            ldapGroup.getGroupMembers().add(new Group(memberDN.getRDNString().replace("cn=", "")));
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
     * @param group The group to update.
     * 
     * @return The newly updated group.
     * 
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws UserNotFoundException If owner or group members not valid users.
     */
    public Group modifyGroup(Group group)
        throws GroupNotFoundException, TransientException,
               AccessControlException, UserNotFoundException
    {
        DN groupDN = getGroupDN(group.getID());
        Group oldGroup = getGroup(groupDN, group.getID(), true);
        Group newGroup = modifyGroup(groupDN, group, oldGroup, null);
        
        DN adminGroupDN = getAdminGroupDN(group.getID());
        Group oldAdminGroup = getGroup(adminGroupDN, group.getID(), true);
        Group newAdminGroup = modifyGroup(adminGroupDN, group, oldAdminGroup, 
                                          null);
        
        newGroup.getGroupAdmins().addAll(newAdminGroup.getGroupAdmins());
        newGroup.getUserAdmins().addAll(newAdminGroup.getUserAdmins());
        
        return newGroup;
    }
    
    private Group modifyGroup(final DN groupDN, final Group newGroup, 
                              final Group oldGroup,
                              final List<Modification> modifications)
        throws UserNotFoundException, TransientException,
               AccessControlException
    {
        if (!newGroup.getProperties().isEmpty())
        {
            throw new UnsupportedOperationException(
                    "Support for groups properties not available");
        }

        List<Modification> mods = new ArrayList<Modification>();
        if (modifications != null)
        {
            mods.addAll(modifications);
        }

        if (newGroup.description == null && oldGroup.description != null)
        {
            mods.add(new Modification(ModificationType.DELETE, "description"));
        }
        else if (newGroup.description != null && oldGroup.description == null)
        {
            mods.add(new Modification(ModificationType.ADD, "description", 
                                        newGroup.description));
        }
        else if (newGroup.description != null && oldGroup.description != null)
        {
            mods.add(new Modification(ModificationType.REPLACE, "description", 
                                        newGroup.description));
        }

        List<String> newMembers = new ArrayList<String>();
        for (User<?> member : newGroup.getUserMembers())
        {
            if (!oldGroup.getUserMembers().remove(member))
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
                newMembers.add(memberDN.toNormalizedString());
            }
        }
        for (Group gr : newGroup.getGroupMembers())
        {
            if (gr.equals(newGroup))
            {
                throw new IllegalArgumentException(
                        "cyclical reference from group member to group");
            }

            if (!oldGroup.getGroupMembers().remove(gr))
            {
                DN grDN = getGroupDN(gr.getID());
                newMembers.add(grDN.toNormalizedString());
            }
        }
        for (User<?> member : newGroup.getUserAdmins())
        {
            if (!oldGroup.getUserAdmins().remove(member))
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
                newMembers.add(memberDN.toNormalizedString());
            }
        }
        for (Group gr : newGroup.getGroupAdmins())
        {
            if (gr.equals(newGroup))
            {
                throw new IllegalArgumentException(
                        "cyclical reference from group member to group");
            }

            if (!oldGroup.getGroupAdmins().remove(gr))
            {
                DN grDN = getGroupDN(gr.getID());
                newMembers.add(grDN.toNormalizedString());
            }
        }
        
        if (!newMembers.isEmpty())
        {
            mods.add(new Modification(ModificationType.ADD, "uniquemember", 
                (String[]) newMembers.toArray(new String[newMembers.size()])));
        }

        List<String> delMembers = new ArrayList<String>();
        for (User<?> member : oldGroup.getUserMembers())
        {
            DN memberDN;
            try
            {
                memberDN = this.userPersist.getUserDN(member);
            }
            catch (LDAPException e)
            {
                throw new UserNotFoundException(
                        "User not found " + member.getUserID());
            }
            delMembers.add(memberDN.toNormalizedString());
        }
        for (Group gr : oldGroup.getGroupMembers())
        {
            DN grDN = getGroupDN(gr.getID());
            delMembers.add(grDN.toNormalizedString());
        }
        for (User<?> member : oldGroup.getUserAdmins())
        {
            DN memberDN;
            try
            {
                memberDN = this.userPersist.getUserDN(member);
            }
            catch (LDAPException e)
            {
                throw new UserNotFoundException(
                        "User not found " + member.getUserID());
            }
            delMembers.add(memberDN.toNormalizedString());
        }
        for (Group gr : oldGroup.getGroupAdmins())
        {
            DN grDN = getGroupDN(gr.getID());
            delMembers.add(grDN.toNormalizedString());
        }
        
        if (!delMembers.isEmpty())
        {
            mods.add(new Modification(ModificationType.DELETE, "uniquemember",
                (String[]) delMembers.toArray(new String[delMembers.size()])));
        }

        ModifyRequest modifyRequest = new ModifyRequest(groupDN, mods);
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
            return getGroup(newGroup.getID());
        }
        catch (GroupNotFoundException e)
        {
            throw new RuntimeException("BUG: modified group not found");
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
    public void deleteGroup(String groupID)
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
        
        if (group.description != null)
        {
            modifs.add(new Modification(ModificationType.DELETE, "description"));
        }
        
        if (group.lastModified != null)
        {
            modifs.add(new Modification(ModificationType.DELETE, "lastModified"));
        }
        
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
    public Collection<Group> getGroups(T userID, Role role, String groupID)
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
        
        if (role == Role.OWNER)
        {
            return getOwnerGroups(user, userDN, groupID);
        }
        else if (role == Role.MEMBER)
        {
            return getMemberGroups(user, userDN, groupID);
        }
        else if (role == Role.RW)
        {
            return getAdminGroups(user, userDN, groupID);
        }
        throw new IllegalArgumentException("Unknown role " + role);
    }
    
    protected Collection<Group> getOwnerGroups(User<T> user, DN userDN,
                                               String groupID)
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
                    config.getGroupsDN(), SearchScope.SUB, filter, 
                    new String[] {"cn", "description", "modifytimestamp"});
            
            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));
            
            Collection<Group> groups = new ArrayList<Group>();
            SearchResult results = getConnection().search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                String groupName = result.getAttributeValue("cn");
                // Ignore existing illegal group names.
                try
                {
                    Group group = new Group(groupName, user);
                    group.description = result.getAttributeValue("description");
                    group.lastModified = 
                        result.getAttributeValueAsDate("modifytimestamp");
                    groups.add(group);
                }
                catch (IllegalArgumentException ignore) { }   
            }
            
            return groups; 
        }
        catch (LDAPException e1)
        {
            // TODO check which LDAP exceptions are transient and which
            // ones are
            // access control
            throw new TransientException("Error getting groups", e1);
        }
    }
    
    protected Collection<Group> getMemberGroups(User<T> user, DN userDN, 
                                                String groupID)
        throws TransientException, AccessControlException,
               GroupNotFoundException, UserNotFoundException
    {
        if (groupID != null)
        {
            Collection<Group> groups = new ArrayList<Group>();
            if (userPersist.isMember(user.getUserID(), groupID))
            {
                groups.add(getGroup(groupID, false));
            }
            return groups;
        }
        else
        {
            try
            {
                Collection<Group> groups = 
                        userPersist.getUserGroups(user.getUserID());

                List<Filter> filters = new ArrayList<Filter>();
                for (Group group : groups)
                {
                    filters.add(Filter.createEqualityFilter("cn", 
                                                            group.getID()));
                }

                Filter filter = Filter.createORFilter(filters);
                SearchRequest searchRequest =  new SearchRequest(
                            config.getAdminGroupsDN(), SearchScope.SUB, filter, 
                            "cn");
            
                SearchResult results = getConnection().search(searchRequest);
                for (SearchResultEntry result : results.getSearchEntries())
                {
                    String groupName = result.getAttributeValue("cn");
  
                }
                return groups;
            }
            catch (LDAPException e)
            {
                throw new TransientException(e.getDiagnosticMessage());
            }
        }
    }
    
    protected Collection<Group> getAdminGroups(User<T> user, DN userDN,
                                            String groupID)
        throws TransientException, AccessControlException,
               GroupNotFoundException, UserNotFoundException
    {
        try
        {
            Collection<Group> queryGroups =  new ArrayList<Group>();
            if (groupID != null)
            {
                queryGroups.add(new Group(groupID, user));
            }
            else
            {
                // List of Groups the user belongs to.
                queryGroups.addAll(getMemberGroups(user, userDN, groupID));
            
                // List of Groups the user owns;
                queryGroups.addAll(getOwnerGroups(user, userDN, groupID));
            }
            
            System.out.println("# groups: " + queryGroups.size());
                    
            List<Filter> filters = new ArrayList<Filter>();
            for (Group member : queryGroups)
            {
//                // Require both groupRead and groupWrite
//                if (member.groupRead != null && member.groupWrite != null)
//                {
//                    DN groupRead = getGroupDN(member.groupRead.getID());
//                    String groupReadAci = 
//                        GROUP_READ_ACI.replace(ACTUAL_GROUP_TOKEN, 
//                                           groupRead.toNormalizedString());
//                    DN groupWrite = getGroupDN(member.groupRead.getID());
//                    String groupWriteAci = 
//                        GROUP_WRITE_ACI.replace(ACTUAL_GROUP_TOKEN, 
//                                            groupWrite.toNormalizedString());
//                    System.out.println(groupReadAci);
//                    System.out.println(groupWriteAci);
//
//                    Filter filter = Filter.createANDFilter(
//                            Filter.createEqualityFilter("aci", groupReadAci),
//                            Filter.createEqualityFilter("aci", groupWriteAci));
//                    filters.add(filter);
//                }
            }

            Collection<Group> groups = new ArrayList<Group>();
            if (filters.isEmpty())
            {
                return groups;
            }
            
            Filter filter = Filter.createORFilter(filters);
            SearchRequest searchRequest =  new SearchRequest(
                        config.getGroupsDN(), SearchScope.SUB, filter, 
                        new String[] {"cn", "owner", "description", 
                                      "modifytimestamp"});

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));
            
            SearchResult results = getConnection().search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                String groupName = result.getAttributeValue("cn");
                DN ownerDN = result.getAttributeValueAsDN("owner");
                User<X500Principal> owner = userPersist.getMember(ownerDN);
                
                // Ignore existing illegal group names.
                try
                {
                    Group group = new Group(groupName, owner);
                    group.description = result.getAttributeValue("description");
                    group.lastModified = 
                            result.getAttributeValueAsDate("modifytimestamp");
                    groups.add(group);
                }
                catch (IllegalArgumentException ignore) { }   
            }
            return groups;
        }
        catch (LDAPException e)
        {
            // TODO check which LDAP exceptions are transient and which
            // ones are
            // access control
            throw new TransientException("Error getting groups", e);
        }
    }
    
//    protected Collection<Group> getRWGroups2(User<T> user, DN userDN, 
//                                             String groupID)
//        throws TransientException, AccessControlException,
//               GroupNotFoundException, UserNotFoundException
//    {
//        try
//        {
//            Collection<Group> groups = new ArrayList<Group>();
//            
//            Collection<Group> queryGroups =  new ArrayList<Group>();
//            if (groupID != null)
//            {
//                queryGroups.add(new Group(groupID, user));
//            }
//            else
//            {
//                // List of Groups the user belongs to.
//                queryGroups.addAll(getMemberGroups(user, userDN, groupID));
//            
//                // List of Groups the user owns;
//                queryGroups.addAll(getOwnerGroups(user, userDN, groupID));
//            }
//            
//            for (Group member : queryGroups)
//            {
//                // Require both groupRead and groupWrite
//                if (member.groupRead != null && member.groupWrite != null)
//                {
//                    DN groupRead = getGroupDN(member.groupRead.getID());
//                    String groupReadAci = 
//                            GROUP_READ_ACI.replace(ACTUAL_GROUP_TOKEN, 
//                                            groupRead.toNormalizedString());
//                    DN groupWrite = getGroupDN(member.groupWrite.getID());
//                    String groupWriteAci = 
//                            GROUP_WRITE_ACI.replace(ACTUAL_GROUP_TOKEN, 
//                                            groupWrite.toNormalizedString());
//
//                    Filter filter = Filter.createANDFilter(
//                            Filter.createEqualityFilter("aci", groupReadAci),
//                            Filter.createEqualityFilter("aci", groupWriteAci));
//
//                    SearchRequest searchRequest = new SearchRequest(
//                            config.getGroupsDN(), SearchScope.SUB, filter, 
//                            new String[] {"cn", "owner", "description", 
//                                          "modifytimestamp"});
//
//                    searchRequest.addControl(
//                            new ProxiedAuthorizationV2RequestControl("dn:" + 
//                                    getSubjectDN().toNormalizedString()));
//
//                    SearchResult results = getConnection().search(searchRequest);
//                    for (SearchResultEntry result : results.getSearchEntries())
//                    {
//                        String groupName = result.getAttributeValue("cn");
//                        DN ownerDN = result.getAttributeValueAsDN("owner");
//                        User<X500Principal> owner = userPersist.getMember(ownerDN);
//
//                        // Ignore existing illegal group names.
//                        try
//                        {
//                            Group group = new Group(groupName, owner);
//                            group.description = result.getAttributeValue("description");
//                            group.lastModified = 
//                                    result.getAttributeValueAsDate("modifytimestamp");
//                            groups.add(group);
//                        }
//                        catch (IllegalArgumentException ignore) { } 
//                    }
//                }
//            }
//            return groups;
//        }
//        catch (LDAPException e)
//        {
//            // TODO check which LDAP exceptions are transient and which
//            // ones are
//            // access control
//            throw new TransientException("Error getting groups", e);
//        }
//    }

    /**
     * Returns a group based on its LDAP DN. The returned group is bare
     * (contains only group ID, description, modifytimestamp).
     * 
     * @param groupDN
     * @return
     * @throws com.unboundid.ldap.sdk.LDAPException
     * @throws ca.nrc.cadc.ac.GroupNotFoundException
     * @throws ca.nrc.cadc.ac.UserNotFoundException
     */
//    protected Group getGroup(DN groupDN)
//        throws LDAPException, GroupNotFoundException, UserNotFoundException
//    {
//        SearchResultEntry searchResult = 
//                getConnection().getEntry(groupDN.toNormalizedString(),
//                                new String[] {"cn", "description"});
//
//        if (searchResult == null)
//        {
//            String msg = "Group not found " + groupDN;
//            logger.debug(msg);
//            throw new GroupNotFoundException(groupDN.toNormalizedString());
//        }
//
//        Group group = new Group(searchResult.getAttributeValue("cn"));
//        group.description = searchResult.getAttributeValue("description");
//        return group;
//    }

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
