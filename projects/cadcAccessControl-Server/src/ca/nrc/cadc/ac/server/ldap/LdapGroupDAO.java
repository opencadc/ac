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
import java.util.HashSet;
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
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;

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
     * Persists a group.
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
        
        if (!group.getProperties().isEmpty())
        {
            throw new UnsupportedOperationException(
                    "Support for groups properties not available");
        }
        
        if (!isCreatorOwner(group.getOwner()))
        {
            throw new AccessControlException("Group owner must be creator");
        }

        try
        {
            Group newGroup = reactivateGroup(group);
            if ( newGroup != null)
            {
                return newGroup;
            }
            else
            {
                
                DN ownerDN = userPersist.getUserDN(group.getOwner());
                
                // add group to groups tree
                LDAPResult result = addGroup(getGroupDN(group.getID()), 
                                             group.getID(), ownerDN, 
                                             group.description, 
                                             group.getUserMembers(), 
                                             group.getGroupMembers());
                LdapDAO.checkLdapResult(result.getResultCode(), null);
                
                // add group to admin groups tree
                result = addGroup(getAdminGroupDN(group.getID()), 
                                  group.getID(), ownerDN, 
                                  group.description, 
                                  group.getUserAdmins(), 
                                  group.getGroupAdmins());
                LdapDAO.checkLdapResult(result.getResultCode(), null);
                
                try
                {
                    return getGroup(group.getID());
                }
                catch (GroupNotFoundException e)
                {
                    throw new RuntimeException("BUG: new group not found");
                }
            }
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), 
                    e.getDiagnosticMessage());
            throw new RuntimeException("Unexpected LDAP exception", e);
        } 
    }
    
    private LDAPResult addGroup(final DN groupDN, final String groupID,
                                final DN ownerDN, final String description, 
                                final Set<User<? extends Principal>> users, 
                                final Set<Group> groups)
        throws UserNotFoundException, LDAPException, TransientException
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
    
    
    /**
     * Checks whether group name available for the user or already in use.
     * @param group
     * @return activated group or null if group does not exists
     * @throws AccessControlException
     * @throws UserNotFoundException
     * @throws GroupNotFoundException
     * @throws TransientException
     * @throws GroupAlreadyExistsException 
     */
    private Group reactivateGroup(final Group group)
        throws AccessControlException, UserNotFoundException,
        TransientException, GroupAlreadyExistsException
    {
        try
        {
            // check group name exists           
            Filter filter = Filter.createEqualityFilter("cn", group.getID());

            SearchRequest searchRequest = 
                    new SearchRequest(
                            getGroupDN(group.getID())
                            .toNormalizedString(), SearchScope.SUB, filter, 
                                      new String[] {"nsaccountlock"});

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            SearchResultEntry searchResult = 
                    getConnection().searchForEntry(searchRequest);
            
            if (searchResult == null)
            {
                return null;
            }

            if (searchResult.getAttributeValue("nsaccountlock") == null)
            {
                throw new 
                GroupAlreadyExistsException("Group already exists " + group.getID());
            }
            
            // activate group            
            try
            {
                return modifyGroup(group, true);
            } 
            catch (GroupNotFoundException e)
            {
                throw new RuntimeException(
                        "BUG: group to modify does not exist" + group.getID());
            }          
        } 
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
            throw new RuntimeException("Unexpected LDAP exception", e);
        }
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
                                             "modifytimestamp", "nsaccountlock"};
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
            Filter filter = Filter.createEqualityFilter("cn", groupID);
            
            SearchRequest searchRequest = 
                    new SearchRequest(groupDN.toNormalizedString(), 
                                      SearchScope.SUB, filter, attributes);

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            SearchResult searchResult = null;
            try
            {
                searchResult = getConnection().search(searchRequest);
            }
            catch (LDAPSearchException e)
            {
                if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT)
                {
                    String msg = "Group not found " + groupID;
                    logger.debug(msg);
                    throw new GroupNotFoundException(groupID);
                }
                else
                {
                    LdapDAO.checkLdapResult(e.getResultCode(), e.getMessage());
                }
            }
            
            if (searchResult.getEntryCount() == 0)
            {
                LdapDAO.checkLdapResult(searchResult.getResultCode(), null);
                //access denied
                String msg = "Not authorized to access " + groupID;
                logger.debug(msg);
                throw new AccessControlException(groupID);
            }
            
            if (searchResult.getEntryCount() >1)
            {
                throw new RuntimeException("BUG: multiple results when retrieving group " + groupID);
            }
            
            SearchResultEntry searchEntry = searchResult.getSearchEntries().get(0);
            
            if (searchEntry.getAttribute("nsaccountlock") != null)
            {
                // deleted group
                String msg = "Group not found " + groupID;
                logger.debug(msg);
                throw new GroupNotFoundException(groupID);
            }
            
            String groupCN = searchEntry.getAttributeValue("cn");
            DN groupOwner = searchEntry.getAttributeValueAsDN("owner");
            
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
            if (searchEntry.hasAttribute("description"))
            {
                ldapGroup.description = 
                        searchEntry.getAttributeValue("description");
            }
            if (searchEntry.hasAttribute("modifytimestamp"))
            {
                ldapGroup.lastModified = 
                        searchEntry.getAttributeValueAsDate("modifytimestamp");
            }

            if (withMembers)
            {
                if (searchEntry.getAttributeValues("uniquemember") != null)
                {
                    for (String member : searchEntry
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
            LdapDAO.checkLdapResult(e1.getResultCode(), e1.getDiagnosticMessage());
            throw new GroupNotFoundException("Not found " + groupID);
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
        getGroup(group.getID()); //group must exists first
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
            DN memberDN = userPersist.getUserDN(member);
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
            DN memberDN = userPersist.getUserDN(member);
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
            LdapDAO.checkLdapResult(getConnection().
                    modify(modifyRequest).getResultCode(), null);
            
            // modify the group itself now
            modifyRequest = new ModifyRequest(getGroupDN(group.getID()), mods);

            modifyRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl(
                            "dn:" + getSubjectDN().toNormalizedString()));
            LdapDAO.checkLdapResult(getConnection().
                    modify(modifyRequest).getResultCode(), null);
        }
        catch (LDAPException e1)
        {
            LdapDAO.checkLdapResult(e1.getResultCode(), e1.getDiagnosticMessage());
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
            LdapDAO.checkLdapResult(result.getResultCode(), null);
        }
        catch (LDAPException e1)
        {
            LdapDAO.checkLdapResult(e1.getResultCode(), e1.getDiagnosticMessage());
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
        DN userDN = userPersist.getUserDN(user);
        
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
                if (role == Role.ADMIN)
                {
                    groupDN = new DN(groupDN.getRDNString() + "," + config.getGroupsDN());
                }
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
        Collection<DN> groupDNs = new HashSet<DN>();
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
            
            SearchResult results = getConnection().search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                String entryDN = result.getAttributeValue("entrydn");
                groupDNs.add(new DN(entryDN));
            }
        }
        catch (LDAPException e1)
        {
            LdapDAO.checkLdapResult(e1.getResultCode(), e1.getDiagnosticMessage());
        }
        return groupDNs; 
    }
    
    protected Collection<DN> getMemberGroups(final User<T> user, 
                                             final DN userDN, 
                                             final String groupID,
                                             final boolean isAdmin)
        throws TransientException, AccessControlException,
               GroupNotFoundException, UserNotFoundException
    {
        Collection<DN> groupDNs = new HashSet<DN>();
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
                groupDNs.add(groupDN);
            }
        }
        else
        {
            Collection<DN> memberGroupDNs = 
                    userPersist.getUserGroups(user.getUserID(), isAdmin);
            groupDNs.addAll(memberGroupDNs);
        }
        return groupDNs;
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
        Filter filter = Filter.createEqualityFilter("entrydn", 
                                                    groupDN.toNormalizedString());
        
        SearchRequest searchRequest =  new SearchRequest(
                    config.getGroupsDN(), SearchScope.SUB, filter, 
                    new String[] {"cn", "description"});
            
        searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));
            
        SearchResultEntry searchResult = 
                getConnection().searchForEntry(searchRequest);

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
    protected DN getGroupDN(final String groupID) throws TransientException
    {
        try
        {
            return new DN("cn=" + groupID + "," + config.getGroupsDN());
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }
    
    /**
     * 
     * @param groupID
     * @return 
     */
    protected DN getAdminGroupDN(final String groupID) throws TransientException
    {
        try
        {
            return new DN("cn=" + groupID + "," + config.getAdminGroupsDN());
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
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
