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
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

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
    private static final String PUB_GROUP_ACI = "(targetattr = \"*\") " + 
            "(version 3.0;acl \"Group Public\";" + 
            "allow (read,compare,search)userdn=\"ldap:///anyone\";)";
    
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
     * Get the group with the given Group ID.
     * 
     * @param groupID The Group unique ID.
     * 
     * @return A Group instance
     * 
     * @throws GroupNotFoundException If the group was not found.
     * @throws TransientException  If an temporary, unexpected problem occurred.
     */
    public Group getGroup(String groupID)
        throws GroupNotFoundException, TransientException,
               AccessControlException
    {
        return getGroup(groupID, true);
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

                DN ownerDN = userPersist.getUserDN(group.getOwner());
                String groupWriteAci = null;
                String groupReadAci = null;
                if (group.groupWrite != null)
                {
                    DN groupWrite = getGroupDN(group.groupWrite.getID());
                    groupWriteAci = GROUP_WRITE_ACI.replace(
                            ACTUAL_GROUP_TOKEN, 
                            groupWrite.toNormalizedString());
                }

                if (group.groupRead != null)
                {
                    DN groupRead = getGroupDN(group.groupRead.getID());
                    groupReadAci = GROUP_READ_ACI.replace(
                            ACTUAL_GROUP_TOKEN, 
                            groupRead.toNormalizedString());
                }

                // add new group
                List<Attribute> attributes = new ArrayList<Attribute>();
                attributes.add(new Attribute("objectClass", 
                                             "groupofuniquenames"));

                attributes.add(new Attribute("cn", group.getID()));
                if (group.description != null)
                {
                    attributes.add(new Attribute("description", 
                                                 group.description));
                }

                attributes.add(new Attribute("owner", 
                                             ownerDN.toNormalizedString()));

                // acis
                List<String> acis = new ArrayList<String>();
                if (group.publicRead)
                {
                    acis.add(PUB_GROUP_ACI);
                }
                if (groupWriteAci != null)
                {
                    acis.add(groupWriteAci);
                }
                if (groupReadAci != null)
                {
                    acis.add(groupReadAci);
                }

                if (!acis.isEmpty())
                {
                    attributes.add(new Attribute("aci", 
                            (String[]) acis.toArray(new String[acis.size()])));
                }

                List<String> members = new ArrayList<String>();
                for (User<?> member : group.getUserMembers())
                {
                    DN memberDN = this.userPersist.getUserDN(member);
                    members.add(memberDN.toNormalizedString());
                }
                for (Group gr : group.getGroupMembers())
                {
                    DN grDN = getGroupDN(gr.getID());
                    members.add(grDN.toNormalizedString());
                }
                if (!members.isEmpty())
                {
                    attributes.add(new Attribute("uniquemember", 
                        (String[]) members.toArray(new String[members.size()])));
                }

                AddRequest addRequest = 
                        new AddRequest(getGroupDN(group.getID()), attributes);

                addRequest.addControl(
                        new ProxiedAuthorizationV2RequestControl(
                                "dn:" + getSubjectDN().toNormalizedString()));

                LDAPResult result = getConnection().add(addRequest);
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
                throw new RuntimeException(e);
            }
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
        Group group = getGroup(groupID, false);
        DN groupDN = getGroupDN(group.getID());
        try
        {
            ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
                    group.getID(), group.getID(), 
                    true, config.getDeletedGroupsDN());

            modifyDNRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            LDAPResult result = getConnection().modifyDN(modifyDNRequest);
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
     * @param user<T> ID of user
     * @param role Role of the user, either owner, member, or read/write.
     * 
     * @return Collection of Groups
     *         matching GROUP_READ_ACI.replace(ACTUAL_GROUP_TOKEN,
     *         readGrDN.toNormalizedString()) the query, or empty
     *         Collection. Never null.
     * @throws TransientException  If an temporary, unexpected problem occurred.
     * @throws UserNotFoundException
     */
    public Collection<Group> getGroups(User<T> user, Role role)
        throws TransientException, AccessControlException,
               UserNotFoundException
    {
        try
        {   
            DN userDN = userPersist.getUserDN(user);
            Filter filter = null;
            if (role == Role.OWNER)
            {
                filter = Filter.createEqualityFilter("owner", userDN.toString());
            }
            else if (role == Role.MEMBER)
            {
                throw new IllegalArgumentException("Member role not implemented");
            }
            else if (role == Role.RW)
            {
                throw new IllegalArgumentException("RW role not implemented");
            }
            
            SearchRequest searchRequest =  new SearchRequest(
                    config.getGroupsDN(), SearchScope.SUB, filter, 
                    new String[] {"cn", "description",
                                  "owner", "modifytimestamp"});
            
            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));
            
            Collection<Group> groups = new ArrayList<Group>();
            SearchResult results = getConnection().search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                String groupName = result.getAttributeValue("cn");
                DN groupOwner = result.getAttributeValueAsDN("owner");
                
                User<X500Principal> owner;
                try
                {
                    owner = userPersist.getMember(groupOwner);
                }
                catch (UserNotFoundException e)
                {
                    throw new RuntimeException("BUG: group owner not found");
                }
                
                Group group = new Group(groupName, owner);
                group.description = result.getAttributeValue("description");
                group.lastModified = result.getAttributeValueAsDate("modifytimestamp");
                groups.add(group);
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

    public boolean isMember(User<T> user, String groupID)
        throws UserNotFoundException, TransientException,
               AccessControlException
    {
        return false;
//        try
//        {
//            
//           
//        }
//        catch (LDAPException e1)
//        {
//            // TODO check which LDAP exceptions are transient and which
//            // ones are
//            // access control
//            throw new TransientException("Error getting the group", e1);
//        }
    }
    
    private Group getGroup(String groupID, boolean withMembers)
        throws GroupNotFoundException, TransientException, 
               AccessControlException
    {
        try
        {
            SearchRequest searchRequest =  new SearchRequest(
                    config.getGroupsDN(), SearchScope.SUB, 
                    "(cn=" + groupID + ")", new String[] {"entrydn", "entryid", 
                    "cn", "description", "owner", "uniquemember", "aci", 
                    "modifytimestamp"});

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            SearchResultEntry group = 
                    getConnection().searchForEntry(searchRequest);
            if (group == null)
            {
                String msg = "Group not found " + groupID;
                logger.debug(msg);
                throw new GroupNotFoundException(groupID);
            }
            String groupCN = group.getAttributeValue("cn");
            DN groupOwner = group.getAttributeValueAsDN("owner");
            Long grID = group.getAttributeValueAsLong("entryid");
            Date lastModified = 
                group.getAttributeValueAsDate("modifytimestamp");
            
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
            ldapGroup.description = group.getAttributeValue("description");
            ldapGroup.lastModified = lastModified;

            if (withMembers)
            {
                if (group.getAttributeValues("uniquemember") != null)
                {
                    for (String member : group
                            .getAttributeValues("uniquemember"))
                    {
                        DN memberDN = new DN(member);
                        if (memberDN.isDescendantOf(config.getUsersDN(), false))
                        {
                            User<X500Principal> usr;
                            try
                            {
                                usr = userPersist.getMember(memberDN);
                            }
                            catch (UserNotFoundException e)
                            {
                                throw new RuntimeException(
                                    "BUG: group member not found");
                            }
                            ldapGroup.getUserMembers().add(usr);
                        }
                        else if (memberDN.isDescendantOf(config.getGroupsDN(),
                                                         false))
                        {
                            Group memberGroup = getGroup(memberDN);
                            ldapGroup.getGroupMembers().add(memberGroup);
                        }
                        else
                        {
                            throw new RuntimeException(
                                "BUG: unknown member DN type: " + memberDN);
                        }
                    }
                }

                // TODO not sure this is going to fly...
                if (group.getAttributeValues("aci") != null)
                {
                    for (String aci : group.getAttributeValues("aci"))
                    {
                        if (aci.contains("Group Read"))
                        {
                            // TODO it's gotta be a better way to do this.
                            String grRead = aci.substring(
                                    aci.indexOf("ldap:///"));
                            grRead = grRead.substring(grRead.indexOf("cn"),
                                                      grRead.lastIndexOf('"'));

                            Group groupRead = getGroup(new DN(grRead));
                            ldapGroup.groupRead = groupRead;
                        }
                        else if (aci.contains("Group Write"))
                        {
                            // TODO it's gotta be a better way to do this.
                            String grWrite = aci.substring(
                                    aci.indexOf("ldap:///"));
                            grWrite = grWrite.substring(grWrite.indexOf("cn"), 
                                                    grWrite.lastIndexOf('"'));

                            Group groupWrite = getGroup(new DN(grWrite));
                            ldapGroup.groupWrite = groupWrite;
                        }
                        else if (aci.equals(PUB_GROUP_ACI))
                        {
                            ldapGroup.publicRead = true;
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
        catch (UserNotFoundException e2)
        {
            throw new RuntimeException("BUG - owner or member not found", e2);
        }
    }

    public Group modifyGroup(Group group)
        throws GroupNotFoundException, TransientException,
               AccessControlException, UserNotFoundException
    {
        // check if group exists
        Group oldGroup = getGroup(group.getID());
        if (!group.getProperties().isEmpty())
        {
            throw new UnsupportedOperationException(
                    "Support for groups properties not available");
        }

        List<Modification> modifs = new ArrayList<Modification>();
        if (group.description == null)
        {
            modifs.add(new Modification(ModificationType.DELETE, 
                                        "description"));
        }
        else
        {
            modifs.add(new Modification(ModificationType.REPLACE, "description", 
                                        group.description));
        }

        List<String> acis = new ArrayList<String>();
        if (group.groupRead != null)
        {
            if (group.groupRead.equals(group))
            {
                throw new IllegalArgumentException(
                        "cyclical reference from groupRead to group");
            }

            DN readGrDN = getGroupDN(group.groupRead.getID());
            acis.add(GROUP_READ_ACI.replace(ACTUAL_GROUP_TOKEN, 
                                            readGrDN.toNormalizedString()));
        }

        if (group.groupWrite != null)
        {
            if (group.groupWrite.equals(group))
            {
                throw new IllegalArgumentException(
                        "cyclical reference from groupWrite to group");
            }

            DN writeGrDN = getGroupDN(group.groupWrite.getID());
            acis.add(GROUP_WRITE_ACI.replace(ACTUAL_GROUP_TOKEN, 
                                             writeGrDN.toNormalizedString()));
        }

        if (group.publicRead)
        {
            acis.add(PUB_GROUP_ACI);
        }
        modifs.add(new Modification(ModificationType.REPLACE, "aci", (String[]) 
                                    acis.toArray(new String[acis.size()])));

        List<String> newMembers = new ArrayList<String>();
        for (User<?> member : group.getUserMembers())
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
        for (Group gr : group.getGroupMembers())
        {
            if (gr.equals(group))
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
        if (!newMembers.isEmpty())
        {
            modifs.add(new Modification(ModificationType.ADD, "uniquemember", 
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
        if (!delMembers.isEmpty())
        {
            modifs.add(new Modification(ModificationType.DELETE, "uniquemember",
                (String[]) delMembers.toArray(new String[delMembers.size()])));
        }

        ModifyRequest modifyRequest = 
                new ModifyRequest(getGroupDN(group.getID()), modifs);
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
            return getGroup(group.getID());
        }
        catch (GroupNotFoundException e)
        {
            throw new RuntimeException("BUG: new group not found");
        }
    }

    /**
     * Returns a group based on its LDAP DN. The returned group is bared
     * (contains only group ID, owner and description).
     * 
     * @param groupDN
     * @return
     * @throws com.unboundid.ldap.sdk.LDAPException
     * @throws ca.nrc.cadc.ac.GroupNotFoundException
     * @throws ca.nrc.cadc.ac.UserNotFoundException
     */
    protected Group getGroup(DN groupDN)
        throws LDAPException, GroupNotFoundException, UserNotFoundException
    {
        SearchResultEntry searchResult = null;

        searchResult = 
                getConnection().getEntry(groupDN.toNormalizedString(),
                                new String[] {"cn", "description", "owner"});

        if (searchResult == null)
        {
            String msg = "Group not found " + groupDN;
            logger.debug(msg);
            throw new GroupNotFoundException(groupDN.toNormalizedString());
        }

        DN ownerDN = searchResult.getAttributeValueAsDN("owner");
        User<X500Principal> owner = userPersist.getMember(ownerDN);
        Group group = new Group(searchResult.getAttributeValue("cn"), owner);

        return group;
    }

    protected DN getGroupDN(String groupID)
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

}
