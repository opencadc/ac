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
import java.util.LinkedList;
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
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.ac.server.GroupDetailSelector;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.util.StringUtil;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
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
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import java.security.AccessController;
import javax.security.auth.Subject;

public class LdapGroupDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapGroupDAO.class);

    private static final String[] PUB_GROUP_ATTRS = new String[]
            {
                    "entrydn", "cn"
            };
    private static final String[] GROUP_ATTRS = new String[]
            {
                    "entrydn", "cn", "nsaccountlock", "owner",
                    "modifytimestamp", "description"
            };
    private static final String[] GROUP_AND_MEMBER_ATTRS = new String[]
            {
                    "entrydn", "cn", "nsaccountlock", "owner",
                    "modifytimestamp", "description", "uniquemember"
            };

    private final Profiler profiler = new Profiler(LdapGroupDAO.class);

    private LdapUserDAO<T> userDAO;

    // this gets filled by the LdapgroupPersistence
    GroupDetailSelector searchDetailSelector;

    public LdapGroupDAO(LdapConnections connections, LdapUserDAO<T> userPersist)
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
     * Persists a group.
     *
     * @param group The group to create
     * @return created group
     * @throws GroupAlreadyExistsException If a group with the same ID already
     *                                     exists.
     * @throws TransientException          If an temporary, unexpected problem occurred.
     * @throws UserNotFoundException       If owner or a member not valid user.
     * @throws GroupNotFoundException
     */
    public void addGroup(final Group group)
            throws GroupAlreadyExistsException, TransientException,
                   UserNotFoundException, AccessControlException,
                   GroupNotFoundException
    {
        if (!group.getProperties().isEmpty())
        {
            throw new UnsupportedOperationException(
                    "Support for groups properties not available");
        }

        // BM: Changed so that the group owner is set to be the
        // user in the subject
        //if (!isCreatorOwner(group.getOwner()))
        //{
        //    throw new AccessControlException("Group owner must be creator");
        //}

        try
        {
            Set<DNPrincipal> ds = group.getOwner().getIdentities(DNPrincipal.class);
            if (ds.isEmpty())
                throw new RuntimeException("BUG: User does not have an internal DNPrincipal");
            DNPrincipal dnp = ds.iterator().next();
            DN ownerDN = new DN(dnp.getName());
            
            if (reactivateGroup(group))
            {
                return;
            }
            else
            {

                // add group to groups tree
                LDAPResult result = addGroup(getGroupDN(group.getID()),
                                             group.getID(), ownerDN,
                                             group.description,
                                             group.getUserMembers(),
                                             group.getGroupMembers());
                LdapDAO.checkLdapResult(result.getResultCode());

                // add group to admin groups tree
                result = addGroup(getAdminGroupDN(group.getID()),
                                  group.getID(), ownerDN,
                                  group.description,
                                  group.getUserAdmins(),
                                  group.getGroupAdmins());
                LdapDAO.checkLdapResult(result.getResultCode());

            }
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
                                final Set<User<? extends Principal>> users,
                                final Set<Group> groups)
            throws UserNotFoundException, LDAPException, TransientException,
                   AccessControlException, GroupNotFoundException
    {
        // add new group
        List<Attribute> attributes = new ArrayList<Attribute>();
        Attribute ownerAttribute =
                new Attribute("owner", ownerDN.toNormalizedString());
        attributes.add(ownerAttribute);
        attributes.add(new Attribute("objectClass", "groupofuniquenames"));
        attributes.add(new Attribute("cn", groupID));

        if (StringUtil.hasText(description))
        {
            attributes.add(new Attribute("description", description));
        }

        List<String> members = new ArrayList<String>();
        for (User<? extends Principal> userMember : users)
        {
            DN memberDN = this.userDAO.getUserDN(userMember);
            members.add(memberDN.toNormalizedString());
        }
        for (Group groupMember : groups)
        {
            final String groupMemberID = groupMember.getID();
            if (!checkGroupExists(groupMemberID))
            {
                throw new GroupNotFoundException(groupMemberID);
            }
            DN memberDN = getGroupDN(groupMemberID);
            members.add(memberDN.toNormalizedString());
        }
        if (!members.isEmpty())
        {
            attributes.add(new Attribute("uniquemember",
                                         (String[]) members
                                                 .toArray(new String[members
                                                         .size()])));
        }

        AddRequest addRequest = new AddRequest(groupDN, attributes);
        //addRequest.addControl(
        //        new ProxiedAuthorizationV2RequestControl(
        //                "dn:" + getSubjectDN().toNormalizedString()));

        logger.debug("addGroup: " + groupDN);
        return getReadWriteConnection().add(addRequest);
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
    private boolean reactivateGroup(final Group group)
            throws AccessControlException, UserNotFoundException,
                   TransientException, GroupAlreadyExistsException
    {
        try
        {
            // check group name exists
            Filter filter = Filter.createEqualityFilter("cn", group.getID());

            DN groupDN = getGroupDN(group.getID());
            SearchRequest searchRequest =
                    new SearchRequest(groupDN.toNormalizedString(), SearchScope.BASE, filter,
                                      new String[]{"nsaccountlock"});

            //searchRequest.addControl(
            //        new ProxiedAuthorizationV2RequestControl("dn:" +
            //                                                 getSubjectDN()
            //                                                         .toNormalizedString()));

            SearchResultEntry searchResult = getReadWriteConnection()
                    .searchForEntry(searchRequest);

            if (searchResult == null)
            {
                return false;
            }

            if (searchResult.getAttributeValue("nsaccountlock") == null)
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
                    .createNOTFilter(Filter.createPresenceFilter("nsaccountlock"));
            filter = Filter.createANDFilter(filter, Filter.create("(cn=*)"));

            final List<String> groupNames = new LinkedList<String>();
            SearchRequest searchRequest = new SearchRequest(
                    new SearchResultListener()
                    {
                        long t1 = System.currentTimeMillis();

                        public void searchEntryReturned(SearchResultEntry sre)
                        {
                            String gname = sre.getAttributeValue("cn");
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

                                logger.debug("found: " + groupNames
                                        .size() + " " + dt + "ms");
                                t1 = t2;
                            }
                        }

                        public void searchReferenceReturned(SearchResultReference srr)
                        {
                            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                        }
                    }, config
                            .getGroupsDN(), SearchScope.ONE, filter, PUB_GROUP_ATTRS);

            SearchResult searchResult = null;
            try
            {
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
            profiler.checkpoint("checkLdapResult");

            return groupNames;
        }
        catch (LDAPException e1)
        {
            logger.debug("getGroupNames Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
            throw new IllegalStateException("Unexpected exception: " + e1
                    .getMatchedDN(), e1);
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
        String[] attrs = GROUP_ATTRS;
        if (complete)
            attrs = GROUP_AND_MEMBER_ATTRS;
        
        Group group = getGroup(getGroupDN(groupID), groupID, attrs);

        if (complete)
        {
            Group adminGroup = getGroup(getAdminGroupDN(groupID), null, GROUP_AND_MEMBER_ATTRS);
            group.getGroupAdmins().addAll(adminGroup.getGroupMembers());
            group.getUserAdmins().addAll(adminGroup.getUserMembers());
        }

        return group;
    }

    // groupID is here so exceptions and loggiong have plain groupID instead of DN
    private Group getGroup(final DN groupDN, final String xgroupID, String[] attributes)
            throws GroupNotFoundException, TransientException,
                   AccessControlException
    {
        logger.debug("getGroup: " + groupDN + " attrs: " + attributes.length);
        String loggableGroupID = xgroupID;
        if (loggableGroupID == null)
        {
            loggableGroupID = groupDN
                    .toString(); // member or admin group: same name, internal tree
        }

        try
        {
            Filter filter = Filter.createNOTFilter(Filter.createPresenceFilter("nsaccountlock"));
            filter = Filter.createANDFilter(filter,
                    Filter.createEqualityFilter("entrydn", groupDN.toNormalizedString()));

            SearchRequest searchRequest =
                    new SearchRequest(groupDN.toNormalizedString(),
                                      SearchScope.BASE, filter, attributes);

            // permissions now checked in LdapGroupPersistence
            
            //searchRequest.addControl(
            //        new ProxiedAuthorizationV2RequestControl("dn:" +
            //                                                 getSubjectDN()
            //                                                         .toNormalizedString()));
            

            SearchResultEntry searchEntry = getReadOnlyConnection()
                    .searchForEntry(searchRequest);

            if (searchEntry == null)
            {
                String msg = "Group not found " + loggableGroupID;
                logger.debug(msg + " cause: null");
                throw new GroupNotFoundException(loggableGroupID);
            }

            Group ldapGroup = createGroupFromEntry(searchEntry, attributes);

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
                            user = userDAO.getX500User(memberDN);
                            ldapGroup.getUserMembers().add(user);
                        }
                        catch (UserNotFoundException e)
                        {
                            // ignore as we do not cleanup deleted users
                            // from groups they belong to
                        }
                    }
                    else if (memberDN
                            .isDescendantOf(config.getGroupsDN(), false))
                    {
                        try
                        {
                            ldapGroup.getGroupMembers()
                                    .add(getGroup(memberDN, null, PUB_GROUP_ATTRS));
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
        String groupID = group.getID();
        getGroup(getGroupDN(groupID), groupID, PUB_GROUP_ATTRS);//group must exists first
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

        if (StringUtil.hasText(group.description))
        {
            mods.add(new Modification(ModificationType.REPLACE, "description",
                                      group.description));
        }
        else
        {
            mods.add(new Modification(ModificationType.REPLACE, "description"));
        }

        try
        {
            Set<String> newMembers = new HashSet<String>();
            for (User<?> member : group.getUserMembers())
            {
                DN memberDN = userDAO.getUserDN(member);
                newMembers.add(memberDN.toNormalizedString());
            }
            for (Group gr : group.getGroupMembers())
            {
                if (!checkGroupExists(gr.getID()))
                {
                    throw new GroupNotFoundException(gr.getID());
                }
                DN grDN = getGroupDN(gr.getID());
                newMembers.add(grDN.toNormalizedString());
            }

            Set<String> newAdmins = new HashSet<String>();
            for (User<?> member : group.getUserAdmins())
            {
                DN memberDN = userDAO.getUserDN(member);
                newAdmins.add(memberDN.toNormalizedString());
            }
            for (Group gr : group.getGroupAdmins())
            {
                if (!checkGroupExists(gr.getID()))
                {
                    throw new GroupNotFoundException(gr.getID());
                }
                DN grDN = getGroupDN(gr.getID());
                newAdmins.add(grDN.toNormalizedString());
            }

            // modify the admin group
            adminMods.add(new Modification(ModificationType.REPLACE, "uniquemember",
                                          (String[]) newAdmins
                                                  .toArray(new String[newAdmins
                                                          .size()])));

            ModifyRequest adminModify =
                    new ModifyRequest(getAdminGroupDN(group.getID()), adminMods);

            //adminModify.addControl(
            //        new ProxiedAuthorizationV2RequestControl(
            //                "dn:" + getSubjectDN().toNormalizedString()));

            LdapDAO.checkLdapResult(
                getReadWriteConnection().modify(adminModify).getResultCode());

            // modify the group itself
            mods.add(new Modification(ModificationType.REPLACE, "uniquemember",
                (String[]) newMembers
                    .toArray(new String[newMembers
                        .size()])));

            ModifyRequest modifyRequest =
                new ModifyRequest(getGroupDN(group.getID()), mods);

            //modifyRequest.addControl(
            //        new ProxiedAuthorizationV2RequestControl(
            //                "dn:" + getSubjectDN().toNormalizedString()));

            LdapDAO.checkLdapResult(
                getReadWriteConnection().modify(modifyRequest).getResultCode());
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
                return new ActivatedGroup(getGroup(group.getID(), true));
            }
            else
            {
                return getGroup(group.getID(), true);
            }
        }
        catch (GroupNotFoundException e)
        {
            throw new RuntimeException("BUG: modified group not found (" + group
                    .getID() + ")");
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
        ModifyRequest clearMembers = new ModifyRequest(groupDN, 
                new Modification(ModificationType.DELETE, "uniquemember"));
        try
        {
            logger.debug("clearMembers " + groupDN);
            LDAPResult result = getReadWriteConnection().modify(clearMembers);
            LdapDAO.checkLdapResult(result.getResultCode(), true);
        }
        catch (LDAPException e1)
        {
            logger.debug("clear members fail: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode(), true);
        }

        ModifyRequest deleteGroup = new ModifyRequest(groupDN, 
                new Modification(ModificationType.ADD, "nsaccountlock", "true"));
        
        try
        {
            logger.debug("deleteGroup " + groupDN);
            LDAPResult result = getReadWriteConnection().modify(deleteGroup);
            LdapDAO.checkLdapResult(result.getResultCode());
        }
        catch (LDAPException e1)
        {
            logger.debug("delete group fail: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }

        try
        {
            Group g = getGroup(getGroupDN(groupID), null, GROUP_ATTRS);
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
            
            Filter filter = Filter.createNOTFilter(Filter.createPresenceFilter("nsaccountlock"));

            filter = Filter.createANDFilter(filter, 
                    Filter.createEqualityFilter("owner", userDN.toNormalizedString()));

            if (groupID != null)
            {
                DN groupDN = getGroupDN(groupID);
                filter = Filter.createANDFilter(filter, 
                    Filter.createEqualityFilter("entrydn", groupDN.toNormalizedString()));
            }

            SearchRequest searchRequest = new SearchRequest(
                    config.getGroupsDN(), SearchScope.SUB, filter, GROUP_ATTRS);

            //searchRequest.addControl(
            //        new ProxiedAuthorizationV2RequestControl("dn:" +
            //                                                 getSubjectDN()
            //                                                         .toNormalizedString()));

            SearchResult results = getReadOnlyConnection()
                    .search(searchRequest);
            for (SearchResultEntry result : results.getSearchEntries())
            {
                ret.add(createGroupFromEntry(result, GROUP_ATTRS));
            }
        }
        catch (LDAPException e1)
        {
            logger.debug("getOwnerGroups Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }
        return ret;
    }

    private Group createGroupFromEntry(SearchResultEntry result, String[] attributes)
            throws LDAPException, TransientException
    {
        if (result.getAttribute("nsaccountlock") != null)
        {
            throw new RuntimeException("BUG: found group with nsaccountlock set: " + result
                    .getAttributeValue("entrydn").toString());
        }

        String entryDN = result.getAttributeValue("entrydn");
        String groupName = result.getAttributeValue("cn");
        if (attributes == PUB_GROUP_ATTRS)
        {
            return new Group(groupName);
        }

        DN ownerDN = result.getAttributeValueAsDN("owner");
        if (ownerDN == null)
        {
            throw new AccessControlException(groupName);
        }
        try
        {
            User owner = userDAO.getX500User(ownerDN);
            Group g = new Group(groupName, owner);
            if (result.hasAttribute("description"))
            {
                g.description = result.getAttributeValue("description");
            }
            if (result.hasAttribute("modifytimestamp"))
            {
                g.lastModified = result
                        .getAttributeValueAsDate("modifytimestamp");
            }
            return g;
        }
        catch (UserNotFoundException ex)
        {
            throw new RuntimeException("Invalid state: owner does not exist: " + ownerDN + " group: " + entryDN);
        }
    }

    /**
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
            logger.debug("getGroupDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }

    /**
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
            logger.debug("getAdminGroupDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(groupID + " not a valid group ID");
    }

    private boolean checkGroupExists(String groupID)
            throws LDAPException, TransientException
    {
        try
        {
            Group g = getGroup(getGroupDN(groupID), groupID, PUB_GROUP_ATTRS);
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

}
