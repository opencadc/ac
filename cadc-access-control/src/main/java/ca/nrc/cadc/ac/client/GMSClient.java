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

package ca.nrc.cadc.ac.client;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.ac.xml.GroupListReader;
import ca.nrc.cadc.ac.xml.GroupReader;
import ca.nrc.cadc.ac.xml.GroupWriter;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.FileContent;
import ca.nrc.cadc.net.HttpDelete;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.HttpTransfer;
import ca.nrc.cadc.net.HttpUpload;
import ca.nrc.cadc.net.InputStreamWrapper;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.net.event.TransferEvent;
import ca.nrc.cadc.net.event.TransferListener;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;
import org.opencadc.gms.GroupClient;
import org.opencadc.gms.GroupURI;

/**
 * Client class for performing group searching and group actions
 * with the access control web service.
 */
public class GMSClient implements TransferListener, GroupClient
{
    private static final Logger log = Logger.getLogger(GMSClient.class);

    final private URI serviceID;

    /**
     * Constructor.
     *
     * @param serviceID            The service ID.
     */
    public GMSClient(URI serviceID)
    {
        if (serviceID == null)
            throw new IllegalArgumentException("invalid serviceID: " + serviceID);
        if (serviceID.getFragment() != null)
            throw new IllegalArgumentException("invalid serviceID (fragment not allowed): " + serviceID);
        this.serviceID = serviceID;
    }

    public void transferEvent(TransferEvent te)
    {
        if ( TransferEvent.RETRYING == te.getState() )
            log.debug("retry after request failed, reason: "  + te.getError());
    }

    public String getEventHeader()
    {
        return null; // no custom eventID header
    }

    /**
     * GMSClient Interface compliance.
     *
     * Default 'role' within a group is 'membership'
     *
     * Ensure serviceIDs match.
     */
    @Override
    public List<GroupURI> getMemberships(List<GroupURI> groups) {
        // return empty list for null or empty groups list
        if (groups == null || groups.isEmpty()) {
            return new ArrayList<>();
        }

        // discard groups not in the target GMS service
        List<String> groupNames = new ArrayList<>();
        for (GroupURI group : groups) {
            if (group.getServiceID().equals(this.serviceID)) {
                groupNames.add(group.getName());
            } else {
                log.warn(String.format("%s is not in the target GMS service %s",
                                       group.getURI().toASCIIString(), this.serviceID.toASCIIString()));
            }
        }
        if (groupNames.isEmpty()) {
            return new ArrayList<>();
        }

        try {
            List<Group> memberships = this.getMemberships(groupNames, null, Role.MEMBER);
            return memberships.stream().map(Group::getID).collect(Collectors.toList());
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * GMSClient Interface compliance.
     *
     * Return true is the calling user is a member
     * of a group in the list of groups.
     *
     * @param groups The groups whose membership to check
     * @return true if the user is a member of a group, false otherwise.
     */
    @Override
    public boolean isMember(List<GroupURI> groups) {
        return !this.getMemberships(groups).isEmpty();
    }
    
    /**
     * GMSClient Interface compliance.
     * 
     * Default 'role' within a group is 'membership'
     * 
     * Ensure serviceIDs match.
     */
    @Override
    public boolean isMember(GroupURI group) {
        return !this.getMemberships(Stream.of(group).collect(Collectors.toList())).isEmpty();
    }
    
    /**
     * GMSClient Interface compliance.
     *  
     * Default 'role' within a group is 'membership'
     */
    @Deprecated
    @Override
    public List<GroupURI> getMemberships() {
        try {
            List<Group> memberships = this.getMemberships(Role.MEMBER);
            return memberships.stream().map(Group::getID).collect(Collectors.toList());
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get a list of groups.
     *
     * @return The list of groups.
     */
    public List<Group> getGroups()
    {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    /**
     * Create a new group.
     *
     * @param group The group to create
     * @return The newly created group will all the information.
     * @throws GroupAlreadyExistsException If a group with the same name already
     *                                     exists.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws UserNotFoundException If User not found
     * @throws IOException If underlying service call fails
     */
    public Group createGroup(Group group)
        throws GroupAlreadyExistsException, AccessControlException,
               UserNotFoundException, WriterException, IOException
    {
        URL createGroupURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        log.debug("createGroupURL request to " + createGroupURL.toString());

        // reset the state of the cache
        clearCache();

        StringBuilder groupXML = new StringBuilder();
        GroupWriter groupWriter = new GroupWriter();
        groupWriter.write(group, groupXML);
        log.debug("createGroup: " + groupXML);

        byte[] bytes = groupXML.toString().getBytes("UTF-8");
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);

        HttpUpload transfer = new HttpUpload(in, createGroupURL);

        transfer.run();

        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            log.debug("createGroup throwable", error);
            // transfer returns a -1 code for anonymous uploads.
            if ((transfer.getResponseCode() == -1) ||
                (transfer.getResponseCode() == 401) ||
                (transfer.getResponseCode() == 403))
            {
                throw new AccessControlException(error.getMessage());
            }
            if (transfer.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            if (transfer.getResponseCode() == 409)
            {
                throw new GroupAlreadyExistsException(error.getMessage());
            }
            if (transfer.getResponseCode() == 404)
            {
                throw new UserNotFoundException(error.getMessage());
            }
            throw new IOException(error);
        }

        String retXML = transfer.getResponseBody();
        try
        {
            log.debug("createGroup returned: " + retXML);
            GroupReader groupReader = new GroupReader();
            return groupReader.read(retXML);
        }
        catch (Exception bug)
        {
            log.error("Unexpected exception", bug);
            throw new RuntimeException(bug);
        }
    }

    /**
     * Get the group object.
     *
     * @param groupName Identifies the group to get.
     * @return The group.
     * @throws GroupNotFoundException If the group was not found.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException If any other error occurs.
     */
    public Group getGroup(String groupName)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL getGroupURL = new URL(groupsURL.toExternalForm() + "/" + groupName);
        log.debug("getGroup request to " + getGroupURL.toString());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpDownload transfer = new HttpDownload(getGroupURL, out);
        transfer.run();

        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            log.debug("getGroup throwable (" + transfer.getResponseCode() + ")", error);
            // transfer returns a -1 code for anonymous access.
            if ((transfer.getResponseCode() == -1) ||
                (transfer.getResponseCode() == 401) ||
                (transfer.getResponseCode() == 403))
            {
                throw new AccessControlException(error.getMessage());
            }
            if (transfer.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            if (transfer.getResponseCode() == 404)
            {
                throw new GroupNotFoundException(error.getMessage());
            }
            throw new IOException(error);
        }

        try
        {
            String groupXML = new String(out.toByteArray(), "UTF-8");
            log.debug("getGroup returned: " + groupXML);
            GroupReader groupReader = new GroupReader();
            return groupReader.read(groupXML);
        }
        catch (Exception bug)
        {
            log.error("Unexpected exception", bug);
            throw new RuntimeException(bug);
        }
    }

    /**
     * Get the all group names.
     *
     * @return The list of names.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException If any other error occurs
     */
    public List<String> getGroupNames()
        throws AccessControlException, IOException
    {
        URL getGroupNamesURL = lookupServiceURL(Standards.GMS_GROUPS_01);

        log.debug("getGroupNames request to " + getGroupNamesURL.toString());

        final List<String> groupNames = new ArrayList<>();
        final HttpDownload httpDownload =
                new HttpDownload(getGroupNamesURL, new InputStreamWrapper()
        {
            @Override
            public void read(final InputStream inputStream) throws IOException
            {
                try
                {
                    InputStreamReader inReader = new InputStreamReader(inputStream);
                    BufferedReader reader = new BufferedReader(inReader);
                    String line;
                    while ((line = reader.readLine()) != null) {
                        groupNames.add(line);
                    }
                }
                catch (Exception bug)
                {
                    log.error("Unexpected exception", bug);
                    throw new RuntimeException(bug);
                }
            }
        });

        // Disable retries.
        httpDownload.setRetry(0, 0, HttpTransfer.RetryReason.NONE);
        httpDownload.run();

        final Throwable error = httpDownload.getThrowable();

        if (error != null)
        {
            final String errMessage = error.getMessage();
            final int responseCode = httpDownload.getResponseCode();

            log.debug("getGroupNames response " + responseCode + ": " +
                      errMessage);

            if ((responseCode == 401) || (responseCode == 403) ||
                    (responseCode == -1))
            {
                throw new AccessControlException(errMessage);
            }
            if (responseCode == 400)
            {
                throw new IllegalArgumentException(errMessage);
            }
            throw new IOException("HttpResponse (" + responseCode + ") - " + errMessage);
        }

        log.debug("Content-Length: " + httpDownload.getContentLength());
        log.debug("Content-Type: " + httpDownload.getContentType());

        return groupNames;
    }

    /**
     * Update a group.
     *
     * @param group The update group object.
     * @return The group after update.
     * @throws IllegalArgumentException If cyclical membership is detected.
     * @throws GroupNotFoundException If the group was not found.
     * @throws UserNotFoundException If a member was not found.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException If any other error occurs.
     * @throws URISyntaxException If URI is incorrect.
     * @throws ReaderException If reader can't be instantiated.
     */
    public Group updateGroup(Group group)
        throws IllegalArgumentException, GroupNotFoundException, UserNotFoundException,
               AccessControlException, WriterException, IOException, ReaderException, URISyntaxException
    {
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL updateGroupURL = new URL(groupsURL.toExternalForm() + "/" + group.getID().getName());
        log.debug("updateGroup request to " + updateGroupURL.toString());

        // reset the state of the cache
        clearCache();

        StringBuilder groupXML = new StringBuilder();
        GroupWriter groupWriter = new GroupWriter();
        groupWriter.write(group, groupXML);
        log.debug("updateGroup: " + groupXML);

        HttpPost transfer = new HttpPost(updateGroupURL, new FileContent(groupXML.toString(), "application/xml", Charset.forName("UTF-8")), false);
        transfer.setTransferListener(this);
        transfer.run();


        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            // transfer returns a -1 code for anonymous access.
            if ((transfer.getResponseCode() == -1) ||
                (transfer.getResponseCode() == 401) ||
                (transfer.getResponseCode() == 403))
            {
                throw new AccessControlException(error.getMessage());
            }
            if (transfer.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            if (transfer.getResponseCode() == 404)
            {
                if (error.getMessage() != null && error.getMessage().toLowerCase().contains("user"))
                    throw new UserNotFoundException(error.getMessage());
                else
                    throw new GroupNotFoundException(error.getMessage());
            }
            throw new IOException(error);
        }

        return (new GroupReader()).read(transfer.getResponseBody());
    }

    /**
     * Delete the group.
     *
     * @param groupName Identifies the group to delete.
     * @throws GroupNotFoundException If the group was not found.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException If any other error occurs.
     */
    public void deleteGroup(String groupName)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL deleteGroupURL = new URL(groupsURL.toExternalForm() + "/" + groupName);
        log.debug("deleteGroup request to " + deleteGroupURL.toString());

        // reset the state of the cache
        clearCache();

        HttpDelete delete = new HttpDelete(deleteGroupURL, true);
        delete.run();

        Throwable error = delete.getThrowable();
        if (error != null)
        {
            // transfer returns a -1 code for anonymous access.
            if (error instanceof AccessControlException)
            {
                throw new AccessControlException(error.getMessage());
            }
            if (delete.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            if (error instanceof ResourceNotFoundException)
            {
                throw new GroupNotFoundException(error.getMessage());
            }

            throw new IOException(error);
        }
    }

    /**
     * Add a group as a member of another group.
     *
     * @param targetGroupName The group in which to add the group member.
     * @param groupMemberName The group member to add.
     * @throws IllegalArgumentException If cyclical membership is detected.
     * @throws GroupNotFoundException If the group was not found.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException If any other error occurs.
     */
    public void addGroupMember(String targetGroupName, String groupMemberName)
        throws IllegalArgumentException, GroupNotFoundException,
               AccessControlException, IOException
    {

        String path = "/" + targetGroupName + "/groupMembers/" + groupMemberName;
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL addGroupMemberURL = new URL(groupsURL.toExternalForm() + path);
        log.debug("addGroupMember request to " + addGroupMemberURL.toString());

        // reset the state of the cache
        clearCache();

        final InputStream is = new ByteArrayInputStream(new byte[0]);
        final HttpUpload httpUpload = new HttpUpload(is, addGroupMemberURL);
        httpUpload.run();

        final Throwable error = httpUpload.getThrowable();
        if (error != null)
        {
            final int responseCode = httpUpload.getResponseCode();
            final String errMessage = error.getMessage();

            if ((responseCode == -1) ||
                (responseCode == 401) ||
                (responseCode == 403))
            {
                throw new AccessControlException(errMessage);
            }
            if (responseCode == 400)
            {
                throw new IllegalArgumentException(errMessage);
            }
            if (responseCode == 404)
            {
                throw new GroupNotFoundException(errMessage);
            }
            throw new IOException(errMessage);
        }
    }

    /**
     * Add a user as a member of a group.
     *
     * @param targetGroupName The group in which to add the group member.
     * @param userID The user to add.
     * @throws GroupNotFoundException If the group was not found.
     * @throws UserNotFoundException If the member was not found.
     * @throws java.io.IOException If any other error occurs.
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void addUserMember(String targetGroupName, Principal userID)
        throws GroupNotFoundException, UserNotFoundException, AccessControlException, IOException
    {
        if (targetGroupName == null)
            throw new IllegalArgumentException("targetGroupName required");

        if (userID == null)
            throw new IllegalArgumentException("userID required");

        log.debug("addUserMember: " + targetGroupName + " + " + userID.getName());

        String userIDType = AuthenticationUtil.getPrincipalType(userID);
        String path = "/" + targetGroupName + "/userMembers/" + NetUtil.encode(userID.getName()) + "?idType=" + userIDType;
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL addUserMemberURL = new URL(groupsURL.toExternalForm() + path);

        log.debug("addUserMember request to " + addUserMemberURL.toString());

        // reset the state of the cache
        clearCache();

        final InputStream is = new ByteArrayInputStream(new byte[0]);
        final HttpUpload httpUpload = new HttpUpload(is, addUserMemberURL);
        httpUpload.run();

        final Throwable error = httpUpload.getThrowable();
        if (error != null)
        {
            final int responseCode = httpUpload.getResponseCode();
            final String errMessage = error.getMessage();

            if ((responseCode == -1) ||
                (responseCode == 401) ||
                (responseCode == 403))
            {
                throw new AccessControlException(errMessage);
            }
            if (responseCode == 400)
            {
                throw new IllegalArgumentException(errMessage);
            }
            if (responseCode == 404)
            {
                if (errMessage != null && errMessage.toLowerCase().contains("user"))
                    throw new UserNotFoundException(errMessage);
                else
                    throw new GroupNotFoundException(errMessage);
            }
            throw new IOException(errMessage);
        }
    }

    /**
     * Remove a group as a member of another group.
     *
     * @param targetGroupName The group from which to remove the group member.
     * @param groupMemberName The group member to remove.
     * @throws GroupNotFoundException If the group was not found.
     * @throws java.io.IOException If any other error occurs.
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void removeGroupMember(String targetGroupName,
                                  String groupMemberName)
        throws GroupNotFoundException, AccessControlException, IOException
    {

        String path = "/" + targetGroupName + "/groupMembers/" + groupMemberName;
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL removeGroupMemberURL = new URL(groupsURL.toExternalForm() + path);
        log.debug("removeGroupMember request to " +
                  removeGroupMemberURL.toString());

        // reset the state of the cache
        clearCache();

        HttpDelete delete = new HttpDelete(removeGroupMemberURL, true);
        delete.run();

        Throwable error = delete.getThrowable();
        if (error != null)
        {
            // transfer returns a -1 code for anonymous access.
            if (error instanceof AccessControlException)
            {
                throw ((AccessControlException) error);
            }
            if (delete.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            if (error instanceof ResourceNotFoundException)
            {
                throw new GroupNotFoundException(error.getMessage());
            }

            throw new IOException(error);
        }
    }

    /**
     * Remove a user as a member of a group.
     *
     * @param targetGroupName The group from which to remove the group member.
     * @param userID The user to remove.
     * @throws GroupNotFoundException If the group was not found.
     * @throws UserNotFoundException If the member was not found.
     * @throws java.io.IOException If any other error occurs.
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void removeUserMember(String targetGroupName, Principal userID)
        throws GroupNotFoundException, UserNotFoundException, AccessControlException, IOException
    {
        String userIDType = AuthenticationUtil.getPrincipalType(userID);

        log.debug("removeUserMember: " + targetGroupName + " - " + userID.getName() + " type: " + userIDType);
        String path = "/" + targetGroupName + "/userMembers/" + NetUtil.encode(userID.getName()) + "?idType=" + userIDType;
        URL groupsURL = lookupServiceURL(Standards.GMS_GROUPS_01);
        URL removeUserMemberURL = new URL(groupsURL.toExternalForm() + path);

        log.debug("removeUserMember: " + removeUserMemberURL.toString());

        // reset the state of the cache
        clearCache();

        HttpDelete delete = new HttpDelete(removeUserMemberURL, true);
        delete.run();

        Throwable error = delete.getThrowable();
        if (error != null)
        {
            // transfer returns a -1 code for anonymous access.
            if (error instanceof AccessControlException)
            {
                throw new AccessControlException(error.getMessage());
            }
            if (delete.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            if (error instanceof ResourceNotFoundException)
            {
                String errMessage = error.getMessage();
                if (errMessage != null && errMessage.toLowerCase().contains("user"))
                    throw new UserNotFoundException(errMessage);
                else
                    throw new GroupNotFoundException(errMessage);
            }

            throw new IOException(error);
        }
    }

    private Principal getCurrentUserID()
    {
        Subject cur = AuthenticationUtil.getCurrentSubject();
        if (cur == null)
            return null; // throw new IllegalArgumentException("no subject");
        Set<HttpPrincipal> ps = cur.getPrincipals(HttpPrincipal.class); // hack
        if (ps.isEmpty())
            return null; // throw new IllegalArgumentException("no principals");
        Principal p = ps.iterator().next();
        log.debug("getCurrentID: " + p.getClass());
        return p;
    }

    /**
     * Get memberships for the current user (subject).
     *
     * @param role
     * @return A list of groups for which the current user has the role.
     * @throws AccessControlException If user is not authenticated.
     * @throws ca.nrc.cadc.ac.UserNotFoundException
     * @throws java.io.IOException If any other error occurs.
     */
    public List<Group> getMemberships(Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return getMemberships(null, role);
    }

    private List<Group> getMemberships(Principal ignore, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return this.getMemberships(null, ignore, role);
    }


    private List<Group> getMemberships(List<String> groupNames, Principal ignore, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        if (role == null)
        {
            throw new IllegalArgumentException("role are required.");
        }

        Principal userID = getCurrentUserID();
        if (groupNames == null || groupNames.isEmpty() && userID != null)
        {
            List<Group> cachedGroups = getCachedGroups(userID, role, true);
            if (cachedGroups != null)
            {
                return cachedGroups;
            }
        }

        String roleString = role.getValue();
        URL searchURL = lookupServiceURL(Standards.GMS_SEARCH_01);
        StringBuilder sb = new StringBuilder();
        sb.append(searchURL.toExternalForm());
        sb.append("?ROLE=");
        sb.append(NetUtil.encode(roleString));
        if (groupNames != null) {
            for (String groupName : groupNames) {
                sb.append("&group=");
                sb.append(NetUtil.encode(groupName));
            }
        }
        URL getMembershipsURL = new URL(sb.toString());

        log.debug("getMemberships request to " + getMembershipsURL.toString());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpDownload transfer = new HttpDownload(getMembershipsURL, out);
        transfer.run();

        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            log.debug("getMemberships throwable", error);
            // transfer returns a -1 code for anonymous access.
            if ((transfer.getResponseCode() == -1) ||
                (transfer.getResponseCode() == 401) ||
                (transfer.getResponseCode() == 403))
            {
                throw new AccessControlException(error.getMessage());
            }
            if (transfer.getResponseCode() == 404)
            {
                throw new UserNotFoundException(error.getMessage());
            }
            if (transfer.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            throw new IOException(error);
        }

        try
        {
            String groupsXML = new String(out.toByteArray(), "UTF-8");
            log.debug("getMemberships returned: " + groupsXML);
            GroupListReader groupListReader = new GroupListReader();
            List<Group> groups = groupListReader.read(groupsXML);
            setCachedGroups(userID, groups, role);
            return groups;
        }
        catch (Exception bug)
        {
            log.error("Unexpected exception", bug);
            throw new RuntimeException(bug);
        }
    }

    /**
     * Return the group, specified by parameter groupName, if the user,
     * identified by userID, is a member of that group.  Return null
     * otherwise.
     *
     * This call is identical to getMemberShip(userID, groupName, Role.MEMBER)
     *
     * @param groupName Identifies the group.
     * @return The group or null of the user is not a member.
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public Group getMembership(String groupName)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return getMembership(groupName, Role.MEMBER);
    }

    /**
     * Return the group, specified by paramter groupName, if the user,
     * identified by userID, is a member (of type role) of that group.
     * Return null otherwise.
     *
     * @param groupName Identifies the group.
     * @param role The membership role to search.
     * @return The group or null of the user is not a member.
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public Group getMembership(String groupName, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        if (groupName == null || role == null)
        {
            throw new IllegalArgumentException("groupName and role are required.");
        }

        Principal userID = getCurrentUserID();
        if (userID != null)
        {
            Group cachedGroup = getCachedGroup(userID, groupName, role);
            if (cachedGroup != null)
            {
                return cachedGroup;
            }
        }

        String roleString = role.getValue();

        String searchGroupPath = "?ROLE=" + NetUtil.encode(roleString) +
                                 "&group=" + NetUtil.encode(groupName);

        URL searchURL = lookupServiceURL(Standards.GMS_SEARCH_01);
        URL getMembershipURL = new URL(searchURL.toExternalForm() + searchGroupPath);

        log.debug("getMembership request to " + getMembershipURL.toString());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpDownload transfer = new HttpDownload(getMembershipURL, out);
        transfer.run();

        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            log.debug("getMembership throwable", error);
            // transfer returns a -1 code for anonymous access.
            if ((transfer.getResponseCode() == -1) ||
                (transfer.getResponseCode() == 401) ||
                (transfer.getResponseCode() == 403))
            {
                throw new AccessControlException(error.getMessage());
            }
            if (transfer.getResponseCode() == 404)
            {
                throw new UserNotFoundException(error.getMessage());
            }
            if (transfer.getResponseCode() == 400)
            {
                throw new IllegalArgumentException(error.getMessage());
            }
            throw new IOException(error);
        }

        try
        {
            String groupsXML = new String(out.toByteArray(), "UTF-8");
            log.debug("getMembership returned: " + groupsXML);
            GroupListReader groupListReader = new GroupListReader();
            List<Group> groups = groupListReader.read(groupsXML);
            if (groups.isEmpty())
            {
                return null;
            }
            if (groups.size() == 1)
            {
                Group ret = groups.get(0);
                addCachedGroup(userID, ret, role);
                return ret;
            }
            throw new IllegalStateException(
                    "Duplicate membership for " + userID + " in group " + groupName);
        }
        catch (Exception bug)
        {
            log.error("Unexpected exception", bug);
            throw new RuntimeException(bug);
        }
    }

    /**
     * Check group membership of the current Subject.
     *
     * @param groupName
     * @return true if the current Subject is a member of the group, false otherwise
     * @throws UserNotFoundException If user does not exist in the system.
     * @throws AccessControlException If user is not authenticated.
     * @throws IOException If an unknown error occured.
     */
    public boolean isMember(String groupName)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return isMember(groupName, Role.MEMBER);
    }

    /**
     *
     * @param groupName
     * @param role
     * @return true if the current Subject is a member of the group with the specified role, false otherwise
     * @throws UserNotFoundException If user does not exist in the system.
     * @throws AccessControlException If user is not authenticated.
     * @throws IOException If an unknown error occured.
     */
    public boolean isMember(String groupName, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return isMember(getCurrentUserID(), groupName, role);
    }

    private boolean isMember(Principal userID, String groupName, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        Group group = getMembership(groupName, role);
        return group != null;
    }

    protected void clearCache()
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        if (subject != null)
        {
            subject.getPrivateCredentials().remove(new GroupMemberships());
        }
    }

    protected GroupMemberships getGroupCache(Principal userID)
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);

        // only consult cache if the userID is of the calling subject
        if (userIsSubject(userID, subject))
        {
            Set<GroupMemberships> gset = subject.getPrivateCredentials(GroupMemberships.class);
            if (gset == null || gset.isEmpty())
            {
                GroupMemberships mems = new GroupMemberships(serviceID.toString(), userID);
                subject.getPrivateCredentials().add(mems);
                return mems;
            }
            GroupMemberships mems = gset.iterator().next();

            // check to ensure they have the same service URI
            if (!serviceID.toString().equals(mems.getServiceURI()))
            {
                log.debug("Not using cache because of differing service URIs: " +
                    "[" + serviceID.toString() + "][" + mems.getServiceURI() + "]");
                return null;
            }

            return mems;
        }
        return null; // no cache
    }

    protected Group getCachedGroup(Principal userID, String groupID, Role role)
    {
        List<Group> groups = getCachedGroups(userID, role, false);
        if (groups == null)
            return null; // no cache
        for (Group g : groups)
        {
            if (g.getID().getName().equals(groupID))
                return g;
        }
        return null;
    }
    protected List<Group> getCachedGroups(Principal userID, Role role, boolean complete)
    {
        GroupMemberships mems = getGroupCache(userID);
        if (mems == null)
            return null; // no cache

        Boolean cacheState = mems.isComplete(role);
        if (!complete || Boolean.TRUE.equals(cacheState))
            return mems.getMemberships(role);

        // caller wanted complete and we don't have that
        return null;
    }

    protected void addCachedGroup(Principal userID, Group group, Role role)
    {
        GroupMemberships mems = getGroupCache(userID);
        if (mems == null)
            return; // no cache

        mems.add(group, role);
    }

    protected void setCachedGroups(Principal userID, List<Group> groups, Role role)
    {
        GroupMemberships mems = getGroupCache(userID);
        if (mems == null)
            return; // no cache

        mems.add(groups, role);
    }

    protected boolean userIsSubject(Principal userID, Subject subject)
    {
        if (userID == null || subject == null)
        {
            return false;
        }

        for (Principal subjectPrincipal : subject.getPrincipals())
        {
            if (AuthenticationUtil.equals(subjectPrincipal, userID))
            {
                return true;
            }
        }
        return false;
    }

    protected RegistryClient getRegistryClient()
    {
        return new RegistryClient();
    }

    /**
     * Lookup the Service URL for the given standard.  The current AuthMethod
     * will be taken into account.
     *
     * @param standard  The URI standard to look up.
     * @return          URL for the service.
     * @throws AccessControlException       If the URL cannot be found for the
     *                                      provided AuthMethod.
     */
    private URL lookupServiceURL(final URI standard)
            throws AccessControlException
    {
        Subject subject = AuthenticationUtil.getCurrentSubject();
        AuthMethod am = AuthenticationUtil.getAuthMethodFromCredentials(subject);
        if (am == null || am.equals(AuthMethod.ANON)) {
            throw new AccessControlException("Anonymous access not supported.");
        }
        
        URL serviceURL = getRegistryClient().getServiceURL(this.serviceID, standard, am);
        
        
        if (serviceURL == null)
        {
            throw new RuntimeException(
                    String.format("Unable to get Service URL for '%s', '%s', '%s'",
                                  serviceID.toString(), standard, am));
        }
        
        return serviceURL;
    }
   
}
