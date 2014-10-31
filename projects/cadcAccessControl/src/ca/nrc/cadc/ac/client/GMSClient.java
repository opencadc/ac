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
package ca.nrc.cadc.ac.client;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupReader;
import ca.nrc.cadc.ac.GroupWriter;
import ca.nrc.cadc.ac.GroupsReader;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.*;

import com.csvreader.CsvReader;


/**
 * Client class for performing group searching and group actions
 * with the access control web service.
 */
public class GMSClient
{
    private static final Logger log = Logger.getLogger(GMSClient.class);
    
    // socket factory to use when connecting
    private SSLSocketFactory sslSocketFactory;
    private SSLSocketFactory mySocketFactory;
    
    private String baseURL;

    /**
     * Constructor.
     * 
     * @param baseURL The URL of the supporting access control web service
     * obtained from the registry.
     */
    public GMSClient(String baseURL)
        throws IllegalArgumentException
    {
        if (baseURL == null)
        {
            throw new IllegalArgumentException("baseURL is required");
        }
        try
        {
            new URL(baseURL);
        }
        catch (MalformedURLException e)
        {
            throw new IllegalArgumentException("URL is malformed: " + 
                                               e.getMessage());
        }

        if (baseURL.endsWith("/"))
        {
            this.baseURL = baseURL.substring(0, baseURL.length() - 1);
        }
        else
        {
            this.baseURL = baseURL;
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
     * @throws UserNotFoundException
     * @throws IOException
     */
    public Group createGroup(Group group)
        throws GroupAlreadyExistsException, AccessControlException, 
               UserNotFoundException, IOException
    {
        URL createGroupURL = new URL(this.baseURL + "/groups");
        log.debug("createGroupURL request to " + createGroupURL.toString());
        
        // reset the state of the cache
        clearCache();

        StringBuilder groupXML = new StringBuilder();
        GroupWriter.write(group, groupXML);
        log.debug("createGroup: " + groupXML);

        byte[] bytes = groupXML.toString().getBytes("UTF-8");
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);

        HttpUpload transfer = new HttpUpload(in, createGroupURL);
        transfer.setSSLSocketFactory(getSSLSocketFactory());

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
            return GroupReader.read(retXML);
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
     * @throws java.io.IOException
     */
    public Group getGroup(String groupName)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        URL getGroupURL = new URL(this.baseURL + "/groups/" + groupName);
        log.debug("getGroup request to " + getGroupURL.toString());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpDownload transfer = new HttpDownload(getGroupURL, out);

        transfer.setSSLSocketFactory(getSSLSocketFactory());
        transfer.run();

        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            log.debug("getGroup throwable", error);
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
            return GroupReader.read(groupXML);
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
     * @throws java.io.IOException
     */
    public List<String> getGroupNames()
        throws AccessControlException, IOException
    {
        final URL getGroupNamesURL = new URL(this.baseURL + "/groups");
        log.debug("getGroupNames request to " + getGroupNamesURL.toString());

        final List<String> groupNames = new ArrayList<String>();
        final HttpDownload httpDownload =
                new HttpDownload(getGroupNamesURL, new InputStreamWrapper()
        {
            @Override
            public void read(final InputStream inputStream) throws IOException
            {
                try
                {
                    final CsvReader reader =
                            new CsvReader(inputStream, ',',
                                          Charset.forName("UTF-8"));
                    if (reader.readRecord())
                    {
                        for (int i = 0; i < reader.getColumnCount(); i++)
                        {
                            groupNames.add(reader.get(i));
                        }
                    }
                }
                catch (Exception bug)
                {
                    log.error("Unexpected exception", bug);
                    throw new RuntimeException(bug);
                }
            }
        });

        httpDownload.setSSLSocketFactory(getSSLSocketFactory());
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

        log.error("Content-Length: " + httpDownload.getContentLength());
        log.error("Content-Type: " + httpDownload.getContentType());

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
     * @throws java.io.IOException
     */
    public void updateGroup(Group group)
        throws IllegalArgumentException, GroupNotFoundException, UserNotFoundException,
               AccessControlException, IOException
    {
        URL updateGroupURL = new URL(this.baseURL + "/groups/" + group.getID());
        log.debug("updateGroup request to " + updateGroupURL.toString());
        
        // reset the state of the cache
        clearCache();

        StringBuilder groupXML = new StringBuilder();
        GroupWriter.write(group, groupXML);
        log.debug("updateGroup: " + groupXML);

        HttpPost transfer = new HttpPost(updateGroupURL, groupXML.toString(), 
                                         "application/xml", false);

        transfer.setSSLSocketFactory(getSSLSocketFactory());
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
    }

    /**
     * Delete the group.
     *
     * @param groupName Identifies the group to delete.
     * @throws GroupNotFoundException If the group was not found.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException
     */
    public void deleteGroup(String groupName)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        URL deleteGroupURL = new URL(this.baseURL + "/groups/" + groupName);
        log.debug("deleteGroup request to " + deleteGroupURL.toString());
        
        // reset the state of the cache
        clearCache();

        HttpURLConnection conn = 
                (HttpURLConnection) deleteGroupURL.openConnection();
        conn.setRequestMethod("DELETE");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn)
                    .setSSLSocketFactory(sf);
        }

        final int responseCode;

        try
        {
            responseCode = conn.getResponseCode();
        }
        catch(Exception e)
        {
            throw new AccessControlException(e.getMessage());
        }
        
        if (responseCode != 200)
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("deleteGroup response " + responseCode + ": " + 
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
            if (responseCode == 404)
            {
                throw new GroupNotFoundException(errMessage);
            }
            throw new IOException("HttpResponse (" + responseCode + ") - " + errMessage);
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
     * @throws java.io.IOException
     */
    public void addGroupMember(String targetGroupName, String groupMemberName)
        throws IllegalArgumentException, GroupNotFoundException,
               AccessControlException, IOException
    {
        URL addGroupMemberURL = new URL(this.baseURL + "/groups/" + 
                                        targetGroupName + "/groupMembers/" + 
                                        groupMemberName);
        log.debug("addGroupMember request to " + addGroupMemberURL.toString());
        
        // reset the state of the cache
        clearCache();

        final InputStream is = new ByteArrayInputStream(new byte[0]);
        final HttpUpload httpUpload = new HttpUpload(is, addGroupMemberURL);

        httpUpload.setSSLSocketFactory(getSSLSocketFactory());
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
     * @throws java.io.IOException
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void addUserMember(String targetGroupName, Principal userID)
        throws GroupNotFoundException, UserNotFoundException, AccessControlException, IOException
    {
        String userIDType = AuthenticationUtil.getPrincipalType(userID);
        String encodedUserID = URLEncoder.encode(userID.getName(), "UTF-8");
        URL addUserMemberURL = new URL(this.baseURL + "/groups/" + 
                                       targetGroupName + "/userMembers/" + 
                                       encodedUserID + "?idType=" + userIDType);

        log.debug("addUserMember request to " + addUserMemberURL.toString());
        
        // reset the state of the cache
        clearCache();

        final InputStream is = new ByteArrayInputStream(new byte[0]);
        final HttpUpload httpUpload = new HttpUpload(is, addUserMemberURL);

        httpUpload.setSSLSocketFactory(getSSLSocketFactory());
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
     * @throws java.io.IOException
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void removeGroupMember(String targetGroupName, 
                                  String groupMemberName)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        URL removeGroupMemberURL = new URL(this.baseURL + "/groups/" + 
                                           targetGroupName + "/groupMembers/" + 
                                           groupMemberName);
        log.debug("removeGroupMember request to " + 
                  removeGroupMemberURL.toString());
        
        // reset the state of the cache
        clearCache();

        HttpURLConnection conn = 
                (HttpURLConnection) removeGroupMemberURL.openConnection();
        conn.setRequestMethod("DELETE");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn)
                    .setSSLSocketFactory(getSSLSocketFactory());
        }
        
        // Try to handle anonymous access and throw AccessControlException 
        int responseCode = -1;
        try
        {
            responseCode = conn.getResponseCode();
        }
        catch (Exception ignore) {}
        
        if (responseCode != 200)
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("removeGroupMember response " + responseCode + ": " + 
                      errMessage);

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
     * Remove a user as a member of a group.
     *
     * @param targetGroupName The group from which to remove the group member.
     * @param userID The user to remove.
     * @throws GroupNotFoundException If the group was not found.
     * @throws UserNotFoundException If the member was not found.
     * @throws java.io.IOException
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void removeUserMember(String targetGroupName, Principal userID)
        throws GroupNotFoundException, UserNotFoundException, AccessControlException, IOException
    {
        String userIDType = AuthenticationUtil.getPrincipalType(userID);
        String encodedUserID = URLEncoder.encode(userID.toString(), "UTF-8");
        URL removeUserMemberURL = new URL(this.baseURL + "/groups/" + 
                                          targetGroupName + "/userMembers/" + 
                                          encodedUserID + "?idType=" + 
                                          userIDType);

        log.debug("removeUserMember request to " +
                  removeUserMemberURL.toString());
        
        // reset the state of the cache
        clearCache();

        HttpURLConnection conn = 
                (HttpURLConnection) removeUserMemberURL.openConnection();
        conn.setRequestMethod("DELETE");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn)
                    .setSSLSocketFactory(getSSLSocketFactory());
        }
        
        // Try to handle anonymous access and throw AccessControlException 
        int responseCode = -1;
        try
        {
            responseCode = conn.getResponseCode();
        }
        catch (Exception ignore) {}

        if (responseCode != 200)
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("removeUserMember response " + responseCode + ": " + 
                      errMessage);

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
     * Get all the memberships of the user of a certain role.
     * 
     * @param userID Identifies the user.
     * @param role The role to look up.
     * @return A list of groups for which the user has the role.
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public List<Group> getMemberships(Principal userID, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        if (userID == null || role == null)
        {
            throw new IllegalArgumentException("userID and role are required.");
        }
        
        List<Group> cachedGroups = getCachedGroups(userID, role);
        if (cachedGroups != null)
        {
            return cachedGroups;
        }
        
        String idType = AuthenticationUtil.getPrincipalType(userID);
        String id = userID.getName();
        String roleString = role.getValue();
        
        StringBuilder searchGroupURL = new StringBuilder(this.baseURL);
        searchGroupURL.append("/search?");
        
        searchGroupURL.append("ID=").append(URLEncoder.encode(id, "UTF-8"));
        searchGroupURL.append("&IDTYPE=")
                .append(URLEncoder.encode(idType, "UTF-8"));
        searchGroupURL.append("&ROLE=")
                .append(URLEncoder.encode(roleString, "UTF-8"));
        
        log.debug("getMemberships request to " + searchGroupURL.toString());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        URL url = new URL(searchGroupURL.toString());
        HttpDownload transfer = new HttpDownload(url, out);

        transfer.setSSLSocketFactory(getSSLSocketFactory());
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
            List<Group> groups = GroupsReader.read(groupsXML);
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
     * Return the group, specified by paramter groupName, if the user,
     * identified by userID, is a member of that group.  Return null
     * otherwise.
     * 
     * This call is identical to getMemberShip(userID, groupName, Role.MEMBER)
     *  
     * @param userID Identifies the user.
     * @param groupName Identifies the group.
     * @return The group or null of the user is not a member.
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public Group getMembership(Principal userID, String groupName)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return getMembership(userID, groupName, Role.MEMBER);
    }
    
    /**
     * Return the group, specified by paramter groupName, if the user,
     * identified by userID, is a member (of type role) of that group.
     * Return null otherwise.
     * 
     * @param userID Identifies the user.
     * @param groupName Identifies the group.
     * @param role The membership role to search.
     * @return The group or null of the user is not a member.
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public Group getMembership(Principal userID, String groupName, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        if (userID == null || groupName == null || role == null)
        {
            throw new IllegalArgumentException("userID and role are required.");
        }
        
        List<Group> cachedGroups = getCachedGroups(userID, role);
        if (cachedGroups != null)
        {
            int index = cachedGroups.indexOf(new Group(groupName));
            if (index != -1)
            {
                return cachedGroups.get(index);
            }
            else
            {
                return null;
            }
        }
        
        String idType = AuthenticationUtil.getPrincipalType(userID);
        String id = userID.getName();
        String roleString = role.getValue();
        
        StringBuilder searchGroupURL = new StringBuilder(this.baseURL);
        searchGroupURL.append("/search?");

        searchGroupURL.append("ID=").append(URLEncoder.encode(id, "UTF-8"));
        searchGroupURL.append("&IDTYPE=")
                .append(URLEncoder.encode(idType, "UTF-8"));
        searchGroupURL.append("&ROLE=")
                .append(URLEncoder.encode(roleString, "UTF-8"));
        searchGroupURL.append("&GROUPID=")
                .append(URLEncoder.encode(groupName, "UTF-8"));
        
        log.debug("getMembership request to " + searchGroupURL.toString());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        URL url = new URL(searchGroupURL.toString());
        HttpDownload transfer = new HttpDownload(url, out);

        transfer.setSSLSocketFactory(getSSLSocketFactory());
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
            List<Group> groups = GroupsReader.read(groupsXML);
            if (groups.size() == 0)
            {
                return null;
            }
            if (groups.size() == 1)
            {
                // don't cache these results as it is not a complete
                // list of memberships--it only applies to one group.
                return groups.get(0);
            }
            throw new IllegalStateException(
                    "Duplicate membership for " + id + " in group " + groupName);
        }
        catch (Exception bug)
        {
            log.error("Unexpected exception", bug);
            throw new RuntimeException(bug);
        }
    }
    
    /**
     * Check if userID is a member of groupName.
     * 
     * This is equivalent to isMember(userID, groupName, Role.MEMBER)
     * 
     * @param userID Identifies the user.
     * @param groupName Identifies the group.
     * @return True if the user is a member of the group
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public boolean isMember(Principal userID, String groupName)
        throws UserNotFoundException, AccessControlException, IOException
    {
        return isMember(userID, groupName, Role.MEMBER);
    }
    
    /**
     * Check if userID is a member (of type role) of groupName.
     * 
     * @param userID Identifies the user.
     * @param groupName Identifies the group.
     * @param role The type of membership.
     * @return True if the user is a member of the group
     * @throws UserNotFoundException If the user does not exist.
     * @throws AccessControlException If not allowed to peform the search.
     * @throws IllegalArgumentException If a parameter is null.
     * @throws IOException If an unknown error occured.
     */
    public boolean isMember(Principal userID, String groupName, Role role)
        throws UserNotFoundException, AccessControlException, IOException
    {
        Group group = getMembership(userID, groupName, role);
        return group != null;
    }

    /**
     * @param sslSocketFactory the sslSocketFactory to set
     */
    public void setSSLSocketFactory(SSLSocketFactory sslSocketFactory)
    {
        if (mySocketFactory != null)
            throw new IllegalStateException("Illegal use of GMSClient: "
                    + "cannot set SSLSocketFactory after using one created from Subject");
        this.sslSocketFactory = sslSocketFactory;
        clearCache();
    }
    
    private int subjectHashCode = 0;
    private SSLSocketFactory getSSLSocketFactory()
    {
        AccessControlContext ac = AccessController.getContext();
        Subject s = Subject.getSubject(ac);
        
        // no real Subject: can only use the one from setSSLSocketFactory
        if (s == null || s.getPrincipals().isEmpty())
        {
            return sslSocketFactory;
        }
        
        // lazy init
        if (this.mySocketFactory == null)
        {
            log.debug("getSSLSocketFactory: " + s);
            this.mySocketFactory = SSLUtil.getSocketFactory(s);
            this.subjectHashCode = s.hashCode();
        }
        else
        {
            int c = s.hashCode();
            if (c != subjectHashCode)
                throw new IllegalStateException("Illegal use of " 
                        + this.getClass().getSimpleName()
                        + ": subject change not supported for internal SSLSocketFactory");
        }
        return this.mySocketFactory;
    }
    
    protected void clearCache()
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        
        if (subject != null)
        {
            log.debug("Clearing cache");
            subject.getPrivateCredentials().clear();
        }
    }

    protected List<Group> getCachedGroups(Principal userID, Role role)
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        
        // only consult cache if the userID is of the calling subject
        if (userIsSubject(userID, subject))
        {
            Set groupCredentialSet = subject.getPrivateCredentials(GroupMemberships.class);
            if ((groupCredentialSet != null) && 
                (groupCredentialSet.size() == 1))
            {
                Iterator i = groupCredentialSet.iterator();
                GroupMemberships groupMemberships = ((GroupMemberships) i.next());
                return groupMemberships.memberships.get(role);
            }
        }
        return null;
    }

    protected void setCachedGroups(Principal userID, List<Group> groups, Role role)
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        
        // only save to cache if the userID is of the calling subject
        if (userIsSubject(userID, subject))
        {
            log.debug("Caching groups for " + userID + ", role " + role);
            
            final GroupMemberships groupCredentials;
            Set groupCredentialSet = subject.getPrivateCredentials(GroupMemberships.class);
            if ((groupCredentialSet != null) && 
                (groupCredentialSet.size() == 1))
            {
                Iterator i = groupCredentialSet.iterator();
                groupCredentials = ((GroupMemberships) i.next());
            }
            else
            {
                groupCredentials = new GroupMemberships();
                subject.getPrivateCredentials().add(groupCredentials);
            }
            
            groupCredentials.memberships.put(role,  groups);
        }
    }
    
    protected boolean userIsSubject(Principal userID, Subject subject)
    {
        if (userID == null || subject == null)
        {
            return false;
        }
        
        for (Principal subjectPrincipal : subject.getPrincipals())
        {
            if (subjectPrincipal.equals(userID))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Class used to hold list of groups in which
     * a user is a member.
     */
    protected class GroupMemberships
    {
        Map<Role, List<Group>> memberships = new HashMap<Role, List<Group>>();

        protected GroupMemberships()
        {
        }

    }

}
