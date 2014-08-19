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

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupAlreadyExistsException;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.GroupReader;
import ca.nrc.cadc.ac.GroupWriter;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.HttpUpload;
import ca.nrc.cadc.net.NetUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 * Client class for communicating with the access control web service.
 */
public class GMSClient
{
    private static final Logger log = Logger.getLogger(GMSClient.class);
    
    // socket factory to use when connecting
    public SSLSocketFactory sslSocketFactory;
    
    private String baseURL;

    /**
     *
     * @param baseURL
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
            URL testURL = new URL(baseURL);
            if (!testURL.getProtocol().equals("https"))
            {
                throw new IllegalArgumentException("URL must have HTTPS protocol");
            }
        }
        catch (MalformedURLException e)
        {
            throw new IllegalArgumentException("URL is malformed: " + e.getMessage());
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
     * Create a new group
     *
     * @param group The group to create
     * @return The newly created group will all the information.
     * @throws GroupAlreadyExistsException If a group with the same name already exists.
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
            if ((transfer.getResponseCode() == 401) || (transfer.getResponseCode() == 403))
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
            log.debug("createGroup returned: " + groupXML);
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
            if ((transfer.getResponseCode() == 401) || (transfer.getResponseCode() == 403))
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
     * Update a group.
     *
     * @param group The update group object.
     * @return The group after update.
     * @throws IllegalArgumentException If cyclical membership is detected.
     * @throws GroupNotFoundException If the group was not found.
     * @throws AccessControlException If unauthorized to perform this operation.
     * @throws java.io.IOException
     */
    public Group updateGroup(Group group)
        throws IllegalArgumentException, GroupNotFoundException,
               AccessControlException, IOException
    {
        URL updateGroupURL = new URL(this.baseURL + "/groups/" + group.getID());
        log.debug("updateGroup request to " + updateGroupURL.toString());

        StringBuilder groupXML = new StringBuilder();
        GroupWriter.write(group, groupXML);
        log.debug("updateGroup: " + groupXML);

        HttpPost transfer = new HttpPost(updateGroupURL, groupXML.toString(), "application/xml", true);

        transfer.setSSLSocketFactory(getSSLSocketFactory());
        transfer.run();

        Throwable error = transfer.getThrowable();
        if (error != null)
        {
            log.debug("updateGroup throwable", error);
            if ((transfer.getResponseCode() == 401) || (transfer.getResponseCode() == 403))
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

        String retXML = transfer.getResponseBody();
        try
        {
            log.debug("updateGroup returned: " + groupXML);
            return GroupReader.read(retXML);
        }
        catch (Exception bug)
        {
            log.error("Unexpected exception", bug);
            throw new RuntimeException(bug);
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
        HttpURLConnection conn = (HttpURLConnection) deleteGroupURL.openConnection();
        conn.setRequestMethod("DELETE");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSSLSocketFactory());
        }
        int responseCode = conn.getResponseCode();
        if (responseCode != 200)
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("deleteGroup response " + responseCode + ": " + errMessage);

            if ((responseCode == 401) || (responseCode == 403))
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
        URL addGroupMemberURL = new URL(this.baseURL + "/groups/" + targetGroupName + "/groupMembers/" + groupMemberName);
        log.debug("addGroupMember request to " + addGroupMemberURL.toString());

        HttpURLConnection conn = (HttpURLConnection) addGroupMemberURL.openConnection();
        conn.setRequestMethod("PUT");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSSLSocketFactory());
        }
        int responseCode = conn.getResponseCode();
        if ((responseCode != 200) && (responseCode != 201))
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("addGroupMember response " + responseCode + ": " + errMessage);

            if ((responseCode == 401) || (responseCode == 403))
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
     * @throws java.io.IOException
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void addUserMember(String targetGroupName, Principal userID)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        String userIDType = AuthenticationUtil.getPrincipalType(userID);
        String encodedUserID = URLEncoder.encode(userID.toString(), "UTF-8");
        URL addUserMemberURL = new URL(this.baseURL + "/groups/" + targetGroupName + "/userMembers/" + encodedUserID + "?idType=" + userIDType);

        log.debug("addUserMember request to " + addUserMemberURL.toString());

        HttpURLConnection conn = (HttpURLConnection) addUserMemberURL.openConnection();
        conn.setRequestMethod("PUT");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSSLSocketFactory());
        }
        int responseCode = conn.getResponseCode();
        if ((responseCode != 200) && (responseCode != 201))
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("addUserMember response " + responseCode + ": " + errMessage);

            if ((responseCode == 401) || (responseCode == 403))
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
     * Remove a group as a member of another group.
     *
     * @param targetGroupName The group from which to remove the group member.
     * @param groupMemberName The group member to remove.
     * @throws GroupNotFoundException If the group was not found.
     * @throws java.io.IOException
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void removeGroupMember(String targetGroupName, String groupMemberName)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        URL removeGroupMemberURL = new URL(this.baseURL + "/groups/" + targetGroupName + "/groupMembers/" + groupMemberName);
        log.debug("removeGroupMember request to " + removeGroupMemberURL.toString());

        HttpURLConnection conn = (HttpURLConnection) removeGroupMemberURL.openConnection();
        conn.setRequestMethod("DELETE");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSSLSocketFactory());
        }
        int responseCode = conn.getResponseCode();
        if (responseCode != 200)
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("removeGroupMember response " + responseCode + ": " + errMessage);

            if ((responseCode == 401) || (responseCode == 403))
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
     * @throws java.io.IOException
     * @throws AccessControlException If unauthorized to perform this operation.
     */
    public void removeUserMember(String targetGroupName, Principal userID)
        throws GroupNotFoundException, AccessControlException, IOException
    {
        String userIDType = AuthenticationUtil.getPrincipalType(userID);
        String encodedUserID = URLEncoder.encode(userID.toString(), "UTF-8");
        URL removeUserMemberURL = new URL(this.baseURL + "/groups/" + targetGroupName + "/userMembers/" + encodedUserID + "?idType=" + userIDType);

        log.debug("removeUserMember request to " + removeUserMemberURL.toString());

        HttpURLConnection conn = (HttpURLConnection) removeUserMemberURL.openConnection();
        conn.setRequestMethod("DELETE");

        SSLSocketFactory sf = getSSLSocketFactory();
        if ((sf != null) && ((conn instanceof HttpsURLConnection)))
        {
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSSLSocketFactory());
        }
        int responseCode = conn.getResponseCode();
        if (responseCode != 200)
        {
            String errMessage = NetUtil.getErrorBody(conn);
            log.debug("removeUserMember response " + responseCode + ": " + errMessage);

            if ((responseCode == 401) || (responseCode == 403))
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

    public Collection<Group> searchGroups()
    {
        throw new UnsupportedOperationException();
    }

    /**
     * @param sslSocketFactory the sslSocketFactory to set
     */
    public void setSSLSocketFactory(SSLSocketFactory sslSocketFactory)
    {
        this.sslSocketFactory = sslSocketFactory;
    }
    
    /**
     * @return the sslSocketFactory
     */
    private SSLSocketFactory getSSLSocketFactory()
    {
        if (this.sslSocketFactory == null)
        {
            log.debug("initHTTPS: lazy init");
            AccessControlContext ac = AccessController.getContext();
            Subject s = Subject.getSubject(ac);
            this.sslSocketFactory = SSLUtil.getSocketFactory(s);
        }
        return this.sslSocketFactory;
    }

    protected Collection<Group> getCachedGroups()
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        if (subject != null)
        {
            Set groupCredentialSet = subject.getPrivateCredentials(GroupCredentials.class);
            if ((groupCredentialSet != null) && (groupCredentialSet.size() == 1))
            {
                Iterator i = groupCredentialSet.iterator();
                return ((GroupCredentials) i.next()).groupMemberships;
            }
        }
        return null;
    }

    protected void setCachedGroups(Collection<Group> groups)
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        if (subject != null)
        {
            GroupCredentials groupCredentials = new GroupCredentials();
            groupCredentials.groupMemberships.addAll(groups);
            subject.getPrivateCredentials().add(groupCredentials);
        }
    }

    /**
     * Class used to hold list of groups in which
     * a user is a member.
     */
    protected class GroupCredentials
    {
        Collection<Group> groupMemberships = new ArrayList<Group>();

        protected GroupCredentials()
        {
        }

    }

}
