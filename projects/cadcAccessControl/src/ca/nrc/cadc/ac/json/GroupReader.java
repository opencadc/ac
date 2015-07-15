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
package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.AC;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.date.DateUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URISyntaxException;
import java.security.Principal;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Scanner;

public class GroupReader
{
    /**
     * Construct a Group from a InputStream.
     *
     * @param in InputStream.
     * @return Group Group.
     * @throws ReaderException
     * @throws IOException
     * @throws URISyntaxException
     */
    public static Group read(InputStream in)
        throws ReaderException, IOException
    {
        if (in == null)
        {
            throw new IOException("stream closed");
        }
        InputStreamReader reader;

        Scanner s = new Scanner(in).useDelimiter("\\A");
        String json = s.hasNext() ? s.next() : "";

        return read(json);
    }

    /**
     * Construct a Group from a Reader.
     *
     * @param reader Reader.
     * @return Group Group.
     * @throws ReaderException
     * @throws IOException
     * @throws URISyntaxException
     */
    public static Group read(Reader reader)
        throws ReaderException, IOException
    {
        if (reader == null)
        {
            throw new IllegalArgumentException("reader must not be null");
        }

        Scanner s = new Scanner(reader).useDelimiter("\\A");
        String json = s.hasNext() ? s.next() : "";

        return read(json);
    }

    /**
     * Construct a Group from an JSON String source.
     *
     * @param json String of JSON.
     * @return Group Group.
     * @throws ReaderException
     * @throws IOException
     * @throws URISyntaxException
     */
    public static Group read(String json)
        throws ReaderException, IOException
    {
        if (json == null)
        {
            throw new IllegalArgumentException("JSON must not be null");
        }

        // Create a JSONObject from the JSON
        try
        {
            return parseGroup(new JSONObject(json).getJSONObject("group"));
        }
        catch (JSONException e)
        {
            String error = "Unable to parse JSON to Group because " +
                           e.getMessage();
            throw new ReaderException(error, e);
        }
    }

    protected static Group parseGroup(JSONObject groupObject)
        throws ReaderException, JSONException
    {
        String uri = groupObject.getString("uri");

        // Group groupID
        int index = uri.indexOf(AC.GROUP_URI);
        if (index == -1)
        {
            String error = "group uri attribute malformed: " + uri;
            throw new ReaderException(error);
        }
        String groupID = uri.substring(AC.GROUP_URI.length());

        // Group owner
        User<? extends Principal> user = null;
        if (groupObject.has("owner"))
        {
            JSONObject ownerObject = groupObject.getJSONObject("owner");
            JSONObject userObject = ownerObject.getJSONObject("user");
            user = UserReader.parseUser(userObject);
        }

        Group group = new Group(groupID, user);

        // description
        if (groupObject.has("description"))
        {
            group.description = groupObject.getString("description");
        }

        // lastModified
        if (groupObject.has("lastModified"))
        {
            try
            {
                DateFormat df = DateUtil.getDateFormat(DateUtil.IVOA_DATE_FORMAT, DateUtil.UTC);
                group.lastModified = df.parse(groupObject.getString("lastModified"));
            }
            catch (ParseException e)
            {
                String error = "Unable to parse group lastModified because " + e.getMessage();

                throw new ReaderException(error);
            }
        }

        // properties
        if (groupObject.has("description"))
        {
            JSONArray propertiesArray = groupObject.getJSONArray("properties");
            for (int i = 0; i < propertiesArray.length(); i++)
            {
                JSONObject propertiesObject = propertiesArray.getJSONObject(i);
                JSONObject propertyObject = propertiesObject.getJSONObject("property");
                group.getProperties().add(GroupPropertyReader.read(propertyObject));
            }
        }

        // groupMembers
        if (groupObject.has("groupMembers"))
        {
            JSONArray groupMembersArray = groupObject.getJSONArray("groupMembers");
            for (int i = 0; i < groupMembersArray.length(); i++)
            {
                JSONObject groupMembersObject = groupMembersArray.getJSONObject(i);
                JSONObject groupMemberObject = groupMembersObject.getJSONObject("group");
                group.getGroupMembers().add(parseGroup(groupMemberObject));
            }
        }

        // userMembers
        if (groupObject.has("userMembers"))
        {
            JSONArray userMembersArray = groupObject.getJSONArray("userMembers");
            for (int i = 0; i < userMembersArray.length(); i++)
            {
                JSONObject userMemberObject = userMembersArray.getJSONObject(i);
                JSONObject userObject = userMemberObject.getJSONObject("user");
                group.getUserMembers().add(UserReader.parseUser(userObject));
            }
        }

        // groupAdmins
        if (groupObject.has("groupAdmins"))
        {
            JSONArray groupAdminsArray = groupObject.getJSONArray("groupAdmins");
            for (int i = 0; i < groupAdminsArray.length(); i++)
            {
                JSONObject groupAdminsObject = groupAdminsArray.getJSONObject(i);
                JSONObject groupAdminObject = groupAdminsObject.getJSONObject("group");
                group.getGroupAdmins().add(parseGroup(groupAdminObject));
            }
        }

        // userAdmins
        if (groupObject.has("userAdmins"))
        {
            JSONArray userAdminsArray = groupObject.getJSONArray("userAdmins");
            for (int i = 0; i < userAdminsArray.length(); i++)
            {
                JSONObject userAdminObject = userAdminsArray.getJSONObject(i);
                JSONObject userObject = userAdminObject.getJSONObject("user");
                group.getUserAdmins().add(UserReader.parseUser(userObject));
            }
        }

        return group;
    }
}
