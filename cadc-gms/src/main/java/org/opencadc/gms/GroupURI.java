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

package org.opencadc.gms;

import java.net.URI;
import java.net.URISyntaxException;
import org.apache.log4j.Logger;

/**
 * Identifier for a group.
 */
public class GroupURI implements Comparable<GroupURI> {
    private static final Logger log = Logger.getLogger(GroupURI.class);

    private URI uri;
    private static String GROUP_NAME_ERRORMSG = "Group Name contains illegal characters (only alphanumeric, '/', -', '.', '_', '~' allowed";

    /**
     * Attempts to create a URI using the specified uri.
     *
     * @param uri The URI to use.
     * @throws IllegalArgumentException argument URI is not a valid group URI
     */
    public GroupURI(URI uri) throws IllegalArgumentException {
        if (uri == null) {
            throw new IllegalArgumentException("null URI");
        }

        // Ensure the scheme is correct
        if (uri.getScheme() == null || !"ivo".equals(uri.getScheme())) {
            throw new IllegalArgumentException("scheme must be 'ivo' in resourceID: " + uri);
        }

        if (uri.getAuthority() == null) {
            throw new IllegalArgumentException("authority is required in resourceID: " + uri);
        }

        if (uri.getPath() == null || uri.getPath().length() == 0) {
            throw new IllegalArgumentException("path is required in resourceID: " + uri);
        }

        if (uri.getFragment() != null) {
            throw new IllegalArgumentException("fragment not allowed in uri: " + uri);
        }

        if (uri.getQuery() == null) {
            throw new IllegalArgumentException("query (group name) required in uri: " + uri);
        }

        String name = uri.getQuery();
        if (!isValidGroupName(name)) {
            throw new IllegalArgumentException("invalid group name: " + name + " reason: " + GROUP_NAME_ERRORMSG);

        }

        this.uri = uri;
    }

    /**
     * Constructs a URI from the string and calls the constructor
     * that takes a URI object.
     *
     * @param uri
     * @throws IllegalArgumentException if the URI is not a valid group URI
     * @throws URISyntaxException       if the argument is not a valid URI
     * @deprecated
     */
    @Deprecated
    public GroupURI(String uri) throws IllegalArgumentException, URISyntaxException {
        this(new URI(uri));
    }

    public GroupURI(URI resourceID, String name) {
        if (resourceID == null) {
            throw new IllegalArgumentException("null GMS resourceID");
        }
        if (name == null) {
            throw new IllegalArgumentException("null group name");
        }

        // Ensure the scheme is correct
        if (resourceID.getScheme() == null || !"ivo".equals(resourceID.getScheme())) {
            throw new IllegalArgumentException("scheme must be 'ivo' in resourceID: " + resourceID);
        }

        if (resourceID.getAuthority() == null) {
            throw new IllegalArgumentException("authority is required in resourceID: " + resourceID);
        }

        if (resourceID.getPath() == null || resourceID.getPath().length() == 0) {
            throw new IllegalArgumentException("path is required in resourceID: " + resourceID);
        }

        if (resourceID.getQuery() != null) {
            throw new IllegalArgumentException("query not allowed in resourceID: " + resourceID);
        }

        if (resourceID.getFragment() != null) {
            throw new IllegalArgumentException("fragment not allowed in resourceID: " + resourceID);
        }

        if (!isValidGroupName(name)) {
            throw new IllegalArgumentException("invalid group name: " + name + " reason: " + GROUP_NAME_ERRORMSG);
        }

        this.uri = URI.create(resourceID.toASCIIString() + "?" + name);
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (this == other) {
            return true;
        }
        if (other instanceof GroupURI) {
            GroupURI otherURI = (GroupURI) other;
            return uri.equals(otherURI.getURI());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public int compareTo(GroupURI t) {
        return uri.compareTo(t.uri);
    }

    /**
     * Returns the underlying URI object.
     *
     * @return The URI object for this GroupURI.
     */
    public URI getURI() {
        return uri;
    }

    /**
     * Returns the query string component of the group URI.
     *
     * @return group name
     */
    public String getName() {
        return uri.getQuery();
    }

    public URI getServiceID() {
        String serviceIDString = uri.getScheme()
                + "://"
                + uri.getAuthority()
                + uri.getPath();
        try {
            return new URI(serviceIDString);
        } catch (URISyntaxException e) {
            throw new RuntimeException("BUG: failed to create serviceID from GroupURI: " + uri, e);
        }
    }

    @Override
    public String toString() {
        // TECHNICAL DEBT: reverting to using this method for debugging purposes only breaks all kinds of
        // things because some functional code expects toString() to be equivalent to getURI().toASCIIString()
        //return "GroupURI[" + uri.toString() + "]";
        return uri.toASCIIString();
    }

    /**
     * Validate groupName passed in. Accepted characters include:
     * Alphanumerics, "-", ".", "_", "~"
     *
     * @param groupName
     * @return boolean
     */
    private boolean isValidGroupName(String groupName) {
        boolean isValid = false;

        if (groupName.matches("^[a-zA-Z0-9/_\\-\\.~]+$")) {
            isValid = true;
        }

        return isValid;
    }

}
