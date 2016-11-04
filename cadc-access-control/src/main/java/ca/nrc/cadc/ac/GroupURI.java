/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2009.                            (c) 2009.
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

package ca.nrc.cadc.ac;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.log4j.Logger;

/**
 * Identifier for a group.
 *
 */
public class GroupURI
{
    private static Logger log = Logger.getLogger(GroupURI.class);

    public static final String SCHEME = "ivo";
    public static final String PATH = "/gms";

    private URI uri;

    /**
     * Attempts to create a URI using the specified uri. The is expected
     * to be in the format:
     *
     * ivo://<authority>/gms?<groupName>
     *
     * @param uri The URI to use.
     * @throws IllegalArgumentException if the URI scheme is not vos
     * @throws NullPointerException if uri is null
     */
    public GroupURI(URI uri)
    {
        if (uri == null)
        {
            throw new IllegalArgumentException("Null URI");
        }

        String fragment = uri.getFragment();
        if (fragment != null && fragment.length() > 0)
        {
            throw new IllegalArgumentException("Fragment not allowed in group URIs");
        }

        try
        {
            this.uri = new URI(uri.getScheme(), uri.getAuthority(),
                    uri.getPath(), uri.getQuery(), fragment);
        }
        catch (URISyntaxException e)
        {
            throw new IllegalArgumentException("URI malformed: " + uri.toString());
        }

        // Ensure the scheme is correct
        if (uri.getScheme() == null || !uri.getScheme().equalsIgnoreCase(SCHEME))
        {
            throw new IllegalArgumentException("GroupURI scheme must be " + SCHEME);
        }

        if (uri.getAuthority() == null)
        {
            throw new IllegalArgumentException("Group authority is required.");
        }

        if (uri.getPath() == null || !uri.getPath().equalsIgnoreCase(PATH))
        {
            if (PATH.contains(uri.getAuthority()))
            {
                throw new IllegalArgumentException("Missing authority");
            }
            throw new IllegalArgumentException("GroupURI path must be " + PATH);
        }

        if (uri.getQuery() == null)
        {
            throw new IllegalArgumentException("Group name is required.");
        }

    }

    /**
     * Constructs a URI from the string and calls the constructor
     * that takes a URI object.
     */
    public GroupURI(String uri)
        throws URISyntaxException
    {
        this(new URI(uri));
    }

    @Override
    public boolean equals(Object rhs)
    {
        if (rhs == null)
            return false;
        if (this == rhs)
            return true;
        if (rhs instanceof GroupURI)
        {
            GroupURI vu = (GroupURI) rhs;
            return uri.equals(vu.uri);
        }
        return false;
    }

    /**
     * Returns the underlying URI object.
     *
     * @return The URI object for this GroupURI.
     */
    public URI getURI()
    {
        return uri;
    }

    /**
     * Returns the decoded authority component of the URI.
     *
     * @return authority of the URI, or null if the authority is undefined.
     */
    public String getAuthority()
    {
        return uri.getAuthority();
    }

    /**
     * Returns the decoded fragment component of the URI.
     *
     * @return fragment of the URI, or null if the fragment is undefined.
     */
    public String getName()
    {
        return uri.getQuery();
    }

    public URI getServiceID()
    {
        String serviceID = uri.getScheme() +
            "://" +
            uri.getAuthority() +
            uri.getPath();
        try
        {
            return new URI(serviceID);
        }
        catch (URISyntaxException e)
        {
            log.error("Could not create service ID", e);
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString()
    {
        return uri.toString();
    }

}