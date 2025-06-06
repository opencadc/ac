/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2020.                            (c) 2020.
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

package org.opencadc.permissions.client;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.net.ResourceAlreadyExistsException;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import org.opencadc.permissions.Grant;
import org.opencadc.permissions.ReadGrant;
import org.opencadc.permissions.WriteGrant;
import org.opencadc.permissions.xml.GrantReader;

/**
 * Client for retrieving grant information about artifacts.
 *
 * @author majorb
 */
public class PermissionsClient {

    private final URL serviceURL;

    public enum Operation {
        read,
        write;
    }

    /**
     * Construct a PermissionsClient for the given serviceID URI.
     *
     * @param serviceID The URI of the service to query.
     * @throws ca.nrc.cadc.net.ResourceNotFoundException if permissions service cannot be found
     */
    public PermissionsClient(URI serviceID) throws ResourceNotFoundException {
        assertNotNull(PermissionsClient.class, "serviceID", serviceID);
        RegistryClient regClient = new RegistryClient();
        serviceURL = regClient.getServiceURL(serviceID, Standards.SI_PERMISSIONS, AuthMethod.CERT);
        if (serviceURL == null) {
            throw new ResourceNotFoundException("not found: " + serviceID);
        }
    }

    /**
     * Get the read permissions information about the file identified by assetID.
     *
     * @param assetID Identifies the artifact for which to retrieve grant information.
     * @return Null if permission information isn't found for the assetID, otherwise the read grant information.
     * @throws TransientException If an unexpected, temporary exception occurred.
     */
    public ReadGrant getReadGrant(URI assetID) throws TransientException {
        return (ReadGrant) getGrant(assetID, Operation.read);
    }

    /**
     * Get the write permissions information about the file identified by assetID.
     *
     * @param assetID Identifies the artifact for which to retrieve grant information.
     * @return Null if permission information isn't found for the assetID, otherwise the write grant information.
     * @throws TransientException If an unexpected, temporary exception occurred.
     */
    public WriteGrant getWriteGrant(URI assetID) throws TransientException {
        return (WriteGrant) getGrant(assetID, Operation.write);
    }

    /**
     * Get the permission information about the file identified by assetID.
     *
     * @param assetID Identifies the artifact for which to retrieve grant information.
     * @param op      The type of grant to retrieve.
     * @return Null if permission information isn't found for the assetID, otherwise the grant information.
     * @throws TransientException If an unexpected, temporary exception occurred.
     */
    Grant getGrant(URI assetID, Operation op) throws TransientException {

        URL grantURL = getGrantURL(serviceURL, op, assetID);
        HttpGet httpGet = new HttpGet(grantURL, true);

        try {
            httpGet.prepare();
        } catch (ResourceAlreadyExistsException e) {
            throw new RuntimeException("BUG: should not be thrown doing a GET", e);
        } catch (IOException e) {
            throw new RuntimeException("error reading server response", e);
        } catch (InterruptedException e) {
            throw new TransientException("temporarily unavailable: " + assetID);
        } catch (ResourceNotFoundException e) {
            return null;
        }

        Grant grant;
        try {
            GrantReader reader = new GrantReader();
            grant = reader.read(httpGet.getInputStream());
        } catch (IOException e) {
            throw new RuntimeException("error reading grant", e);
        }
        return grant;
    }

    /**
     * Construct the URL to retrieve the grant information.
     *
     * @param serviceURL The URL of the permissions service.
     * @param op         The type of grant to retrieve.
     * @param assetID    Identifies the artifact for which to retrieve grant information.
     * @return URL to the grant information.
     */
    URL getGrantURL(URL serviceURL, Operation op, URI assetID) {
        try {
            return new URL(serviceURL.toExternalForm() + "?OP=" + op + "&ID=" + NetUtil.encode(assetID.toASCIIString()));
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("invalid assetID " + assetID + ": " + e.getMessage());
        }
    }

    private void assertNotNull(Class caller, String name, Object test) {
        if (test == null) {
            throw new IllegalArgumentException("invalid " + caller.getSimpleName() + "." + name + ": null");
        }
    }
}
