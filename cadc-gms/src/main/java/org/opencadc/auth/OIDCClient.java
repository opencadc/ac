/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2024.                            (c) 2024.
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
 ************************************************************************
 */

package org.opencadc.auth;

import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.InvalidConfigException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import org.json.JSONObject;


/**
 * Client to the currently configured OpenID Connect provider.
 * TODO: Generic enough to be more central?
 *
 * @see LocalAuthority for configuration
 * @see ca.nrc.cadc.reg.client.RegistryClient for configuration
 */
class OIDCClient {
    private static final String WELL_KNOWN_ENDPOINT = "/.well-known/openid-configuration";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo_endpoint";
    private static final String ISSUER_LOOKUP_KEY = Standards.SECURITY_METHOD_OPENID.toASCIIString();

    /**
     * Obtain the Issuer base URL.
     *
     * @return URL of the Issuer.  Never null.
     */
    static URI getIssuerID() {
        final LocalAuthority localAuthority = new LocalAuthority();
        return localAuthority.getServiceURI(OIDCClient.ISSUER_LOOKUP_KEY);
    }

    /**
     * Obtain the Issuer base URL.
     *
     * @return URL of the Issuer.  Never null.
     * @throws InvalidConfigException If the configured Issuer URL is not a valid URL.
     */
    static URL getIssuer() {
        final URI openIDIssuerURI = OIDCClient.getIssuerID();
        try {
            return openIDIssuerURI.toURL();
        } catch (MalformedURLException ex) {
            throw new InvalidConfigException("found " + OIDCClient.ISSUER_LOOKUP_KEY + " = " + openIDIssuerURI + " - expected valid URL", ex);
        }
    }

    /**
     * Obtain the .well-known endpoint JSON document.
     * TODO: Cache this?
     *
     * @return The JSON Object of the response data.
     * @throws MalformedURLException If URLs cannot be created as expected.
     */
    static JSONObject getWellKnownJSON() throws MalformedURLException {
        final URL oidcIssuer = OIDCClient.getIssuer();
        final URL configurationURL = new URL(oidcIssuer.toExternalForm() + OIDCClient.WELL_KNOWN_ENDPOINT);
        final Writer writer = new StringWriter();
        final HttpGet httpGet = new HttpGet(configurationURL, inputStream -> {
            final Reader inputReader = new BufferedReader(new InputStreamReader(inputStream));
            final char[] buffer = new char[8192];
            int charsRead;
            while ((charsRead = inputReader.read(buffer)) >= 0) {
                writer.write(buffer, 0, charsRead);
            }
            writer.flush();
        });

        httpGet.run();

        return new JSONObject(writer.toString());
    }

    /**
     * Pull the User Info Endpoint URL from the Well Known JSON document.
     *
     * @return URL of the User Info Endpoint to validate a bearer token.  Never null.
     * @throws MalformedURLException For a poorly formed URL.
     */
    static URL getUserInfoEndpoint() throws MalformedURLException {
        final JSONObject jsonObject = OIDCClient.getWellKnownJSON();
        final String userInfoEndpointString = jsonObject.getString(OIDCClient.USERINFO_ENDPOINT_KEY);
        return new URL(userInfoEndpointString);
    }
}
