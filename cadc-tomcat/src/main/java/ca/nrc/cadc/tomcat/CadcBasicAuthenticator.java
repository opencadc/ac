/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2015.                            (c) 2015.
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
*  $Revision: 5 $
*
************************************************************************
 */

package ca.nrc.cadc.tomcat;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

/**
 * Custom class for Tomcat realm authentication.
 * <p>
 * This class was written against the Apache Tomcat 7 (7.0.33.0) API
 * <p>
 * Authentication checks are performed as REST calls to servers
 * implementing the cadcAccessControl-Server code.
 *
 * @author majorb
 */
public class CadcBasicAuthenticator extends RealmBase {

    private static Logger log = Logger.getLogger(CadcBasicAuthenticator.class);

    private URL loginURL;

    static {
        RealmUtil.initLogging();
        Logger.getLogger("ca.nrc.cadc.tomcat").setLevel(Level.INFO);
    }

    /**
     * Set the login URL for the current host. Used by the realm configuration.
     *
     * @param configuredLoginURL The String login URL.
     */
    public void setLoginURL(final String configuredLoginURL) {
        try {
            this.loginURL = new URL(configuredLoginURL);
            if (!"https".equals(loginURL.getProtocol())) {
                log.warn("INSECURE: detected insecure protocol '" + loginURL.getProtocol() + " in loginURL: " + loginURL.toExternalForm());
            }
        } catch (MalformedURLException ex) {
            throw new RuntimeException("CONFIG: invalid loginURL: " + configuredLoginURL);
        }
    }

    @Override
    protected String getName() {
        // not used
        return this.getClass().getSimpleName();
    }

    @Override
    protected String getPassword(final String username) {
        // not used
        return null;
    }

    @Override
    protected Principal getPrincipal(final String username) {
        // not used
        return null;
    }

    @Override
    public Principal authenticate(String username, String credentials) {
        long start = System.currentTimeMillis();
        boolean success = true;

        try {
            boolean valid = login(username, credentials);

            if (valid) {
                // authentication ok, add public role
                List<String> roles = Collections.singletonList("public");

                // Don't want to return the password here in the principal
                // in case it makes it into the servlet somehow
                return new GenericPrincipal(username, null, roles);
            }

            return null;
        } catch (Throwable t) {
            success = false;
            String message = "username/password authentication failed: " + t.getMessage();
            log.error(message, t);
            return null;
        } finally {
            long duration = System.currentTimeMillis() - start;

            // Converted from StringBuilder as it was unnecessary.
            // jenkinsd 2016.08.09
            String json = "{"
                    + "\"method\":\"AUTH\","
                    + "\"user\":\"" + username + "\","
                    + "\"success\":" + success + ","
                    + "\"time\":" + duration
                    + "}";

            log.info(json);
        }
    }

    boolean login(String username, String credentials)
            throws IOException {
        String post = "username=" + username + "&password=" + credentials;

        HttpURLConnection conn = (HttpURLConnection) loginURL.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        byte[] postData = post.getBytes("UTF-8");
        conn.getOutputStream().write(postData);

        int responseCode = conn.getResponseCode();

        log.debug("Http POST to /ac/login returned " + responseCode + " for user " + username);

        if (responseCode != 200) {
            // authentication not ok
            if (responseCode != 401) {
                // not an unauthorized, so log the
                // possible server side error
                String errorMessage = "Error calling loginURL: " + loginURL + "  error code: " + responseCode;
                throw new IllegalStateException(errorMessage);
            }

            // authentication simply failed
            return false;
        }

        return true;
    }

}
