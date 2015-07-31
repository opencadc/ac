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

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.varia.LevelRangeFilter;

/**
 * Custom class for Tomcat realm authentication.
 *
 * This class was written against the Apache Tomcat 7 (7.0.33.0) API
 *
 * Authentication checks are performed as REST calls to servers
 * implementing the cadcAccessControl-Server code.
 *
 * @author majorb
 */
public class CadcBasicAuthenticator extends RealmBase
{

    private static Logger log = Logger.getLogger(CadcBasicAuthenticator.class);
    private static final String AC_URI = "ivo://cadc.nrc.ca/canfargms";

    private static final String ISO_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss.SSS";

    // SHORT_FORMAT applies to DEBUG and TRACE logging levels
    private static final String SHORT_FORMAT = "%-4r [%t] %-5p %c{1} %x - %m\n";

    // LONG_FORMAT applies to INFO, WARN, ERROR and FATAL logging levels
    private static final String LONG_FORMAT = "%d{" + ISO_DATE_FORMAT
                                              + "} [%t] %-5p %c{1} %x - %m\n";

    static
    {
        initLogging();
        Logger.getLogger("ca.nrc.cadc.tomcat").setLevel(Level.INFO);
    }

    @Override
    protected String getName()
    {
        // not used
        return this.getClass().getSimpleName();
    }

    @Override
    protected String getPassword(final String username)
    {
        // not used
        return null;
    }

    @Override
    protected Principal getPrincipal(final String username)
    {
        // not used
        return null;
    }

    @Override
    public Principal authenticate(String username, String credentials)
    {
        long start = System.currentTimeMillis();
        boolean success = true;

        try
        {
            RealmRegistryClient registryClient = new RealmRegistryClient();
            URL loginURL = registryClient.getServiceURL(
                new URI(AC_URI), "http", "/login");

            String post = "userid=" + username + "&password=" + credentials;

            HttpURLConnection conn = (HttpURLConnection) loginURL.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);

            byte[] postData = post.getBytes("UTF-8");
            conn.getOutputStream().write(postData);

            int responseCode = conn.getResponseCode();

            log.debug("Http POST to /ac/login returned " +
                    responseCode + " for user " + username);

            if (responseCode != 200)
            {
                // authentication not ok
                if (responseCode != 401)
                {
                    // not an unauthorized, so log the
                    // possible server side error
                    String errorMessage = "Error calling /ac/login, error code: " + responseCode;
                    success = false;
                    throw new IllegalStateException(errorMessage);
                }

                // authentication simply failed
                return null;
            }

            // authentication ok, add public role
            List<String> roles = Arrays.asList("public");

            // Don't want to return the password here in the principal
            // in case it makes it into the servlet somehow
            return new GenericPrincipal(username, "", roles);

        }
        catch (Throwable t)
        {
            String message = "Could not do http basic authentication: " + t.getMessage();
            log.error(message, t);
            throw new IllegalStateException(message, t);
        }
        finally
        {
            long duration = System.currentTimeMillis() - start;

            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"method\":\"AUTH\",");
            json.append("\"user\":\"" + username + "\",");
            json.append("\"success\":" + success + ",");
            json.append("\"time\":" + duration);
            json.append("}");

            log.info(json.toString());
        }
    }

    private static void initLogging()
    {
        // Clear all existing appenders, if there's any.
        BasicConfigurator.resetConfiguration();
        Logger.getRootLogger().setLevel(Level.ERROR); // must redo after reset

        String errorLogFormat = LONG_FORMAT;
        String infoLogFormat = LONG_FORMAT;
        String debugLogFormat = SHORT_FORMAT;

        // Appender for WARN, ERROR and FATAL with LONG_FORMAT message prefix
        ConsoleAppender conAppenderHigh =
                new ConsoleAppender(new PatternLayout(errorLogFormat));
        LevelRangeFilter errorFilter = new LevelRangeFilter();
        errorFilter.setLevelMax(Level.FATAL);
        errorFilter.setLevelMin(Level.WARN);
        errorFilter.setAcceptOnMatch(true);
        conAppenderHigh.clearFilters();
        conAppenderHigh.addFilter(errorFilter);
        BasicConfigurator.configure(conAppenderHigh);

        // Appender for INFO with LONG_FORMAT message prefix
        ConsoleAppender conAppenderInfo =
                new ConsoleAppender(new PatternLayout(infoLogFormat));
        LevelRangeFilter infoFilter = new LevelRangeFilter();
        infoFilter.setLevelMax(Level.INFO);
        infoFilter.setLevelMin(Level.INFO);
        infoFilter.setAcceptOnMatch(true);
        conAppenderInfo.clearFilters();
        conAppenderInfo.addFilter(infoFilter);
        BasicConfigurator.configure(conAppenderInfo);

        // Appender for DEBUG and TRACE with LONG_FORMAT message prefix
        ConsoleAppender conAppenderDebug =
                new ConsoleAppender(new PatternLayout(debugLogFormat));
        LevelRangeFilter debugFilter = new LevelRangeFilter();
        debugFilter.setLevelMax(Level.DEBUG);
        debugFilter.setLevelMin(Level.TRACE);
        debugFilter.setAcceptOnMatch(true);
        conAppenderDebug.clearFilters();
        conAppenderDebug.addFilter(debugFilter);
        BasicConfigurator.configure(conAppenderDebug);
    }

}