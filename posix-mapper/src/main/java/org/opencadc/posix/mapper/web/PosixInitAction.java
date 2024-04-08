/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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
 *
 ************************************************************************
 */

package org.opencadc.posix.mapper.web;

import ca.nrc.cadc.db.DBUtil;
import ca.nrc.cadc.rest.InitAction;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import org.opencadc.posix.mapper.db.InitializeMappingDatabase;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Logger;
import javax.sql.DataSource;

public class PosixInitAction extends InitAction {

    private static final Logger LOGGER = Logger.getLogger(PosixInitAction.class.getName());

    // config keys
    public static final String JNDI_DATASOURCE = "jdbc/posix-mapper"; // context.xml

    // config keys
    private static final String POSIX_KEY = "org.opencadc.posix.mapper";
    static final String SCHEMA_KEY = PosixInitAction.POSIX_KEY + ".schema";

    public static final String UID_START_KEY = PosixInitAction.POSIX_KEY + ".uid.start";
    public static final String GID_START_KEY = PosixInitAction.POSIX_KEY + ".gid.start";

    static final String RESOURCE_ID_KEY = PosixInitAction.POSIX_KEY + ".resourceID";

    // Add multiples of these to the Properties file.
    static final String ALLOWED_DISTINGUISHED_NAMES_KEY = PosixInitAction.POSIX_KEY + ".authDN";

    static final String[] CHECK_CONFIG_KEYS = new String[] {
            PosixInitAction.SCHEMA_KEY, PosixInitAction.RESOURCE_ID_KEY,
            PosixInitAction.UID_START_KEY, PosixInitAction.GID_START_KEY
    };

    MultiValuedProperties props;
    private final Map<String, Object> daoConfig = new HashMap<>();

    @Override
    public void doInit() {
        initConfig();
        initDatabase();
    }

    /**
     * Read config file and verify that all required entries are present.
     *
     * @return MultiValuedProperties containing the application config
     * @throws IllegalStateException if required config items are missing
     */
    public static MultiValuedProperties getConfig() {
        final PropertiesReader propertiesReader = new PropertiesReader("posix-mapper.properties");
        final MultiValuedProperties multiValuedProperties = propertiesReader.getAllProperties();

        final StringBuilder errorReportMessage = new StringBuilder();
        errorReportMessage.append("incomplete config: ");

        Arrays.stream(PosixInitAction.CHECK_CONFIG_KEYS)
              .forEach(key -> PosixInitAction.checkConfigProperty(key, multiValuedProperties, errorReportMessage));

        if (errorReportMessage.indexOf("MISSING") > 0) {
            throw new IllegalStateException(errorReportMessage.toString());
        }

        return multiValuedProperties;
    }

    static void checkConfigProperty(final String key, final MultiValuedProperties multiValuedProperties,
                                    final StringBuilder errorReportMessage) {
        final String configPropertyValue = multiValuedProperties.getFirstPropertyValue(key);
        errorReportMessage.append("\n\t").append(key).append(": ");
        if (configPropertyValue == null) {
            errorReportMessage.append("MISSING");
        } else {
            errorReportMessage.append("OK");
        }
    }

    private void initConfig() {
        LOGGER.info("initConfig: START");
        this.props = PosixInitAction.getConfig();
        this.daoConfig.putAll(getDaoConfig(props));
        LOGGER.info("initConfig: OK");
    }

    static Map<String,Object> getDaoConfig(MultiValuedProperties props) {
        final Map<String,Object> ret = new TreeMap<>();
        ret.put("jndiDataSourceName", PosixInitAction.JNDI_DATASOURCE);
        ret.put("schema", props.getFirstPropertyValue(PosixInitAction.SCHEMA_KEY));

        return ret;
    }

    private void initDatabase() {
        LOGGER.info("initDatabase: START");
        try {
            DataSource ds = DBUtil.findJNDIDataSource(PosixInitAction.JNDI_DATASOURCE);
            String database = (String) daoConfig.get("database");
            String schema = (String) daoConfig.get("schema");
            final InitializeMappingDatabase init = new InitializeMappingDatabase(ds, database, schema);
            init.doInit();
            LOGGER.info("initDatabase: " + PosixInitAction.JNDI_DATASOURCE + " " + schema + " OK");
        } catch (Exception ex) {
            throw new IllegalStateException("check/init database failed", ex);
        }
    }
}
