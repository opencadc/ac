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

package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import org.apache.log4j.Logger;
import com.unboundid.ldap.sdk.LDAPConnection;

/**
 * This class in the means by which the DAO classes obtain
 * connections to LDAP.  The connections are either manual (if config is
 * provided) or automatic and with a connection pool if a persistence
 * object is provided.
 * <p>
 * This class is not thread-safe but does not need to be since new
 * instances of the DAO classes are always created.
 *
 * @author majorb
 */
class LdapConnections {
    private final static Logger log = Logger.getLogger(LdapConnections.class);

    private LdapPersistence persistence;
    private LdapConfig config;

    private LdapConnectionPool readOnlyPool;
    private LdapConnectionPool readWritePool;
    private LdapConnectionPool unboundReadOnlyPool;

    private LDAPConnection autoConfigReadOnlyConn;
    private LDAPConnection autoConfigReadWriteConn;
    private LDAPConnection autoConfigUnboundReadOnlyConn;

    private LDAPConnection manualConfigReadOnlyConn;
    private LDAPConnection manualConfigReadWriteConn;
    private LDAPConnection manualConfigUnboundReadOnlyConn;

    LdapConnections(LdapPersistence persistence) {
        if (persistence == null)
            throw new RuntimeException("persistence object is required");
        this.persistence = persistence;
    }

    LdapConnections(LdapConfig config) {
        if (config == null)
            throw new RuntimeException("config object is required");

        this.config = config;
    }

    LDAPConnection getReadOnlyConnection() throws TransientException {
        if (persistence != null) {
            if (readOnlyPool == null) {
                readOnlyPool = persistence.getPool(LdapPersistence.POOL_READONLY);
            }
            if (autoConfigReadOnlyConn == null) {
                log.debug("Getting new auto config read only connection.");
                Profiler profiler = new Profiler(LdapConnections.class);
                autoConfigReadOnlyConn = readOnlyPool.getConnection();
                profiler.checkpoint("Get read only connection");
            } else {
                log.debug("Getting reused auto config read only connection.");
            }
            return autoConfigReadOnlyConn;
        } else {
            if (readOnlyPool == null) {
                readOnlyPool = new LdapConnectionPool(config, config.getReadOnlyPool(), LdapPersistence.POOL_READONLY, true, true);
            }
            if (manualConfigReadOnlyConn == null) {
                log.debug("Getting new manual config read only connection.");
                manualConfigReadOnlyConn = readOnlyPool.getConnection();
            } else {
                log.debug("Getting reused manual config read only connection.");
            }
            return manualConfigReadOnlyConn;
        }
    }

    LDAPConnection getReadWriteConnection() throws TransientException {
        if (persistence != null) {
            if (readWritePool == null) {
                readWritePool = persistence.getPool(LdapPersistence.POOL_READWRITE);
            }
            if (autoConfigReadWriteConn == null) {
                log.debug("Getting new auto config read write connection.");
                Profiler profiler = new Profiler(LdapConnections.class);
                autoConfigReadWriteConn = readWritePool.getConnection();
                profiler.checkpoint("Get read write connection");
            } else {
                log.debug("Getting reused auto config read write connection.");
            }
            return autoConfigReadWriteConn;
        } else {
            if (readWritePool == null) {
                readWritePool = new LdapConnectionPool(config, config.getReadWritePool(), LdapPersistence.POOL_READWRITE, true, false);
            }
            if (manualConfigReadWriteConn == null) {
                log.debug("Getting new manual config read write connection.");
                manualConfigReadWriteConn = readWritePool.getConnection();
            } else {
                log.debug("Getting reused manual config read write connection.");
            }
            return manualConfigReadWriteConn;
        }
    }

    LDAPConnection getUnboundReadOnlyConnection() throws TransientException {
        if (persistence != null) {
            if (unboundReadOnlyPool == null) {
                unboundReadOnlyPool = persistence.getPool(LdapPersistence.POOL_UNBOUNDREADONLY);
            }
            if (autoConfigUnboundReadOnlyConn == null) {
                log.debug("Getting new auto config unbound read only connection.");
                Profiler profiler = new Profiler(LdapConnections.class);
                autoConfigUnboundReadOnlyConn = unboundReadOnlyPool.getConnection();
                profiler.checkpoint("Get read write connection");
            } else {
                log.debug("Getting reused auto config unbound read only connection.");
            }
            return autoConfigUnboundReadOnlyConn;
        } else {
            if (unboundReadOnlyPool == null) {
                unboundReadOnlyPool = new LdapConnectionPool(config, config.getUnboundReadOnlyPool(), LdapPersistence.POOL_UNBOUNDREADONLY, false, true);
            }
            if (manualConfigUnboundReadOnlyConn == null) {
                log.debug("Getting new manual config unbound read only connection.");
                manualConfigUnboundReadOnlyConn = unboundReadOnlyPool.getConnection();
            } else {
                log.debug("Getting reused manual config unbound read only connection.");
            }
            return manualConfigUnboundReadOnlyConn;
        }
    }

    void releaseConnections() {
        Profiler profiler = new Profiler(LdapConnections.class);
        if (persistence != null) {
            if (autoConfigReadOnlyConn != null) {
                log.debug("Releasing read only auto config connection.");
                readOnlyPool.releaseConnection(autoConfigReadOnlyConn);
                profiler.checkpoint("Release read only connection");
            }
            if (autoConfigReadWriteConn != null) {
                log.debug("Releasing read write auto config connection.");
                readWritePool.releaseConnection(autoConfigReadWriteConn);
                profiler.checkpoint("Release read write connection");
            }
            if (autoConfigUnboundReadOnlyConn != null) {
                log.debug("Releasing unbound read only auto config connection.");
                unboundReadOnlyPool.releaseConnection(autoConfigUnboundReadOnlyConn);
                profiler.checkpoint("Release read only connection");
            }
        } else {
            if (manualConfigReadOnlyConn != null) {
                log.debug("Releasing read only manual config connection.");
                readOnlyPool.releaseConnection(manualConfigReadOnlyConn);
            }
            if (manualConfigReadWriteConn != null) {
                log.debug("Releasing read write manual config connection.");
                readWritePool.releaseConnection(manualConfigReadWriteConn);
            }
            if (manualConfigUnboundReadOnlyConn != null) {
                log.debug("Releasing unbound read only manual config connection.");
                unboundReadOnlyPool.releaseConnection(manualConfigUnboundReadOnlyConn);
            }
        }
    }

    /**
     * Best-effort manual pool shutdown.
     */
    @Override
    protected void finalize() {
        if (readOnlyPool != null && persistence == null) {
            log.debug("Closing manual config readonly connection pool--should only see this " +
                    "message when running unit tests.");
            readOnlyPool.shutdown();
        }
        if (readWritePool != null && persistence == null) {
            log.debug("Closing manual config readwrite connection pool--should only see this " +
                    "message when running unit tests.");
            readWritePool.shutdown();
        }
        if (unboundReadOnlyPool != null && persistence == null) {
            log.debug("Closing manual config unboundreadonly connection pool--should only see this " +
                    "message when running unit tests.");
            unboundReadOnlyPool.shutdown();
        }
    }

    LdapConfig getCurrentConfig() {
        if (persistence != null)
            return persistence.getCurrentConfig();
        else
            return config;
    }


}
