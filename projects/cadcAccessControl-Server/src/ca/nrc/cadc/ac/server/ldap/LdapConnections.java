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

import org.apache.log4j.Logger;

import ca.nrc.cadc.profiler.Profiler;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPReadWriteConnectionPool;

/**
 * This class in the means by which the DAO classes obtain
 * connections to LDAP.  The connections are either manual (if config is
 * provided) or automatic and with a connection pool if a persistence
 * object is provided.
 *
 * This class is not thread-safe but does not need to be since new
 * instances of the DAO classes are always created.
 *
 * @author majorb
 */
class LdapConnections
{
    private final static Logger log = Logger.getLogger(LdapConnections.class);

    Profiler profiler = new Profiler(LdapConnections.class);

    private LdapPersistence persistence;

    private LDAPConnection autoConfigReadOnlyConn;
    private LDAPConnection autoConfigReadWriteConn;

    private LdapConfig config;

    private LDAPReadWriteConnectionPool manualConfigPool;
    private LDAPConnection manualConfigReadOnlyConn;
    private LDAPConnection manualConfigReadWriteConn;

    LdapConnections(LdapPersistence persistence)
    {
        this.persistence = persistence;
    }

    LdapConnections(LdapConfig config)
    {
        this.config = config;
    }

    LDAPConnection getReadOnlyConnection() throws LDAPException
    {
        if (persistence != null)
        {
            log.debug("Obtaining auto config read only connection.");
            if (autoConfigReadOnlyConn == null)
            {
                autoConfigReadOnlyConn = persistence.getReadOnlyConnection();
                profiler.checkpoint("Get read only connection");
            }
            return autoConfigReadOnlyConn;
        }
        else
        {
            log.debug("Obtaining manual config read only connection.");
            if (manualConfigPool == null)
            {
                log.debug("Creating manual config connection pool--should only see this " +
                        "message when running unit tests.");
                manualConfigPool = LdapConnectionPool.createPool(config);
            }
            if (manualConfigReadOnlyConn == null)
            {
                manualConfigReadOnlyConn = manualConfigPool.getReadConnection();
            }
            return manualConfigReadOnlyConn;
        }
    }

    LDAPConnection getReadWriteConnection() throws LDAPException
    {
        if (persistence != null)
        {
            log.debug("Obtaining auto config read write connection.");
            if (autoConfigReadWriteConn == null)
            {
                autoConfigReadWriteConn = persistence.getReadWriteConnection();
                profiler.checkpoint("Get read write connection");
            }
            return autoConfigReadWriteConn;
        }
        else
        {
            log.debug("Obtaining manual config read write connection.");
            if (manualConfigPool == null)
            {
                log.debug("Creating manual config connection pool--should only see this " +
                        "message when running unit tests.");
                manualConfigPool = LdapConnectionPool.createPool(config);
            }
            if (manualConfigReadWriteConn == null)
            {
                manualConfigReadWriteConn = manualConfigPool.getReadConnection();
            }
            return manualConfigReadWriteConn;
        }
    }

    void releaseConnections()
    {
        if (persistence != null)
        {
            log.debug("Releasing auto config connections.");
            if (autoConfigReadOnlyConn != null)
            {
                persistence.releaseReadOnlyConnection(autoConfigReadOnlyConn);
                profiler.checkpoint("Release read only connection");
            }
            if (autoConfigReadWriteConn != null)
            {
                persistence.releaseReadWriteConnection(autoConfigReadWriteConn);
                profiler.checkpoint("Release read write connection");
            }
        }
        else
        {
            log.debug("Releasing manual config connections.");
            if (manualConfigReadOnlyConn != null)
            {
                manualConfigPool.releaseReadConnection(manualConfigReadOnlyConn);
            }
            if (manualConfigReadWriteConn != null)
            {
                manualConfigPool.releaseWriteConnection(manualConfigReadWriteConn);
            }
        }
    }

    /**
     * Best-effort manual pool shutdown.
     */
    @Override
    public void finalize()
    {
        if (manualConfigPool != null)
        {
            log.debug("Closing manual config connection pool--should only see this " +
            		"message when running unit tests.");
            manualConfigPool.close();
        }
    }

    LdapConfig getCurrentConfig()
    {
        if (persistence != null)
            return persistence.getCurrentConfig();
        else
            return config;

    }

}
