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
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.server.ldap.LdapConfig.LdapPool;
import ca.nrc.cadc.ac.server.ldap.LdapConfig.PoolPolicy;
import ca.nrc.cadc.ac.server.ldap.LdapConfig.SystemState;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;

import com.unboundid.ldap.sdk.FastestConnectServerSet;
import com.unboundid.ldap.sdk.FewestConnectionsServerSet;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RoundRobinServerSet;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;

/**
 * This object is designed to be shared between the DAO classes
 * for access to LDAP.  There should only be a single instance.
 * It wraps a connection pool object from the UnboundID library.
 * This object is thread-safe.
 *
 * @author majorb
 */
public class LdapConnectionPool
{
    private static final Logger logger = Logger.getLogger(LdapConnectionPool.class);

    protected LdapConfig currentConfig;
    private String poolName;
    private LDAPConnectionPool pool;
    private Object poolMonitor = new Object();
    private LDAPConnectionOptions connectionOptions;
    private boolean readOnly;
    private SystemState systemState;

    public LdapConnectionPool(LdapConfig config, LdapPool poolConfig, String poolName, boolean boundPool, boolean readOnly)
    {
        if (config == null)
            throw new IllegalArgumentException("config required");
        if (poolConfig == null)
            throw new IllegalArgumentException("poolConfig required");
        if (poolName == null)
            throw new IllegalArgumentException("poolName required");

        connectionOptions = new LDAPConnectionOptions();
        connectionOptions.setUseSynchronousMode(true);
        connectionOptions.setAutoReconnect(true);
        currentConfig = config;
        this.poolName = poolName;
        this.readOnly = readOnly;

        systemState = config.getSystemState();
        logger.debug("Construct pool: " + poolName + ". system state: " + systemState);
        if (SystemState.ONLINE.equals(systemState) || (SystemState.READONLY.equals(systemState) && readOnly))
        {
            Profiler profiler = new Profiler(LdapConnectionPool.class);
            synchronized (poolMonitor)
            {
                if (!boundPool)
                    pool = createPool(config, poolConfig, poolName, null, null);
                else
                    pool = createPool(config, poolConfig, poolName, config.getAdminUserDN(), config.getAdminPasswd());

                if (pool != null)
                {
                    logger.debug(poolName + " statistics after create:\n" + pool.getConnectionPoolStatistics());
                    profiler.checkpoint("Create read only pool.");
                }
            }
        }
        else
        {
            logger.debug("Not creating pool " + poolName + " because system state is " + systemState);
        }
    }

    public LDAPConnection getConnection() throws TransientException
    {

        logger.debug("Get connection: " + poolName + ". system state: " + systemState);
        if (SystemState.OFFLINE.equals(systemState))
        {
            throw new TransientException("The system is down for maintenance.", 600);
        }

        if (SystemState.READONLY.equals(systemState))
        {
            if (!readOnly)
            {
                throw new TransientException("The system is in read-only mode.", 600);
            }
        }

        try
        {
            Profiler profiler = new Profiler(LdapConnectionPool.class);
            LDAPConnection conn = null;
            synchronized (poolMonitor)
            {
                conn = pool.getConnection();

                // BM: This query to the base dn (starting at dc=) has the
                // effect of clearing any proxied authorization state associated
                // with the receiving ldap server connection.  Without this in
                // place, proxied authorization information is sometimes ignored.
//                logger.debug("Testing connection");
//                int index = currentConfig.getGroupsDN().indexOf(',');
//                String rdn = currentConfig.getGroupsDN().substring(0, index);
//                Filter filter = Filter.create("(" + rdn + ")");
//
//                index = rdn.indexOf('=');
//                String attribute = rdn.substring(0, index);
//
//                SearchRequest searchRequest = new SearchRequest(currentConfig.getGroupsDN(), SearchScope.BASE, filter, new String[] {attribute});
//                conn.search(searchRequest);
//                profiler.checkpoint("pool.initConnection");
            }
            logger.debug(poolName + " pool statistics after borrow:\n" + pool.getConnectionPoolStatistics());
            profiler.checkpoint("get " + poolName + " connection");
            conn.setConnectionOptions(connectionOptions);

            return conn;
        }
        catch (LDAPException e)
        {
            throw new TransientException("Failed to get connection", e);
        }
    }

    public void releaseConnection(LDAPConnection conn)
    {
        if (pool != null)
        {
            Profiler profiler = new Profiler(LdapConnectionPool.class);
            pool.releaseConnection(conn);
            profiler.checkpoint("pool.releaseConnection");
            logger.debug(poolName + " pool statistics after release:\n" + pool.getConnectionPoolStatistics());
        }
    }
    
    public String getPoolStatistics()
    {
        if (pool != null)
            return poolName + " pool statistics: " + pool.getConnectionPoolStatistics();
        return null;
    }

    public LdapConfig getCurrentConfig()
    {
        return currentConfig;
    }

    public void shutdown()
    {
        if (pool != null)
        {
            logger.debug("Closing pool...");
            Profiler profiler = new Profiler(LdapConnectionPool.class);
            pool.close();
            profiler.checkpoint("pool.shutdown");
        }
    }

    public String getName()
    {
        return poolName;
    }

    private LDAPConnectionPool createPool(LdapConfig config, LdapPool poolConfig, String poolName, String bindID, String bindPW)
    {
        try
        {
            logger.debug("LDAP Config: " + config);
            String[] hosts = poolConfig.getServers().toArray(new String[0]);
            int[] ports = new int[poolConfig.getServers().size()];
            for (int i=0; i<poolConfig.getServers().size(); i++)
            {
                ports[i] = config.getPort();
            }

            ServerSet serverSet = null;
            if (poolConfig.getPolicy().equals(PoolPolicy.roundRobin))
            {
                serverSet = new RoundRobinServerSet(hosts, ports, LdapDAO.getSocketFactory(config));
            }
            else if (poolConfig.getPolicy().equals(PoolPolicy.fewestConnections))
            {
                serverSet = new FewestConnectionsServerSet(hosts, ports, LdapDAO.getSocketFactory(config));
            }
            else if (poolConfig.getPolicy().equals(PoolPolicy.firstResponse))
            {
                serverSet = new FastestConnectServerSet(hosts, ports, LdapDAO.getSocketFactory(config));
            }
            else
            {
                throw new IllegalStateException("Unconfigured pool policy: " + poolConfig.getPolicy());
            }

            SimpleBindRequest bindRequest = null;
            if (bindID != null && bindPW != null)
            {
                logger.debug("Binding pool as " + bindID);
                bindRequest = new SimpleBindRequest(bindID, bindPW);
            }
            else
            {
                logger.debug("Binding pool annonymously");
                bindRequest = new SimpleBindRequest();
            }
            LDAPConnectionPool connectionPool = new LDAPConnectionPool(
                serverSet, bindRequest, poolConfig.getInitSize(), poolConfig.getMaxSize());

            connectionPool.setCreateIfNecessary(poolConfig.getCreateIfNeeded());
            connectionPool.setMaxWaitTimeMillis(poolConfig.getMaxWait());
            connectionPool.setConnectionPoolName(poolName);

            return connectionPool;
        }
        catch (Exception e)
        {
            logger.error("Failed to create connection pool", e);
            throw new IllegalStateException(e);
        }
    }

}
