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
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;

import com.unboundid.ldap.sdk.FewestConnectionsServerSet;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPReadWriteConnectionPool;
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

    private static final int POOL_CHECK_INTERVAL_MILLESCONDS = 10000; // 10 seconds

    Profiler profiler = new Profiler(LdapConnectionPool.class);

    protected LdapConfig currentConfig;
    private LDAPReadWriteConnectionPool pool;
    private Object poolMonitor = new Object();
    private LDAPConnectionOptions connectionOptions;

    private long lastPoolCheck = System.currentTimeMillis();

    public LdapConnectionPool()
    {
        this(LdapConfig.getLdapConfig());
    }

    public LdapConnectionPool(LdapConfig config)
    {
        if (config == null)
            throw new IllegalArgumentException("config required");

        connectionOptions = new LDAPConnectionOptions();
        connectionOptions.setUseSynchronousMode(true);
        connectionOptions.setAutoReconnect(true);
        currentConfig = config;
        synchronized (poolMonitor)
        {
            pool = createPool(currentConfig);
            profiler.checkpoint("Create pool");
        }
    }

    public LDAPConnection getReadOnlyConnection() throws TransientException
    {
        poolCheck();

        try
        {
            LDAPConnection conn = null;
            synchronized (poolMonitor)
            {
                conn = pool.getReadConnection();
            }
            logger.debug("Read pool statistics after borrow:\n" + pool.getReadPoolStatistics());
            profiler.checkpoint("get read only connection");
            conn.setConnectionOptions(connectionOptions);

            return conn;
        }
        catch (LDAPException e)
        {
            throw new TransientException("Failed to get read only connection", e);
        }
    }

    public LDAPConnection getReadWriteConnection() throws TransientException
    {
        poolCheck();

        try
        {
            LDAPConnection conn = null;
            synchronized (poolMonitor)
            {
                conn = pool.getWriteConnection();
            }

            logger.debug("write pool statistics after borrow:\n" + pool.getWritePoolStatistics());
            profiler.checkpoint("get read write connection");
            conn.setConnectionOptions(connectionOptions);

            return conn;
        }
        catch (LDAPException e)
        {
            throw new TransientException("Failed to get read write connection", e);
        }
    }

    public void releaseReadOnlyConnection(LDAPConnection conn)
    {
        pool.releaseReadConnection(conn);
        logger.debug("Read pool statistics after release:\n" + pool.getReadPoolStatistics());
    }

    public void releaseReadWriteConnection(LDAPConnection conn)
    {
        pool.releaseWriteConnection(conn);
        logger.debug("write pool statistics after release:\n" + pool.getWritePoolStatistics());
    }

    public LdapConfig getCurrentConfig()
    {
        return currentConfig;
    }

    public void shutdown()
    {
        logger.debug("Shutting down pool");
        pool.close();
        profiler.checkpoint("Shutdown pool");
    }

    @Override
    public void finalize()
    {
        // just in case the client doesn't call shutdown()
        if (!pool.isClosed())
            pool.close();
    }

    private void poolCheck()
    {
        if (timeToCheckPool())
        {
            // check to see if the configuration has changed
            logger.debug("checking for ldap config change");
            LdapConfig newConfig = LdapConfig.getLdapConfig();
            if (!newConfig.equals(currentConfig))
            {
                logger.debug("Detected ldap configuration change, rebuilding pools");
                boolean poolRecreated = false;
                final LDAPReadWriteConnectionPool oldPool = pool;

                synchronized (poolMonitor)
                {
                    // check to see if another thread has already
                    // done the work
                    if (timeToCheckPool())
                    {
                        this.currentConfig = newConfig;
                        pool = createPool(currentConfig);
                        profiler.checkpoint("Rebuild pool");
                        lastPoolCheck = System.currentTimeMillis();
                        poolRecreated = true;
                    }
                }

                if (poolRecreated)
                {
                    // close the old pool in a separate thread
                    Runnable closeOldPool = new Runnable()
                    {
                        public void run()
                        {
                            logger.debug("Closing old pool...");
                            oldPool.close();
                            logger.debug("Old pool closed.");
                        }
                    };
                    Thread closePoolThread = new Thread(closeOldPool);
                    closePoolThread.start();
                }

            }
            else
            {
                lastPoolCheck = System.currentTimeMillis();
            }
        }
    }

    private boolean timeToCheckPool()
    {
        return (System.currentTimeMillis() - lastPoolCheck) > POOL_CHECK_INTERVAL_MILLESCONDS;
    }

    private LDAPReadWriteConnectionPool createPool(LdapConfig config)
    {
        LDAPConnectionPool ro = createPool(config.getReadOnlyPool(), config);
        LDAPConnectionPool rw = createPool(config.getReadOnlyPool(), config);
        LDAPReadWriteConnectionPool pool = new LDAPReadWriteConnectionPool(ro, rw);
        logger.debug("Read pool statistics after create:\n" + pool.getReadPoolStatistics());
        logger.debug("Write pool statistics after create:\n" + pool.getWritePoolStatistics());
        return pool;
    }

    private synchronized LDAPConnectionPool createPool(LdapPool pool, LdapConfig config)
    {
        try
        {
            logger.debug("LDAP Config: " + config);
            String[] hosts = pool.getServers().toArray(new String[0]);
            int[] ports = new int[pool.getServers().size()];
            for (int i=0; i<pool.getServers().size(); i++)
            {
                ports[i] = config.getPort();
            }

            ServerSet serverSet = null;
            if (pool.getPolicy().equals(PoolPolicy.roundRobin))
            {
                serverSet = new RoundRobinServerSet(hosts, ports, LdapDAO.getSocketFactory(config));
            }
            else if (pool.getPolicy().equals(PoolPolicy.fewestConnections))
            {
                serverSet = new FewestConnectionsServerSet(hosts, ports, LdapDAO.getSocketFactory(config));
            }
            else
            {
                throw new IllegalStateException("Unconfigured pool policy: " + pool.getPolicy());
            }

            SimpleBindRequest bindRequest = new SimpleBindRequest(config.getAdminUserDN(), config.getAdminPasswd());
            LDAPConnectionPool connectionPool = new LDAPConnectionPool(
                serverSet, bindRequest, pool.getInitSize(), pool.getMaxSize());

            connectionPool.setCreateIfNecessary(pool.getCreateIfNeeded());
            connectionPool.setMaxWaitTimeMillis(pool.getMaxWait());

            return connectionPool;
        }
        catch (Exception e)
        {
            logger.error("Failed to create connection pool", e);
            throw new IllegalStateException(e);
        }
    }


}
