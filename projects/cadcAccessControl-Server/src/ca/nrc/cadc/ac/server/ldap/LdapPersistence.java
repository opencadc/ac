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

import java.util.HashMap;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;

import ca.nrc.cadc.ac.server.ldap.LdapConfig.LdapPool;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;

/**
 * Class that provides access to the LdapConnectionPool through
 * JNDI binding.
 */
public abstract class LdapPersistence
{

    // pool names
    public static final String POOL_READONLY = "readOnly";
    public static final String POOL_READWRITE = "readWrite";
    public static final String POOL_UNBOUNDREADONLY = "unboundReadOnly";

    private static final Logger logger = Logger.getLogger(LdapPersistence.class);
    private static final String LDAP_POOL_JNDI_NAME = ConnectionPools.class.getName();
    private static final int POOL_CHECK_INTERVAL_MILLESCONDS = 10000; // 10 seconds

    Profiler profiler = new Profiler(LdapPersistence.class);

    private long lastPoolCheck = System.currentTimeMillis();
    private ConnectionPools pools;

    // static monitor is required for when multiple LdapPersistence objects
    // are created.
    private static Object jndiMonitor = new Object();

    protected LdapPersistence()
    {
        initPools();
    }

    protected LDAPConnection getConnection(String poolName) throws TransientException
    {
        poolCheck();
        return pools.getPools().get(poolName).getConnection();
    }

    protected void releaseConnection(String poolName, LDAPConnection conn)
    {
        pools.getPools().get(poolName).releaseConnection(conn);
    }

    protected LdapConfig getCurrentConfig()
    {
        return pools.getConfig();
    }

    protected void shutdown()
    {
        // shutdown the pools
        pools.getPools().get(POOL_READONLY).shutdown();
        pools.getPools().get(POOL_READWRITE).shutdown();
        pools.getPools().get(POOL_UNBOUNDREADONLY).shutdown();

        // unbind the pool
        try
        {
            InitialContext ic = new InitialContext();
            ic.unbind(LDAP_POOL_JNDI_NAME);
        }
        catch (NamingException e)
        {
            logger.warn("Could not unbind ldap pools", e);
        }
    }

    private void initPools()
    {
        try
        {
            pools = lookupPool();
            logger.debug("Pool from JNDI lookup: " + pools);

            if (pools == null)
            {
                synchronized (jndiMonitor)
                {
                    pools = lookupPool();
                    logger.debug("Pool from second JNDI lookup: " + pools);
                    if (pools == null)
                    {
                        LdapConfig config = LdapConfig.getLdapConfig();
                        pools = createPools(config);
                        InitialContext ic = new InitialContext();
                        ic.bind(LDAP_POOL_JNDI_NAME, pools);
                        profiler.checkpoint("Bound LDAP pools to JNDI");
                        logger.debug("Bound LDAP pools to JNDI");
                    }
                }
            }
        }
        catch (Throwable t)
        {
            String message = "Failed to find or create LDAP connection pool: " + t.getMessage();
            throw new IllegalStateException(message, t);
        }
    }

    private ConnectionPools createPools(LdapConfig config)
    {
        Map<String,LdapConnectionPool> poolMap = new HashMap<String,LdapConnectionPool>(3);
        poolMap.put(POOL_READONLY, new LdapConnectionPool(
            config, config.getReadOnlyPool(), POOL_READONLY, true));
        poolMap.put(POOL_READWRITE, new LdapConnectionPool(
            config, config.getReadWritePool(), POOL_READWRITE, true));
        poolMap.put(POOL_UNBOUNDREADONLY, new LdapConnectionPool(
            config, config.getUnboundReadOnlyPool(), POOL_UNBOUNDREADONLY, false));
        profiler.checkpoint("Created 3 LDAP connection pools");
        return new ConnectionPools(poolMap, config);
    }

    private ConnectionPools lookupPool() throws NamingException
    {
        try
        {
            InitialContext ic = new InitialContext();
            return (ConnectionPools) ic.lookup(LDAP_POOL_JNDI_NAME);
        }
        catch (NameNotFoundException e)
        {
            return null;
        }
    }

    private void poolCheck() throws TransientException
    {
        if (timeToCheckPool())
        {
            // check to see if the configuration has changed
            logger.debug("checking for ldap config change");
            LdapConfig newConfig = LdapConfig.getLdapConfig();
            if (!newConfig.equals(pools.getConfig()))
            {
                logger.debug("Detected ldap configuration change, rebuilding pools");
                boolean poolRecreated = false;
                final ConnectionPools oldPools = pools;

                synchronized (jndiMonitor)
                {
                    // check to see if another thread has already
                    // done the work
                    if (timeToCheckPool())
                    {
                        try
                        {
                            ConnectionPools newPools = createPools(newConfig);
                            InitialContext ic = new InitialContext();
                            try
                            {
                                ic.unbind(LDAP_POOL_JNDI_NAME);
                            }
                            catch (NamingException e)
                            {
                                logger.warn("Could not unbind previous JNDI instance", e);
                            }
                            ic.bind(LDAP_POOL_JNDI_NAME, pools);
                            profiler.checkpoint("Rebuild pools");
                            lastPoolCheck = System.currentTimeMillis();
                            pools = newPools;
                            poolRecreated = true;
                        }
                        catch (NamingException e)
                        {
                            logger.debug("JNDI Naming Exception: " + e.getMessage());
                            throw new TransientException("JNDI Naming Exception", e);
                        }
                    }
                }

                if (poolRecreated)
                {
                    // close the old pool in a separate thread
                    Runnable closeOldPools = new Runnable()
                    {
                        public void run()
                        {
                            logger.debug("Closing old pools...");
                            oldPools.getPools().get(POOL_READONLY).shutdown();
                            oldPools.getPools().get(POOL_READWRITE).shutdown();
                            oldPools.getPools().get(POOL_UNBOUNDREADONLY).shutdown();
                            logger.debug("Old pools closed.");
                        }
                    };
                    Thread closePoolsThread = new Thread(closeOldPools);
                    closePoolsThread.start();
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

}
