/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.ServiceConfigurationError;

import org.apache.log4j.Logger;

import ca.nrc.cadc.db.ConnectionConfig;
import ca.nrc.cadc.db.DBConfig;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;

/**
 * Reads and stores the LDAP configuration information.
 *
 * @author adriand
 *
 */
public class LdapConfig
{
    private static final Logger logger = Logger.getLogger(LdapConfig.class);

    // A temporary hack to set the LDAP config file name.
    // Refer to https://github.com/opencadc/ac/issues/60 
    public static final String CONFIG = "ac-ldap-config.properties";

    public static final String READONLY_PREFIX = "readOnly.";
    public static final String READWRITE_PREFIX = "readWrite.";
    public static final String UB_READONLY_PREFIX = "unboundReadOnly.";
    public static final String POOL_SERVERS = "servers";
    public static final String POOL_INIT_SIZE = "poolInitSize";
    public static final String POOL_MAX_SIZE = "poolMaxSize";
    public static final String POOL_POLICY = "poolPolicy";
    public static final String MAX_WAIT = "maxWait";
    public static final String CREATE_IF_NEEDED = "createIfNeeded";

    public static final String LDAP_DBRC_ENTRY = "dbrcHost";
    public static final String LDAP_PORT = "port";
    public static final String LDAP_SERVER_PROXY_USER = "proxyUser";
    public static final String LDAP_USERS_DN = "usersDN";
    public static final String LDAP_USER_REQUESTS_DN = "userRequestsDN";
    public static final String LDAP_GROUPS_DN = "groupsDN";
    public static final String LDAP_ADMIN_GROUPS_DN  = "adminGroupsDN";

    private final static int SECURE_PORT = 636;

    public enum PoolPolicy
    {
        roundRobin,
        fewestConnections,
        fastestConnect
    }

    public enum SystemState
    {
        ONLINE,
        READONLY,
        OFFLINE
    }

    public class LdapPool
    {
        private List<String> servers;
        private int initSize;
        private int maxSize;
        private PoolPolicy policy;
        private long maxWait;
        private boolean createIfNeeded;

        public List<String> getServers()
        {
            return servers;
        }
        public int getInitSize()
        {
            return initSize;
        }
        public int getMaxSize()
        {
            return maxSize;
        }
        public PoolPolicy getPolicy()
        {
            return policy;
        }
        public long getMaxWait()
        {
            return maxWait;
        }
        public boolean getCreateIfNeeded()
        {
            return createIfNeeded;
        }

        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append(" Servers: ");
            for (String server : servers)
            {
                sb.append(" [" + server + "]");
            }
            sb.append(" initSize: " + initSize);
            sb.append(" maxSize: " + maxSize);
            sb.append(" policy: " + policy);
            sb.append(" maxWait: " + maxWait);
            sb.append(" createIfNeeded: " + createIfNeeded);
            return sb.toString();
        }

        @Override
        public boolean equals(Object other)
        {
            if (other == null || !(other instanceof LdapPool))
                return false;

            LdapPool l = (LdapPool) other;

            if (! l.servers.equals(servers))
                return false;

            if (l.initSize != initSize)
                return false;

            if (l.maxSize != maxSize)
                return false;

            if ( !(l.policy.equals(policy)))
                return false;

            if ( !(l.maxWait == maxWait))
                return false;

            if ( !(l.createIfNeeded == createIfNeeded))
                return false;

            return true;
        }
    };

    private LdapPool readOnlyPool = new LdapPool();
    private LdapPool readWritePool = new LdapPool();
    private LdapPool unboundReadOnlyPool = new LdapPool();
    private int port;
    private String usersDN;
    private String userRequestsDN;
    private String groupsDN;
    private String adminGroupsDN;
    private String proxyUserDN;
    private String proxyPasswd;
    private String dbrcHost;
    private SystemState systemState;

    public String getProxyUserDN()
    {
        return proxyUserDN;
    }

    public String getProxyPasswd()
    {
        return proxyPasswd;
    }

    public static LdapConfig getLdapConfig()
    {
        return loadLdapConfig(CONFIG);
    }

    public static LdapConfig loadLdapConfig(String ldapProperties)
    {
        logger.debug("Reading LDAP properties from: " + ldapProperties);
        PropertiesReader pr = new PropertiesReader(ldapProperties);

        MultiValuedProperties config = pr.getAllProperties();
        if (config == null || config.keySet() == null)
        {
            throw new RuntimeException("failed to read any LDAP property ");
        }

        LdapConfig ldapConfig = new LdapConfig();

        loadPoolConfig(ldapConfig.readOnlyPool, pr, READONLY_PREFIX);
        loadPoolConfig(ldapConfig.readWritePool, pr, READWRITE_PREFIX);
        loadPoolConfig(ldapConfig.unboundReadOnlyPool, pr, UB_READONLY_PREFIX);

        ldapConfig.dbrcHost = getProperty(pr, LDAP_DBRC_ENTRY);
        ldapConfig.port = Integer.valueOf(getProperty(pr, LDAP_PORT));
        ldapConfig.proxyUserDN = getProperty(pr, LDAP_SERVER_PROXY_USER);
        ldapConfig.usersDN = getProperty(pr, LDAP_USERS_DN);
        ldapConfig.userRequestsDN = getProperty(pr, LDAP_USER_REQUESTS_DN);
        ldapConfig.groupsDN = getProperty(pr, LDAP_GROUPS_DN);
        ldapConfig.adminGroupsDN = getProperty(pr, LDAP_ADMIN_GROUPS_DN);

        ldapConfig.systemState = getSystemState(ldapConfig);

        try
        {
            DBConfig dbConfig = new DBConfig();
            ConnectionConfig cc = dbConfig.getConnectionConfig(ldapConfig.dbrcHost, ldapConfig.proxyUserDN);
            if ( (cc == null) || (cc.getUsername() == null) || (cc.getPassword() == null))
            {
                throw new RuntimeException("failed to find connection info in ~/.dbrc");
            }
            ldapConfig.proxyPasswd = cc.getPassword();
        }
        catch (FileNotFoundException e)
        {
            throw new RuntimeException("failed to find .dbrc file ");
        }
        catch (IOException e)
        {
            throw new RuntimeException("failed to read .dbrc file ");
        }

        return ldapConfig;
    }

    private static void loadPoolConfig(LdapPool pool, PropertiesReader pr, String prefix)
    {
        pool.servers = getMultiProperty(pr, prefix + POOL_SERVERS);
        pool.initSize = Integer.valueOf(getProperty(pr, prefix + POOL_INIT_SIZE));
        pool.maxSize = Integer.valueOf(getProperty(pr, prefix + POOL_MAX_SIZE));
        pool.policy = PoolPolicy.valueOf(getProperty(pr, prefix + POOL_POLICY));
        if (pool.policy == PoolPolicy.fastestConnect && !prefix.equals(READONLY_PREFIX)) {
            throw new ServiceConfigurationError(PoolPolicy.fastestConnect.toString() + 
                " pool policy cannot be applied to " + 
                prefix.substring(0, prefix.length() - 1) + " pool servers.");
        }
        pool.maxWait = Long.valueOf(getProperty(pr, prefix + MAX_WAIT));
        pool.createIfNeeded = Boolean.valueOf(getProperty(pr, prefix + CREATE_IF_NEEDED));
    }

    private static String getProperty(PropertiesReader properties, String key)
    {
        String prop = properties.getFirstPropertyValue(key);
        if (prop == null)
        {
            throw new RuntimeException("failed to read property " + key);
        }
        return prop;
    }

    private static List<String> getMultiProperty(PropertiesReader properties, String key)
    {
        String prop = getProperty(properties, key);

        if (prop == null)
            throw new RuntimeException("failed to read property " + key);

        String[] props = prop.split(" ");
        return Arrays.asList(props);
    }

    private static SystemState getSystemState(LdapConfig ldapConfig)
    {
        if (ldapConfig.getReadOnlyPool().getMaxSize() == 0)
        {
            return SystemState.OFFLINE;
        }

        if (ldapConfig.getUnboundReadOnlyPool().getMaxSize() == 0)
        {
            return SystemState.OFFLINE;
        }

        if (ldapConfig.getReadWritePool().getMaxSize() == 0)
        {
            return SystemState.READONLY;
        }

        return SystemState.ONLINE;
    }


    @Override
    public boolean equals(Object other)
    {
        if (other == null || !(other instanceof LdapConfig))
            return false;

        LdapConfig l = (LdapConfig) other;

        if (l.port != port)
            return false;

        if ( !(l.usersDN.equals(usersDN)))
            return false;

        if ( !(l.userRequestsDN.equals(userRequestsDN)))
            return false;

        if ( !(l.groupsDN.equals(groupsDN)))
            return false;

        if ( !(l.adminGroupsDN.equals(adminGroupsDN)))
            return false;

        if ( !(l.proxyUserDN.equals(proxyUserDN)))
            return false;

        if ( !(l.dbrcHost.equals(dbrcHost)))
            return false;

        if ( !(l.readOnlyPool.equals(readOnlyPool)))
            return false;

        if ( !(l.readWritePool.equals(readWritePool)))
            return false;

        if ( !(l.unboundReadOnlyPool.equals(unboundReadOnlyPool)))
            return false;

        return true;
    }

    private LdapConfig()
    {
    }

    public LdapPool getReadOnlyPool()
    {
        return readOnlyPool;
    }

    public LdapPool getReadWritePool()
    {
        return readWritePool;
    }

    public LdapPool getUnboundReadOnlyPool()
    {
        return unboundReadOnlyPool;
    }

    public String getUsersDN()
    {
        return this.usersDN;
    }

    public String getUserRequestsDN()
    {
        return this.userRequestsDN;
    }

    public String getGroupsDN()
    {
        return this.groupsDN;
    }

    public String getAdminGroupsDN()
    {
        return this.adminGroupsDN;
    }

    public String getDbrcHost()
    {
        return this.dbrcHost;
    }

    public int getPort()
    {
        return this.port;
    }

    public boolean isSecure()
    {
        return getPort() == SECURE_PORT;
    }

    public String getAdminUserDN()
    {
        return this.proxyUserDN;
    }

    public String getAdminPasswd()
    {
        return this.proxyPasswd;
    }

    /**
     * Check if in read-only or offline mode.
     *
     * A read max connection size of zero implies offline mode.
     * A read-wrtie max connection size of zero implies read-only mode.
     */
    public SystemState getSystemState()
    {
        return systemState;
    }

    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(" ReadOnlyPool: [" + readOnlyPool + "]");
        sb.append(" ReadWritePool: [" + readWritePool + "]");
        sb.append(" UnboundReadOnlyPool: [" + unboundReadOnlyPool + "]");
        sb.append(" Port: " + port);
        sb.append(" dbrcHost: " + dbrcHost);
        sb.append(" proxyUserDN: " + proxyUserDN);

        return sb.toString();
    }

}
