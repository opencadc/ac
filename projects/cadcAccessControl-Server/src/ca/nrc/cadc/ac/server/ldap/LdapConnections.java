package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.profiler.Profiler;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;

class LdapConnections
{
    Profiler profiler = new Profiler(LdapPersistence.class);

    private LdapPersistence persistence;

    private LDAPConnection readOnlyConn;
    private LDAPConnection readWriteConn;

    private LdapConfig config;

    private LDAPConnection nonPooledConn;

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
            if (readOnlyConn == null)
            {
                readOnlyConn = persistence.getReadOnlyConnection();
                profiler.checkpoint("Get read only connection");
            }
            return readOnlyConn;
        }
        else
        {
            if (nonPooledConn == null)
            {
                nonPooledConn = getConnection(config);
            }
            return nonPooledConn;
        }
    }

    LDAPConnection getReadWriteConnection() throws LDAPException
    {
        if (persistence != null)
        {
            if (readWriteConn == null)
            {
                readWriteConn = persistence.getReadWriteConnection();
                profiler.checkpoint("Get read write connection");
            }
            return readWriteConn;
        }
        else
        {
            if (nonPooledConn == null)
            {
                nonPooledConn = getConnection(config);
            }
            return nonPooledConn;
        }
    }

    void releaseConnections()
    {
        if (persistence != null)
        {
            if (readOnlyConn != null)
            {
                persistence.releaseReadOnlyConnection(readOnlyConn);
                profiler.checkpoint("Release read only connection");
            }
            if (readWriteConn != null)
            {
                persistence.releaseReadWriteConnection(readWriteConn);
                profiler.checkpoint("Release read write connection");
            }
        }
        if (nonPooledConn != null)
        {
            nonPooledConn.close();
            profiler.checkpoint("Close non-pooled connection");
        }
    }

    LdapConfig getCurrentConfig()
    {
        if (persistence != null)
            return persistence.getCurrentConfig();
        else
            return config;
    }

    private static LDAPConnection getConnection(LdapConfig config) throws LDAPException
    {
        LDAPConnection conn = new LDAPConnection(
            LdapDAO.getSocketFactory(config),
            config.getReadWritePool().getServers().get(0),
            config.getPort());
        conn.bind(config.getAdminUserDN(), config.getAdminPasswd());
        return conn;
    }

}
