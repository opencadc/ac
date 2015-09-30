package ca.nrc.cadc.ac.server.ldap;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

import com.unboundid.ldap.sdk.LDAPConnection;

import ca.nrc.cadc.util.Log4jInit;

public class LdapConnectionsTest
{

    private final static Logger log = Logger.getLogger(LdapConnectionsTest.class);

    public LdapConnectionsTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);
        Log4jInit.setLevel("ca.nrc.cadc.profiler", Level.DEBUG);
    }

    @Test
    public void testAutoConfig()
    {
        try
        {
            LDAPConnection readConn = new LDAPConnection();
            LDAPConnection writeConn = new LDAPConnection();
            LdapPersistence persistence = EasyMock.createMock(LdapPersistence.class);

            EasyMock.expect(persistence.getReadOnlyConnection()).andReturn(readConn).once();
            EasyMock.expect(persistence.getReadWriteConnection()).andReturn(writeConn).once();
            EasyMock.expect(persistence.getCurrentConfig()).andReturn(null).once();

            persistence.releaseReadOnlyConnection(readConn);
            EasyMock.expectLastCall().once();

            persistence.releaseReadWriteConnection(writeConn);
            EasyMock.expectLastCall().once();

            EasyMock.replay(persistence);

            LdapConnections connections = new LdapConnections(persistence);

            // multiple calls to get connections should only go to the pool once
            connections.getReadOnlyConnection();
            connections.getReadOnlyConnection();
            connections.getReadOnlyConnection();

            connections.getReadWriteConnection();
            connections.getReadWriteConnection();
            connections.getReadWriteConnection();

            connections.getCurrentConfig();

            connections.releaseConnections();

            EasyMock.verify(persistence);

        }
        catch (Exception e)
        {
            log.error("Unexpected exception", e);
            Assert.fail("Unexpected exception");
        }
    }

    @Test
    public void testManualConfig()
    {
        try
        {
            LDAPConnection readConn = new LDAPConnection();
            LDAPConnection writeConn = new LDAPConnection();
            LdapConnectionPool pool = EasyMock.createMock(LdapConnectionPool.class);

            EasyMock.expect(pool.getReadOnlyConnection()).andReturn(readConn).once();
            EasyMock.expect(pool.getReadWriteConnection()).andReturn(writeConn).once();
            EasyMock.expect(pool.getCurrentConfig()).andReturn(null).once();

            pool.releaseReadOnlyConnection(readConn);
            EasyMock.expectLastCall().once();

            pool.releaseReadWriteConnection(writeConn);
            EasyMock.expectLastCall().once();

            EasyMock.replay(pool);

            LdapConnections connections = new LdapConnections(pool);

            // multiple calls to get connections should only go to the pool once
            connections.getReadOnlyConnection();
            connections.getReadOnlyConnection();
            connections.getReadOnlyConnection();

            connections.getReadWriteConnection();
            connections.getReadWriteConnection();
            connections.getReadWriteConnection();

            connections.getCurrentConfig();

            connections.releaseConnections();

            EasyMock.verify(pool);

        }
        catch (Exception e)
        {
            log.error("Unexpected exception", e);
            Assert.fail("Unexpected exception");
        }
    }

}
