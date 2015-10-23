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

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.util.Log4jInit;

import com.unboundid.ldap.sdk.LDAPConnection;

public class LdapConnectionsTest
{

    private final static Logger log = Logger.getLogger(LdapConnectionsTest.class);

    public LdapConnectionsTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.profiler", Level.INFO);
    }

    @Test
    public void testAutoConfig()
    {
        try
        {
            LdapConnectionPool readPool = EasyMock.createMock(LdapConnectionPool.class);
            LdapConnectionPool writePool = EasyMock.createMock(LdapConnectionPool.class);
            LdapConnectionPool unReadPool = EasyMock.createMock(LdapConnectionPool.class);

            LDAPConnection readConn = new LDAPConnection();
            LDAPConnection writeConn = new LDAPConnection();
            LDAPConnection unReadConn = new LDAPConnection();

            LdapPersistence persistence = EasyMock.createMock(LdapPersistence.class);

            EasyMock.expect(persistence.getPool(LdapPersistence.POOL_READONLY)).andReturn(readPool).once();
            EasyMock.expect(persistence.getPool(LdapPersistence.POOL_READWRITE)).andReturn(writePool).once();
            EasyMock.expect(persistence.getPool(LdapPersistence.POOL_UNBOUNDREADONLY)).andReturn(unReadPool).once();
            EasyMock.expect(persistence.getCurrentConfig()).andReturn(null).once();

            EasyMock.expect(readPool.getConnection()).andReturn(readConn).once();
            EasyMock.expect(writePool.getConnection()).andReturn(writeConn).once();
            EasyMock.expect(unReadPool.getConnection()).andReturn(unReadConn).once();

            readPool.releaseConnection(readConn);
            EasyMock.expectLastCall().once();

            writePool.releaseConnection(writeConn);
            EasyMock.expectLastCall().once();

            unReadPool.releaseConnection(unReadConn);
            EasyMock.expectLastCall().once();

            EasyMock.replay(persistence, readPool, writePool, unReadPool);

            LdapConnections connections = new LdapConnections(persistence);

            // multiple calls to get connections should only go to the pool once
            connections.getReadOnlyConnection();
            connections.getReadOnlyConnection();
            connections.getReadOnlyConnection();

            connections.getReadWriteConnection();
            connections.getReadWriteConnection();
            connections.getReadWriteConnection();

            connections.getUnboundReadOnlyConnection();
            connections.getUnboundReadOnlyConnection();
            connections.getUnboundReadOnlyConnection();

            connections.getCurrentConfig();

            connections.releaseConnections();

            EasyMock.verify(persistence, readPool, writePool, unReadPool);

        }
        catch (Exception e)
        {
            log.error("Unexpected exception", e);
            Assert.fail("Unexpected exception");
        }
    }

}
