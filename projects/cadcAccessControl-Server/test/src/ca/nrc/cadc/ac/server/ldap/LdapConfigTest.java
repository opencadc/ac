/**
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
 ************************************************************************
 */


package ca.nrc.cadc.ac.server.ldap;

import java.util.ArrayList;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.ac.server.ldap.LdapConfig.PoolPolicy;
import ca.nrc.cadc.util.PropertiesReader;

/**
 * Tests the LdapConfig class.
 */
public class LdapConfigTest
{
    private static final Logger log = Logger.getLogger(LdapConfig.class);

    public LdapConfigTest()
    {
    }

    @Test
    public void testLoadConfig1()
    {
        try
        {
            System.setProperty(PropertiesReader.class.getName() + ".dir", "test/config");

            LdapConfig c = LdapConfig.getLdapConfig("testConfig1.properties");
            Assert.assertEquals("devLdap", c.getDbrcHost());
            Assert.assertEquals(389, c.getPort());
            Assert.assertEquals("uid=testproxy,ou=SpecialUsers,dc=testcanfar", c.getProxyUserDN());
            Assert.assertEquals("usersDN", c.getUsersDN());
            Assert.assertEquals("userRequestsDN", c.getUserRequestsDN());
            Assert.assertEquals("groupsDN", c.getGroupsDN());
            Assert.assertEquals("adminGroupsDN", c.getAdminGroupsDN());
            Assert.assertEquals(Arrays.asList("server1","server2","server3"), c.getReadOnlyPool().getServers());
            Assert.assertEquals(3, c.getReadOnlyPool().getInitSize());
            Assert.assertEquals(8, c.getReadOnlyPool().getMaxSize());
            Assert.assertEquals(PoolPolicy.roundRobin, c.getReadOnlyPool().getPolicy());

            Assert.assertEquals(Arrays.asList("server4","server5"), c.getReadWritePool().getServers());
            Assert.assertEquals(4, c.getReadWritePool().getInitSize());
            Assert.assertEquals(9, c.getReadWritePool().getMaxSize());
            Assert.assertEquals(PoolPolicy.fewestConnections, c.getReadWritePool().getPolicy());
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
        finally
        {
            System.clearProperty(PropertiesReader.class.getName() + ".dir");
        }
    }

    @Test
    public void testLoadConfig2()
    {
        try
        {
            System.setProperty(PropertiesReader.class.getName() + ".dir", "test/config");

            LdapConfig c = LdapConfig.getLdapConfig("testConfig2.properties");
            Assert.assertEquals("devLdap", c.getDbrcHost());
            Assert.assertEquals(389, c.getPort());
            Assert.assertEquals("uid=testproxy,ou=SpecialUsers,dc=testcanfar", c.getProxyUserDN());
            Assert.assertEquals("usersDN", c.getUsersDN());
            Assert.assertEquals("userRequestsDN", c.getUserRequestsDN());
            Assert.assertEquals("groupsDN", c.getGroupsDN());
            Assert.assertEquals("adminGroupsDN", c.getAdminGroupsDN());
            Assert.assertEquals(Arrays.asList("serverA","serverB","serverC"), c.getReadOnlyPool().getServers());
            Assert.assertEquals(0, c.getReadOnlyPool().getInitSize());
            Assert.assertEquals(1, c.getReadOnlyPool().getMaxSize());
            Assert.assertEquals(PoolPolicy.fewestConnections, c.getReadOnlyPool().getPolicy());
            Assert.assertEquals(Arrays.asList("serverC"), c.getReadWritePool().getServers());
            Assert.assertEquals(1, c.getReadWritePool().getInitSize());
            Assert.assertEquals(2, c.getReadWritePool().getMaxSize());
            Assert.assertEquals(PoolPolicy.fewestConnections, c.getReadWritePool().getPolicy());
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
        finally
        {
            System.clearProperty(PropertiesReader.class.getName() + ".dir");
        }
    }

    @Test
    public void testConfigEquals1()
    {
        try
        {
            System.setProperty(PropertiesReader.class.getName() + ".dir", "test/config");

            LdapConfig c1 = LdapConfig.getLdapConfig("testConfig1.properties");
            LdapConfig c2 = LdapConfig.getLdapConfig("testConfig1.properties");
            Assert.assertEquals(c1, c2);
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
        finally
        {
            System.clearProperty(PropertiesReader.class.getName() + ".dir");
        }
    }

    @Test
    public void testConfigEquals2()
    {
        try
        {
            System.setProperty(PropertiesReader.class.getName() + ".dir", "test/config");

            LdapConfig c1 = LdapConfig.getLdapConfig("testConfig2.properties");
            LdapConfig c2 = LdapConfig.getLdapConfig("testConfig2.properties");
            Assert.assertEquals(c1, c2);
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
        finally
        {
            System.clearProperty(PropertiesReader.class.getName() + ".dir");
        }
    }

    @Test
    public void testConfigNotEquals()
    {
        try
        {
            System.setProperty(PropertiesReader.class.getName() + ".dir", "test/config");

            LdapConfig c1 = LdapConfig.getLdapConfig("testConfig1.properties");
            LdapConfig c2 = LdapConfig.getLdapConfig("testConfig2.properties");
            Assert.assertTrue(!c1.equals(c2));
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
        finally
        {
            System.clearProperty(PropertiesReader.class.getName() + ".dir");
        }
    }

}
