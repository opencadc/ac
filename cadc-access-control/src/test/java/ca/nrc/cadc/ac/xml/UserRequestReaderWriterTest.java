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
package ca.nrc.cadc.ac.xml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URI;
import java.util.UUID;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.TestUtil;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import javax.security.auth.x500.X500Principal;

/**
 *
 * @author jburke
 */
public class UserRequestReaderWriterTest
{
    private static Logger log = Logger.getLogger(UserRequestReaderWriterTest.class);

    public UserRequestReaderWriterTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @BeforeClass
    public static void setupClass()
    {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
        System.out.println("set config dir to: " + System.getProperty(PropertiesReader.class.getName() + ".dir"));
    }

    @AfterClass
    public static void teardownClass()
    {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    @Test
    public void testReaderExceptions()
        throws Exception
    {
        try
        {
            String s = null;
            UserRequestReader userRequestReader = new UserRequestReader();
            UserRequest u = userRequestReader.read(s);
            fail("null String should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e) {}

        try
        {
            InputStream in = null;
            UserRequestReader userRequestReader = new UserRequestReader();
            UserRequest u = userRequestReader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e) {}

        try
        {
            Reader r = null;
            UserRequestReader userRequestReader = new UserRequestReader();
            UserRequest u = userRequestReader.read(r);
            fail("null Reader should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e) {}
    }

    @Test
    public void testWriterExceptions()
        throws Exception
    {
        try
        {
            UserRequestWriter userRequestWriter = new UserRequestWriter();
            userRequestWriter.write(null, new StringBuilder());
            fail("null UserRequest should throw WriterException");
        }
        catch (WriterException e) {}
    }

    @Test
    public void testReadWrite()
        throws Exception
    {
        User expectedUser = new User();
        UUID uuid = UUID.randomUUID();
        URI uri = new URI("ivo://cadc.nrc.ca/user?" + uuid);
        TestUtil.setField(expectedUser, new InternalID(uri), AbstractReaderWriter.ID);

        expectedUser.getIdentities().add(new NumericPrincipal(uuid));
        expectedUser.personalDetails = new PersonalDetails("firstname", "lastname");

        char[] expectedPassword = "123456".toCharArray();

        UserRequest expected =
            new UserRequest(expectedUser, expectedPassword);

        StringBuilder xml = new StringBuilder();
        UserRequestWriter userRequestWriter = new UserRequestWriter();
        userRequestWriter.write(expected, xml);
        assertFalse(xml.toString().isEmpty());
        
        UserRequestReader userRequestReader = new UserRequestReader();
        UserRequest actual = userRequestReader.read(xml.toString());
        assertNotNull(actual);
        assertEquals(expected.getUser(), actual.getUser());
        assertEquals(String.valueOf(expected.getPassword()),
                     String.valueOf(actual.getPassword()));
    }
    
    @Test
    public void testReadWriteX()
        throws Exception
    {
        User u = new User();
        u.personalDetails = new PersonalDetails("Patrick", "Dowler");
        u.getIdentities().add(new X500Principal("cn=patrick dowler,ou=nrc-cnrc.gc.ca,o=grid,c=ca"));

        char[] p = "scallyWaG".toCharArray();

        UserRequest expected = new UserRequest(u, p);

        StringBuilder xml = new StringBuilder();
        UserRequestWriter w = new UserRequestWriter();
        w.write(expected, xml);
        
        log.info("req:\n" + xml);
    }

}
