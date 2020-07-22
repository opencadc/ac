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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.Date;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opencadc.gms.GroupURI;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.TestUtil;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import org.apache.log4j.Level;

/**
 *
 * @author jburke
 */
public class GroupReaderWriterTest
{
    private static Logger log = Logger.getLogger(GroupReaderWriterTest.class);

    private String ERROR_MSG_BASE = "should throw InvalidExceptionError";

    static {
        Log4jInit.setLevel(Group.class.getPackage().getName(), Level.INFO);
    }
    
    @BeforeClass
    public static void setupClass()
    {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
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
            GroupReader groupReader = new GroupReader();
            Group g = groupReader.read(s);
            fail("null String " + ERROR_MSG_BASE);
        }
        catch (IllegalArgumentException e) {}

        try
        {
            InputStream in = null;
            GroupReader groupReader = new GroupReader();
            Group g = groupReader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e) {}

        try
        {
            Reader r = null;
            GroupReader groupReader = new GroupReader();
            Group g = groupReader.read(r);
            fail("null element should throw ReaderException");
        }
        catch (IllegalArgumentException e) {}
    }

    @Test
    public void testWriterExceptions()
        throws Exception
    {
        try
        {
            GroupWriter groupWriter = new GroupWriter();
            groupWriter.write(null, new StringBuilder());
            fail("null Group should throw WriterException");
        }
        catch (WriterException e) {}
    }

    @Test
    public void testMinimalReadWrite()
        throws Exception
    {
        Group expected = new Group(new GroupURI("ivo://example.org/gms?groupID"));

        StringBuilder xml = new StringBuilder();
        GroupWriter groupWriter = new GroupWriter();
        groupWriter.write(expected, xml);
        assertFalse(xml.toString().isEmpty());

        GroupReader groupReader = new GroupReader();
        Group actual = groupReader.read(xml.toString());
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    public void testMaximalReadWrite()
        throws Exception
    {
        User owner = new User();
        X500Principal x500Principal = new X500Principal("cn=foo,o=bar");
        owner.getIdentities().add(x500Principal);
        owner.personalDetails = new PersonalDetails("foo", "bar");
        owner.personalDetails.address = "address";
        owner.personalDetails.email = "email";
        owner.personalDetails.institute = "institute";
        owner.personalDetails.city = "city";
        owner.personalDetails.country = "country";
        owner.posixDetails = new PosixDetails("foo", 123, 456, "/dev/null");

        Group expected = new Group(new GroupURI("ivo://example.org/gms?groupID"));
        setGroupOwner(expected, owner);
        expected.description = "description";
        expected.lastModified = new Date();
        expected.getProperties().add(new GroupProperty("key1", "value1", true));
        expected.getProperties().add(new GroupProperty("key2", "value2", false));

        Group groupMember = new Group(new GroupURI("ivo://example.org/gms?member"));
        User userMember = new User();
        userMember.getIdentities().add(new HttpPrincipal("foo"));
        URI memberUri = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        TestUtil.setField(userMember, new InternalID(memberUri), AbstractReaderWriter.ID);

        Group groupAdmin = new Group(new GroupURI("ivo://example.org/gms?admin"));
        User userAdmin = new User();
        userAdmin.getIdentities().add(new HttpPrincipal("bar"));
        URI adminUri = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        TestUtil.setField(userAdmin, new InternalID(adminUri), AbstractReaderWriter.ID);

        expected.getGroupMembers().add(groupMember);
        expected.getUserMembers().add(userMember);
        expected.getGroupAdmins().add(groupAdmin);
        expected.getUserAdmins().add(userAdmin);

        StringBuilder xml = new StringBuilder();
        GroupWriter groupWriter = new GroupWriter();
        groupWriter.write(expected, xml);
        assertFalse(xml.toString().isEmpty());

        GroupReader groupReader = new GroupReader();
        Group actual = groupReader.read(xml.toString());
        assertNotNull(actual);
        assertEquals(expected, actual);
        assertEquals(expected.description, actual.description);
        assertEquals(expected.lastModified, actual.lastModified);
        assertEquals(expected.getProperties(), actual.getProperties());
        assertTrue(expected.getGroupMembers().containsAll(actual.getGroupMembers()));
        assertTrue(actual.getGroupMembers().containsAll(expected.getGroupMembers()));
        assertTrue(expected.getUserMembers().containsAll(actual.getUserMembers()));
        assertTrue(actual.getUserMembers().containsAll(expected.getUserMembers()));
    }

    private void setGroupOwner(Group group, User owner)
    {
        // set private uri field using reflection
        try
        {
            Field field = group.getClass().getDeclaredField("owner");
            field.setAccessible(true);
            field.set(group, owner);
        }
        catch (NoSuchFieldException e)
        {
            throw new RuntimeException("Group owner field not found", e);
        }
        catch (IllegalAccessException e)
        {
            throw new RuntimeException("unable to update Group owner field", e);
        }
    }

}
