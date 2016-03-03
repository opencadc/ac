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
package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.TestUtil;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.util.Log4jInit;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * @author jburke
 */
public class JsonGroupReaderWriterTest
{
    private static Logger log = Logger.getLogger(JsonGroupReaderWriterTest.class);

    @BeforeClass
    public static void setUpClass()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac.json", Level.INFO);
    }

    @Test
    public void testReaderExceptions() throws Exception
    {
        try
        {
            String s = null;
            JsonGroupReader reader = new JsonGroupReader();
            Group g = reader.read(s);
            fail("null String should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
        }

        try
        {
            InputStream in = null;
            JsonGroupReader reader = new JsonGroupReader();
            Group g = reader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e)
        {
        }

        try
        {
            Reader r = null;
            JsonGroupReader reader = new JsonGroupReader();
            Group g = reader.read(r);
            fail("null element should throw ReaderException");
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    @Test
    public void testWriterExceptions()
            throws Exception
    {
        try
        {
            JsonGroupWriter writer = new JsonGroupWriter();
            writer.write(null, new StringBuilder());
            fail("null Group should throw WriterException");
        }
        catch (WriterException e)
        {
        }
    }

    @Test
    public void testMinimalReadWrite()
            throws Exception
    {
        Group expected = new Group("groupID");

        StringBuilder json = new StringBuilder();
        JsonGroupWriter writer = new JsonGroupWriter();
        writer.write(expected, json);
        assertFalse(json.toString().isEmpty());

        JsonGroupReader reader = new JsonGroupReader();
        Group actual = reader.read(json.toString());
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    public void testMaximalReadWrite()
            throws Exception
    {
        User owner = new User();
        UUID uuid = UUID.randomUUID();
        URI uri = new URI("ivo://cadc.nrc.ca/user?" +uuid);
        TestUtil.setInternalID(owner, new InternalID(uri));

        X500Principal x500Principal = new X500Principal("cn=foo,o=bar");
        owner.getIdentities().add(x500Principal);
        PersonalDetails personalDetails = new PersonalDetails("foo", "bar");
        personalDetails.address = "address";
        personalDetails.email = "email";
        personalDetails.institute = "institute";
        personalDetails.city = "city";
        personalDetails.country = "country";
        owner.personalDetails = personalDetails;
        PosixDetails posixDetails = new PosixDetails("foo", 123L, 456L, "/dev/null");
        owner.posixDetails = posixDetails;

        Group expected = new Group("groupID", owner);
        expected.description = "description";
        expected.lastModified = new Date();
        expected.getProperties().add(new GroupProperty("key1", "value1", true));
        expected.getProperties().add(new GroupProperty("key2", "value2", true));
        expected.getProperties().add(new GroupProperty("key3", "value3", true));

        Group groupMember = new Group("member", new User());
        User userMember = new User();
        URI memberUri = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        TestUtil.setInternalID(userMember, new InternalID(memberUri));
        Group groupAdmin = new Group("admin", new User());
        User userAdmin = new User();
        URI adminUri = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        TestUtil.setInternalID(userAdmin, new InternalID(adminUri));

        expected.getGroupMembers().add(groupMember);
        expected.getUserMembers().add(userMember);
        expected.getGroupAdmins().add(groupAdmin);
        expected.getUserAdmins().add(userAdmin);

        JsonGroupWriter writer = new JsonGroupWriter();
        StringBuilder sb = new StringBuilder();
        writer.write(expected, sb);

        String json = sb.toString();
        log.debug(json);

        JsonGroupReader reader = new JsonGroupReader();
        Group actual = reader.read(json);

        // Sort them so the tests work in Java 8.
        // (List implementation changed)
        final List<GroupProperty> sortedExpectedProperties =
                new ArrayList<GroupProperty>(expected.getProperties());
        final List<GroupProperty> sortedActualProperties =
                new ArrayList<GroupProperty>(actual.getProperties());

        Collections.sort(sortedExpectedProperties,
                         new GroupPropertyComparator());
        Collections.sort(sortedActualProperties, new GroupPropertyComparator());

        assertNotNull(actual);
        assertEquals(expected, actual);
        assertEquals(expected.description, actual.description);
        assertEquals(expected.lastModified, actual.lastModified);
        assertEquals("Properties don't match.", sortedExpectedProperties,
                     sortedActualProperties);
        assertEquals(expected.getGroupMembers(), actual.getGroupMembers());
        assertEquals(expected.getUserMembers(), actual.getUserMembers());
    }

    class GroupPropertyComparator implements Comparator<GroupProperty>
    {
        @Override
        public int compare(GroupProperty o1, GroupProperty o2)
        {
            final int keyComp = o1.getKey()
                    .compareTo(o2.getKey());
            final int result;

            if (keyComp == 0)
            {
                result = o1.getValue().toString().compareTo(
                        o2.getValue().toString());
            }
            else
            {
                result = keyComp;
            }

            return result;
        }
    }
}
