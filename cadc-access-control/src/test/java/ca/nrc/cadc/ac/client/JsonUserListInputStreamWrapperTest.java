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
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.client;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
import ca.nrc.cadc.ac.json.JsonUserListWriter;
import ca.nrc.cadc.ac.xml.AbstractReaderWriter;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;


public class JsonUserListInputStreamWrapperTest
{
    private static final Logger log = Logger.getLogger(JsonUserListInputStreamWrapperTest.class);

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
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
    public void readInputStream() throws Exception
    {
        final List<User> output = new ArrayList<User>();
        final JsonUserListInputStreamWrapper testSubject =
                new JsonUserListInputStreamWrapper(output);
        final JsonUserListWriter userListWriter = new JsonUserListWriter();
        final Writer writer = new StringWriter();
        final Collection<User> users = new ArrayList<User>();

        final User user1 = new User();
        URI uri1 = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        InternalID id1 = new InternalID(uri1);
        TestUtil.setField(user1, id1, AbstractReaderWriter.ID);
        users.add(user1);

        final User user2 = new User();
        URI uri2 = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        InternalID id2 = new InternalID(uri2);
        TestUtil.setField(user2, id2, AbstractReaderWriter.ID);
        user2.personalDetails = new PersonalDetails("firstname", "lastname");
        users.add(user2);

        userListWriter.write(users, writer);
        String json = writer.toString();
        log.debug("user:\n" + json);

        final InputStream inputStream = new ByteArrayInputStream(json.getBytes());

        testSubject.read(inputStream);

        assertEquals("First item is wrong.", id1, output.get(0).getID());
        assertEquals("Second item is wrong.", id2, output.get(1).getID());
    }
}
