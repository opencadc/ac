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
 *  $Revision: 5 $
 *
 ************************************************************************
 */

package org.opencadc.permissions.xml;

import ca.nrc.cadc.util.Log4jInit;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.util.Date;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.opencadc.gms.GroupURI;
import org.opencadc.permissions.Grant;
import org.opencadc.permissions.ReadGrant;
import org.opencadc.permissions.WriteGrant;

public class GrantReaderWriterTest {

    private static final Logger log = Logger.getLogger(GrantReaderWriterTest.class);

    static {
        Log4jInit.setLevel("package org.opencadc.inventory.permissions.xml", Level.INFO);
    }

    public GrantReaderWriterTest() {
    }

    @Test
    public void testMinimalReadGrant() {
        try {
            ReadGrant expected = new ReadGrant(URI.create("ivo:foo/bar"), new Date(), true);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            GrantWriter writer = new GrantWriter();
            writer.write(expected, bos);

            String xml = bos.toString();
            log.info("xml:\n" + xml);

            GrantReader reader = new GrantReader();
            Grant actual = reader.read(xml);

            Assert.assertTrue(actual instanceof ReadGrant);

            Assert.assertEquals(expected.getAssetID(), actual.getAssetID());
            Assert.assertEquals(expected.getExpiryDate(), actual.getExpiryDate());
            Assert.assertEquals(expected.isAnonymousAccess(), ((ReadGrant) actual).isAnonymousAccess());
            Assert.assertTrue(actual.getGroups().isEmpty());

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testMinimalWriteGrant() {
        try {
            WriteGrant expected = new WriteGrant(URI.create("ivo://foo/bar"), new Date());

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            GrantWriter writer = new GrantWriter();
            writer.write(expected, bos);

            String xml = bos.toString();
            log.info("xml:\n" + xml);

            GrantReader reader = new GrantReader();
            Grant actual = reader.read(xml);

            Assert.assertTrue(actual instanceof WriteGrant);

            Assert.assertEquals(expected.getAssetID(), actual.getAssetID());
            Assert.assertEquals(expected.getExpiryDate(), actual.getExpiryDate());
            Assert.assertTrue(actual.getGroups().isEmpty());

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testReadGrantRoundTrip() {
        try {
            ReadGrant expected = new ReadGrant(URI.create("ivo:foo/bar"), new Date(), true);
            expected.getGroups().add(new GroupURI(URI.create("ivo://foo.com/bar?group1")));
            expected.getGroups().add(new GroupURI(URI.create("ivo://foo.com/bar?group2")));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            GrantWriter writer = new GrantWriter();
            writer.write(expected, bos);

            String xml = bos.toString();
            log.info("xml:\n" + xml);
            System.out.println("xml:\n" + xml);

            GrantReader reader = new GrantReader();
            ReadGrant actual = (ReadGrant) reader.read(xml);

            Assert.assertEquals(expected.getAssetID(), actual.getAssetID());
            Assert.assertEquals(expected.getExpiryDate(), actual.getExpiryDate());
            Assert.assertEquals(expected.isAnonymousAccess(), actual.isAnonymousAccess());
            Assert.assertEquals(expected.getGroups().size(), actual.getGroups().size());

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testWriteGrantRoundTrip() {
        try {
            WriteGrant expected = new WriteGrant(URI.create("ivo:foo/bar"), new Date());
            expected.getGroups().add(new GroupURI(URI.create("ivo://foo.com/bar?group1")));
            expected.getGroups().add(new GroupURI(URI.create("ivo://foo.com/bar?group2")));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            GrantWriter writer = new GrantWriter();
            writer.write(expected, bos);

            String xml = bos.toString();
            log.info("xml:\n" + xml);

            GrantReader reader = new GrantReader();
            WriteGrant actual = (WriteGrant) reader.read(xml);

            Assert.assertEquals(expected.getAssetID(), actual.getAssetID());
            Assert.assertEquals(expected.getExpiryDate(), actual.getExpiryDate());
            Assert.assertEquals(expected.getGroups().size(), actual.getGroups().size());

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

}
