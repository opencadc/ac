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

package ca.nrc.cadc.ac;

import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import org.apache.log4j.Logger;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UserTest
{
    private static Logger log = Logger.getLogger(UserTest.class);

    @Test
    public void simpleEqualityTests() throws Exception
    {

        User user1 = new User();

        // set InternalID
        URI uri = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        InternalID internalID = new InternalID(uri);
        TestUtil.setInternalID(user1, internalID);
        assertEquals(user1.getID(), internalID);

        User user2 = user1;
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        user1.personalDetails = new PersonalDetails("Joe", "Raymond");
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());

        user1.posixDetails = new PosixDetails("jray", 12, 23, "/home/jray");
        assertEquals(user1, user2);
        assertEquals(user1.hashCode(), user2.hashCode());
    }

    @Test
    public void comparatorTest() throws Exception
    {
        User user = new User();
        boolean result = false;

        // HttpPrincipal
        HttpPrincipal httpPrincipal1 = new HttpPrincipal("foo");
        HttpPrincipal httpPrincipal2 = new HttpPrincipal("bar");

        result = user.getIdentities().add(httpPrincipal1);
        assertTrue(result);
        result = user.getIdentities().add(httpPrincipal1);
        assertFalse(result);

        result = user.getIdentities().add(httpPrincipal2);
        assertFalse(result);

        // X500Principal
        X500Principal x500Principal1 = new X500Principal("cn=foo,c=bar");
        X500Principal x500Principal2 = new X500Principal("cn=bar,c=foo");

        result = user.getIdentities().add(x500Principal1);
        assertTrue(result);
        result = user.getIdentities().add(x500Principal1);
        assertFalse(result);

        result = user.getIdentities().add(x500Principal2);
        assertTrue(result);
        result = user.getIdentities().add(x500Principal2);
        assertFalse(result);

        // NumericPrincipal
        NumericPrincipal numericPrincipal1 = new NumericPrincipal(UUID.randomUUID());
        NumericPrincipal numericPrincipal2 = new NumericPrincipal(UUID.randomUUID());

        result = user.getIdentities().add(numericPrincipal1);
        assertTrue(result);
        result = user.getIdentities().add(numericPrincipal1);
        assertFalse(result);

        result = user.getIdentities().add(numericPrincipal2);
        assertTrue(result);
        result = user.getIdentities().add(numericPrincipal2);
        assertFalse(result);

        // DNPrincipal
        DNPrincipal dnPrincipal1 = new DNPrincipal("cn=foo,dc=bar");
        DNPrincipal dnPrincipal2 = new DNPrincipal("cn=bar,dc=foo");

        result = user.getIdentities().add(dnPrincipal1);
        assertTrue(result);
        result = user.getIdentities().add(dnPrincipal1);
        assertFalse(result);

        result = user.getIdentities().add(dnPrincipal2);
        assertTrue(result);
        result = user.getIdentities().add(dnPrincipal2);
        assertFalse(result);
    }

}
