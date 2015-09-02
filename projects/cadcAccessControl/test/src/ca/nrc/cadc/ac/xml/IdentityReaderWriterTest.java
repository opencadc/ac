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

import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import org.apache.log4j.Logger;
import org.jdom2.Element;
import org.junit.Test;

import javax.management.remote.JMXPrincipal;
import javax.security.auth.x500.X500Principal;
import java.security.Principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 *
 * @author jburke
 */
public class IdentityReaderWriterTest extends AbstractReaderWriter
{
    private static Logger log = Logger.getLogger(IdentityReaderWriterTest.class);

    @Test
    public void testReaderExceptions()
        throws Exception
    {
        Element element = null;
        try
        {
            Principal p = getPrincipal(element);
            fail("null element should throw ReaderException");
        }
        catch (ReaderException e) {}
         
        element = new Element("foo");
        try
        {
            Principal p = getPrincipal(element);
            fail("element not named 'identity' should throw ReaderException");
        }
        catch (ReaderException e) {}
         
        element = new Element("identity");
        try
        {
            Principal p = getPrincipal(element);
            fail("element without 'type' attribute should throw ReaderException");
        }
        catch (ReaderException e) {}
         
        element.setAttribute("type", "foo");
        try
        {
            Principal p = getPrincipal(element);
            fail("element with unknown 'type' attribute should throw ReaderException");
        }
        catch (ReaderException e) {}
    }
     
    @Test
    public void testWriterExceptions()
        throws Exception
    {
        Principal p = null;
        try
        {
            Element element = getElement(p);
            fail("null Identity should throw WriterException");
        }
        catch (WriterException e) {}
         
        p = new JMXPrincipal("foo");
        try
        {
            Element element = getElement(p);
            fail("Unsupported Principal type should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e) {}
    }
     
    @Test
    public void testReadWrite()
        throws Exception
    {
        // X500
        Principal expected = new X500Principal("cn=foo,o=bar");
        Element element = getElement(expected);
        assertNotNull(element);
         
        Principal actual = getPrincipal(element);
        assertNotNull(actual);
         
        assertEquals(expected, actual);

        // CADC
        expected = new NumericPrincipal(123l);
        element = getElement(expected);
        assertNotNull(element);
         
        actual = getPrincipal(element);
        assertNotNull(actual);
         
        assertEquals(expected, actual);
        
        // OpenID
        expected = new OpenIdPrincipal("bar");
        element = getElement(expected);
        assertNotNull(element);
         
        actual = getPrincipal(element);
        assertNotNull(actual);
         
        assertEquals(expected, actual);
        
        // HTTP
        expected = new HttpPrincipal("baz");
        element = getElement(expected);
        assertNotNull(element);
         
        actual = getPrincipal(element);
        assertNotNull(actual);
         
        assertEquals(expected, actual);
    }
    
}
