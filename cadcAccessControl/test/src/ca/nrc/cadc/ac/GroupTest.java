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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.log4j.Logger;
import org.junit.Test;

import ca.nrc.cadc.auth.HttpPrincipal;

public class GroupTest
{
    private static Logger log = Logger.getLogger(GroupTest.class);
    
    @Test
    public void simpleGroupTest() throws Exception
    {
        Group group1 = new Group("TestGroup");
        Group group2 = group1;
        assertEquals(group1.hashCode(), group2.hashCode());
        assertEquals(group1, group2);
        assertTrue(group1 == group2);
        
        User<HttpPrincipal> owner = new User<HttpPrincipal>(new HttpPrincipal("owner"));
        Group group3 = new Group("TestGroup", owner);
        User<HttpPrincipal> user = new User<HttpPrincipal>(new HttpPrincipal("user"));
        
        group3.getUserMembers().add(user);
        assertEquals(1, group3.getUserMembers().size());

        Group group4 = group3;
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3, group4);
        assertTrue(group3 == group4);
        
        group4 = new Group("TestGroup", owner);
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3,group4);
        
        group4.getUserMembers().add(user);
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3,group4);
        
        group3.getGroupMembers().add(group4);
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3,group4);
        
        group4.getUserAdmins().add(user);
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3,group4);
        
        group3.getGroupAdmins().add(group4);
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3,group4);
        
        group3.description = "Test group";
        assertEquals(group3.hashCode(), group4.hashCode());
        assertEquals(group3,group4);
        
        group4 = new Group("NewTestGroup-._~.", owner);
        assertFalse(group3.hashCode() == group4.hashCode());
        assertFalse(group3.equals(group4));
        
        // test toString
        System.out.println(group3);
    }
    
    @Test
    public void exceptionTests()
    {
        boolean thrown = false;
        try
        {
            new Group(null, new User<HttpPrincipal>(new HttpPrincipal("owner")));
        }
        catch(IllegalArgumentException e)
        {
            thrown = true;
        }
        assertTrue(thrown);
        
        
        thrown = false;
        try
        {
            new Group("NewTestGroup", null);
            thrown = true;
        }
        catch(IllegalArgumentException e)
        {
            fail("Owner can be null");
        }
        assertTrue(thrown);
        
        // invavlid group IDs
        thrown = false;
        try
        {
            new Group("New/Test/Group", new User<HttpPrincipal>(new HttpPrincipal("owner")));
        }
        catch(IllegalArgumentException e)
        {
            thrown = true;
        }
        assertTrue(thrown);
        
        thrown = false;
        try
        {
            new Group("New%Test%Group", new User<HttpPrincipal>(new HttpPrincipal("owner")));
        }
        catch(IllegalArgumentException e)
        {
            thrown = true;
        }
        assertTrue(thrown);
        
        thrown = false;
        try
        {
            new Group("New\\Test\\Group", new User<HttpPrincipal>(new HttpPrincipal("owner")));
        }
        catch(IllegalArgumentException e)
        {
            thrown = true;
        }
        assertTrue(thrown);
    }
    
}
