/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2022.                            (c) 2022.
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

package org.opencadc.gms;

import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import java.io.File;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.Subject;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author pdowler
 */
public class IvoaGroupClientTest {
    private static final Logger log = Logger.getLogger(IvoaGroupClientTest.class);

    static {
        Log4jInit.setLevel("org.opencadc.gms", Level.INFO);
    }
    
    Subject subject;
    
    public IvoaGroupClientTest() throws Exception { 
        String certFilename = System.getProperty("user.name") + ".pem";
        File pem = FileUtil.getFileFromResource(certFilename, IvoaGroupClientTest.class);
        this.subject = SSLUtil.createSubject(pem);
    }
    
    @Test
    public void testGetMembershipsAll() throws Exception {
        final IvoaGroupClient gms = new IvoaGroupClient();
        final URI resourceID = URI.create("ivo://cadc.nrc.ca/gms");
        
        List<GroupURI> groups = Subject.doAs(subject, (PrivilegedExceptionAction<List<GroupURI>>) () -> {
            return gms.getMemberships(resourceID);
        });
        
        Assert.assertNotNull(groups);
        for (GroupURI u : groups) {
            log.info("member: " + u);
        }
        Assert.assertFalse(groups.isEmpty());
    }
    
    @Test
    public void testGetMembershipsSubset() throws Exception {
        final IvoaGroupClient gms = new IvoaGroupClient();
        
        URI resourceID = URI.create("ivo://cadc.nrc.ca/gms");
        GroupURI g1 = new GroupURI(resourceID, "CADC");
        GroupURI g2 = new GroupURI(resourceID, "no-such-group");
        GroupURI g3 = new GroupURI(resourceID, "CAOM2");
        final List<GroupURI> in = new ArrayList<>();
        in.add(g1);
        in.add(g2);
        in.add(g3);
        
        List<GroupURI> groups = Subject.doAs(subject, (PrivilegedExceptionAction<List<GroupURI>>) () -> {
            return gms.getMemberships(in);
        });
        
        Assert.assertNotNull(groups);
        for (GroupURI u : groups) {
            log.info("member: " + u);
        }
        Assert.assertTrue(groups.contains(g1));
        Assert.assertFalse(groups.contains(g2));
        Assert.assertTrue(groups.contains(g3));
        Assert.assertEquals(2, groups.size());
    }
    
    @Test
    public void testIsMember() throws Exception {
        final IvoaGroupClient gms = new IvoaGroupClient();
        final URI resourceID = URI.create("ivo://cadc.nrc.ca/gms");
        GroupURI g1 = new GroupURI(resourceID, "CADC");
        GroupURI g2 = new GroupURI(resourceID, "no-such-group");
        
        boolean m1 = Subject.doAs(subject, (PrivilegedExceptionAction<Boolean>) () -> {
            return gms.isMember(g1);
        });
        Assert.assertTrue("member of " + g1, m1);
        
        boolean m2 = Subject.doAs(subject, (PrivilegedExceptionAction<Boolean>) () -> {
            return gms.isMember(g2);
        });
        Assert.assertFalse("member of " + g2, m2);
    }
}
