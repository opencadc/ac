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

package ca.nrc.cadc.ac.client;

import java.net.URI;
import java.net.URL;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.ac.AC;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Log4jInit;

public class GMSClientTest
{
    
    private static final Logger log = Logger.getLogger(GMSClientTest.class);
    
    public GMSClientTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }
    
    @Test
    public void testUserIsSubject()
    {
        try
        {
            Subject subject = new Subject();
            HttpPrincipal userID = new HttpPrincipal("test");
            HttpPrincipal userID2 = new HttpPrincipal("test2");
            subject.getPrincipals().add(userID);
            
            RegistryClient regClient = new RegistryClient();
            URL baseURL = regClient.getServiceURL(new URI(AC.GMS_SERVICE_URI));
            GMSClient client = new GMSClient(baseURL.toString());

            Assert.assertFalse(client.userIsSubject(null, null));
            Assert.assertFalse(client.userIsSubject(userID, null));
            Assert.assertFalse(client.userIsSubject(null, subject));
            Assert.assertFalse(client.userIsSubject(userID2, subject));
            Assert.assertTrue(client.userIsSubject(userID, subject));
            
            HttpPrincipal userID3 = new HttpPrincipal("test3");
            subject.getPrincipals().add(userID3);
            
            Assert.assertTrue(client.userIsSubject(userID, subject));
            Assert.assertFalse(client.userIsSubject(userID2, subject));
            Assert.assertTrue(client.userIsSubject(userID3, subject));
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
    }
    
    @Test
    public void testGroupCaching()
    {
        try
        {
            Subject subject = new Subject();
            final HttpPrincipal userID = new HttpPrincipal("test");
            subject.getPrincipals().add(userID);

            Subject.doAs(subject, new PrivilegedExceptionAction<Object>()
                {
                    @Override
                    public Object run() throws Exception
                    {
                        RegistryClient regClient = new RegistryClient();
                        URL baseURL = regClient.getServiceURL(new URI(AC.GMS_SERVICE_URI));
                        GMSClient client = new GMSClient(baseURL.toString());

                        List<Group> initial = client.getCachedGroups(userID, Role.MEMBER);
                        Assert.assertNull("Cache should be null", initial);

                        List<Group> expected = new ArrayList<Group>();
                        Group group1 = new Group("1");
                        Group group2 = new Group("2");
                        expected.add(group1);
                        expected.add(group2);

                        client.setCachedGroups(userID, expected, Role.MEMBER);

                        List<Group> actual = client.getCachedGroups(userID, Role.MEMBER);
                        Assert.assertEquals("Wrong cached groups", expected, actual);
                        
                        // check against another role
                        actual = client.getCachedGroups(userID, Role.OWNER);
                        Assert.assertNull("Cache should be null", actual);
                        
                        // check against another userid
                        final HttpPrincipal userID2 = new HttpPrincipal("test2");
                        actual = client.getCachedGroups(userID2, Role.MEMBER);
                        Assert.assertNull("Cache should be null", actual);

                        return null;
                    }
                });

            // do the same without a subject
            RegistryClient regClient = new RegistryClient();
            URL baseURL = regClient.getServiceURL(new URI(AC.GMS_SERVICE_URI));
            GMSClient client = new GMSClient(baseURL.toString());

            List<Group> initial = client.getCachedGroups(userID, Role.MEMBER);
            Assert.assertNull("Cache should be null", initial);

            List<Group> newgroups = new ArrayList<Group>();
            Group group1 = new Group("1");
            Group group2 = new Group("2");
            newgroups.add(group1);
            newgroups.add(group2);

            client.setCachedGroups(userID, newgroups, Role.MEMBER);

            List<Group> actual = client.getCachedGroups(userID, Role.MEMBER);
            Assert.assertNull("Cache should still be null", actual);
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
    }

}
