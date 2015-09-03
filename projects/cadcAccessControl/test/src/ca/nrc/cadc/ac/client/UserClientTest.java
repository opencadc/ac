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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;

import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.AC;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Log4jInit;

import org.junit.Assert;
import org.junit.Test;


public class UserClientTest
{
    
    private static final Logger log = Logger.getLogger(UserClientTest.class);
    
    public UserClientTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);
    }


    @Test
    public void testConstructor()
    {
    	// case 1: test construction with a null URL
        try
        {
            new UserClient(null);            
            Assert.fail("Null base URL should throw an illegalArgumentException.");
        }
        catch (IllegalArgumentException iae)
        {
            Assert.assertEquals("baseURL is required", iae.getMessage());
        }
        catch (Throwable t)
        {
        	Assert.fail("Unexpected exception: " + t.getMessage());
        }
        
        // case 2: test construction with a malformed URL
        try
        {
            new UserClient("noSuchProtocol://localhost");            
            Assert.fail("Malformed URL should throw an illegalArgumentException.");
        }
        catch (IllegalArgumentException iae)
        {
            Assert.assertTrue("Expecting 'URL is malformed'", 
            		iae.getMessage().contains("URL is malformed"));
        }
        catch (Throwable t)
        {
        	Assert.fail("Unexpected exception: " + t.getMessage());
        }
    }
    
    @Test
    public void testSubjectWithNoPrincipal()
    {
    	try
    	{
	        // test subject augmentation given a subject with no principal
	    	Subject subject = new Subject();
	    	this.createUserClient().augmentSubject(subject);
	    	Assert.assertEquals("Should have no principal.", 0, subject.getPrincipals().size());
    	}
    	catch(Throwable t)
    	{
    		Assert.fail("Unexpected exception: " + t.getMessage());
    	}
    }
    
    @Test
    public void testSubjectWithMultiplePrincipal() 
    {
        try
        {
            // test subject augmentation given a subject with more than one principal
            Subject subject = new Subject();
            subject.getPrincipals().add(new NumericPrincipal(4));
            subject.getPrincipals().add(new HttpPrincipal("cadcauthtest1"));
            this.createUserClient().augmentSubject(subject);
            Assert.fail("Expecting an IllegalArgumentException.");
        }
        catch(IllegalArgumentException e)
        {
            String expected = "Subject has more than one principal.";
            Assert.assertEquals(expected, e.getMessage());
        }
    	catch(Throwable t)
    	{
    		Assert.fail("Unexpected exception: " + t.getMessage());
    	}
    }
    
    @Test
    public void testSubjectWithUnsupportedPrincipal() 
    {
    	Principal principal = new JMXPrincipal("APIName");
        try
        {
            // test subject augmentation given a subject with more than one principal
            Subject subject = new Subject();
            subject.getPrincipals().add(principal);
            this.createUserClient().augmentSubject(subject);
            Assert.fail("Expecting an IllegalArgumentException.");
        }
        catch(IllegalArgumentException e)
        {
            String expected = "Subject has unsupported principal " + principal.getName();
            Assert.assertEquals(expected, e.getMessage());
        }
    	catch(Throwable t)
    	{
    		Assert.fail("Unexpected exception: " + t.getMessage());
    	}
    }
   
    protected UserClient createUserClient() throws URISyntaxException, MalformedURLException
    {
    	RegistryClient regClient = new RegistryClient();
    	URI serviceURI = new URI(AC.GMS_SERVICE_URI);
    	URL baseURL = regClient.getServiceURL(serviceURI, "https");
    	return new UserClient(baseURL.toString());

    }
}
