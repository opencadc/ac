/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2025.                            (c) 2025.
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

package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.ac.json.JsonUserRequestWriter;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.HttpUpload;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Log4jInit;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class AddUserRequestIntTest
{
    private static final Logger log = Logger.getLogger(AddUserRequestIntTest.class);

    static URL userRequestServiceURL;
    static File authTest1File;

    Map<String, Object> params;

    @BeforeClass
    public static void before()
        throws Exception
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.reg", Level.INFO);

        URI umsServiceURI = new URI("ivo://cadc.nrc.ca/gms");
        RegistryClient regClient = new RegistryClient();
        userRequestServiceURL = regClient
            .getServiceURL(umsServiceURI, Standards.UMS_REQS_01, AuthMethod.CERT);
        log.info("postServiceUrl: " + userRequestServiceURL);
    }
    
    private String writeUserRequest(final UserRequest userRequest)
            throws IOException, WriterException
    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        JsonUserRequestWriter writer = new JsonUserRequestWriter();
        writer.write(userRequest, pw);

        return sw.toString();
    }
    
    private String getContentType()
    {
        return "application/json; charset=UTF-8";
    }  
    
    @Test
    public void testAddExistingUserID() throws Exception
    {
    	// create the new user
    	String username = "dn" + System.currentTimeMillis() + "1";
        final HttpPrincipal userID = new HttpPrincipal(username);
        String dn = "CN=" + username + ",OU=cadc,O=hia,C=ca";
        final X500Principal x500Principal = new X500Principal(dn);
    	User user = new User();
        user.getIdentities().add(userID);
        user.getIdentities().add(x500Principal);
        user.personalDetails = new PersonalDetails("add", "userRequest");
        user.personalDetails.email = username + "@canada.ca";
        UserRequest userRequest = new UserRequest(user, "12345678".toCharArray());
        String userString = writeUserRequest(userRequest);
        InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));
        
        Assert.assertNotNull(userRequestServiceURL);
        
        // add the new user to the UserRequest tree
        HttpUpload addNewUserRequest = new HttpUpload(in, new URL(userRequestServiceURL.toExternalForm()));
        addNewUserRequest.setRequestProperty("Accept", getContentType());
        addNewUserRequest.run();
        Assert.assertEquals(201, addNewUserRequest.getResponseCode());
        Assert.assertNull(addNewUserRequest.getThrowable());
        
        // attempt to add the user again
        in = new ByteArrayInputStream(userString.getBytes("UTF-8"));
        HttpUpload addExistingUserRequest = new HttpUpload(in, new URL(userRequestServiceURL.toExternalForm()));
        addExistingUserRequest.setRequestProperty("Accept", getContentType());
        addExistingUserRequest.run();
        Assert.assertEquals(409, addExistingUserRequest.getResponseCode());
    	Assert.assertNotNull("Failed to detect user with same user ID already exists", addExistingUserRequest.getThrowable());
    	String message = addExistingUserRequest.getThrowable().getMessage();
    	Assert.assertTrue(message.contains("user ") && message.contains(" found in "));
    }

    @Test
    public void testAddExistingEmailAddress() throws Exception
    {
    	// create the new user
    	String prefix = "dn1";
    	String suffix = System.currentTimeMillis() + "1";
    	String username = prefix + suffix;
        final HttpPrincipal userID = new HttpPrincipal(username);
    	User user = new User();
        user.getIdentities().add(userID);
        user.personalDetails = new PersonalDetails("add", "userRequest");
        user.personalDetails.email = username + "@canada.ca";
        UserRequest userRequest = new UserRequest(user, "12345678".toCharArray());
        String userString = writeUserRequest(userRequest);
        InputStream in = new ByteArrayInputStream(userString.getBytes("UTF-8"));
        
        Assert.assertNotNull(userRequestServiceURL);
        
        // add the new user to the UserRequest tree
        HttpUpload addNewUserRequest = new HttpUpload(in, new URL(userRequestServiceURL.toExternalForm()));
        addNewUserRequest.setRequestProperty("Accept", getContentType());
        addNewUserRequest.run();
        Assert.assertEquals(201, addNewUserRequest.getResponseCode());
        Assert.assertNull(addNewUserRequest.getThrowable());
        
        // attempt to add another user but with the same email address
        prefix = "dn2";
    	String newUsername = prefix + suffix;
        final HttpPrincipal newUserID = new HttpPrincipal(newUsername);
    	User newUser = new User();
        newUser.getIdentities().add(newUserID);
        newUser.personalDetails = new PersonalDetails("add", "userRequest");
        newUser.personalDetails.email = username + "@canada.ca";
        UserRequest newUserRequest = new UserRequest(newUser, "123456".toCharArray());
        String newUserString = writeUserRequest(newUserRequest);
        in = new ByteArrayInputStream(newUserString.getBytes("UTF-8"));
        HttpUpload addExistingUserRequest = new HttpUpload(in, new URL(userRequestServiceURL.toExternalForm()));
        addExistingUserRequest.setRequestProperty("Accept", getContentType());
        addExistingUserRequest.run();
        Assert.assertEquals(409, addExistingUserRequest.getResponseCode());
    	Assert.assertNotNull("Failed to detect user with same email address already exists", addExistingUserRequest.getThrowable());
    	String message = addExistingUserRequest.getThrowable().getMessage();
    	Assert.assertTrue(message.contains("email address ") && message.contains(" found in "));
    }
}
