/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2016.                            (c) 2016.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.oidc;

import java.io.File;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.Subject;

import org.junit.Assert;
import org.junit.Test;
import org.opencadc.gms.GroupURI;

import ca.nrc.cadc.ac.server.oidc.RelyParty.Claim;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;


public class OIDCUtilTest
{

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", org.apache.log4j.Level.INFO);
    }
    
    @Test
    public void testGetRelyParty() throws Exception {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/config");
        System.setProperty("user.home", "src/test/config");

        // normal attributes
        String oidc = "client-id";
        String secret = "client-secret";
        GroupURI accessGroup = new GroupURI(URI.create("ivo://cadc.nrc.ca/gms?CADC_TEST1-Staff"));
        String description = "client description";
        List<Claim> claims = Arrays.asList(new Claim[] {RelyParty.Claim.NAME, RelyParty.Claim.EMAIL, RelyParty.Claim.GROUPS});
        boolean signDocuments = true;

        RelyParty actual = OIDCUtil.getRelyParty(oidc);
        Assert.assertEquals("Incorrect client ID", oidc, actual.getClientID());
        Assert.assertEquals("Incorrect client secret", secret, actual.getClientSecret());
        Assert.assertEquals("Incorrect client access group", accessGroup, actual.getAccessGroup());
        Assert.assertEquals("Incorrect client description", description, actual.getClientDescription());
        List<Claim> actualClaims = actual.getClaims();
        Assert.assertEquals("Incorrect number of claims", claims.size(), actualClaims.size());
        for (Claim claim : claims) {
            Assert.assertTrue("Claim " + claim + " is missing", actualClaims.contains(claim));
        }

        Assert.assertEquals("Incorrect signdocuments", signDocuments, actual.isSignDocuments());
        
        // One claim
        oidc = "client-id-1-claim";
        secret = "client-1-claim-secret";
        accessGroup = new GroupURI(URI.create("ivo://cadc.nrc.ca/gms?my-1-claim-group"));
        description = "client-1-claim description";
        claims = Arrays.asList(new Claim[] {RelyParty.Claim.EMAIL});
        signDocuments = false;

        actual = OIDCUtil.getRelyParty(oidc);
        Assert.assertEquals("Incorrect client ID", oidc, actual.getClientID());
        Assert.assertEquals("Incorrect client secret", secret, actual.getClientSecret());
        Assert.assertEquals("Incorrect client access group", accessGroup, actual.getAccessGroup());
        Assert.assertEquals("Incorrect client description", description, actual.getClientDescription());
        actualClaims = actual.getClaims();
        Assert.assertEquals("Incorrect number of claims", claims.size(), actualClaims.size());
        for (Claim claim : claims) {
            Assert.assertTrue("Claim " + claim + " is missing", actualClaims.contains(claim));
        }

        Assert.assertEquals("Incorrect signdocuments", signDocuments, actual.isSignDocuments());
        
        // No access group
        oidc = "client-id-no-access-group";
        secret = "client-no-access-group-secret";
        description = "client-no-access-group description";
        claims = Arrays.asList(new Claim[] {RelyParty.Claim.EMAIL});
        signDocuments = true;

        actual = OIDCUtil.getRelyParty(oidc);
        Assert.assertEquals("Incorrect client ID", oidc, actual.getClientID());
        Assert.assertEquals("Incorrect client secret", secret, actual.getClientSecret());
        Assert.assertNull("Client access group should be null", actual.getAccessGroup());
        Assert.assertEquals("Incorrect client description", description, actual.getClientDescription());
        actualClaims = actual.getClaims();
        Assert.assertEquals("Incorrect number of claims", claims.size(), actualClaims.size());
        for (Claim claim : claims) {
            Assert.assertTrue("Claim " + claim + " is missing", actualClaims.contains(claim));
        }

        Assert.assertEquals("Incorrect signdocuments", signDocuments, actual.isSignDocuments());
        
        // Empty access group
        oidc = "client-id-empty-access-group";
        secret = "client-empty-access-group-secret";
        description = "client-empty-access-group description";
        claims = Arrays.asList(new Claim[] {RelyParty.Claim.EMAIL});
        signDocuments = true;

        actual = OIDCUtil.getRelyParty(oidc);
        Assert.assertEquals("Incorrect client ID", oidc, actual.getClientID());
        Assert.assertEquals("Incorrect client secret", secret, actual.getClientSecret());
        Assert.assertNull("Client access group should be null", actual.getAccessGroup());
        Assert.assertEquals("Incorrect client description", description, actual.getClientDescription());
        actualClaims = actual.getClaims();
        Assert.assertEquals("Incorrect number of claims", claims.size(), actualClaims.size());
        for (Claim claim : claims) {
            Assert.assertTrue("Claim " + claim + " is missing", actualClaims.contains(claim));
        }

        Assert.assertEquals("Incorrect signdocuments", signDocuments, actual.isSignDocuments());
    }

    @Test
    public void testAccessAllowed() throws Exception {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/config");
        System.setProperty("user.home", "src/test/config");

        // case 1: no access group, should be allowed
        Assert.assertTrue("should be allowed, i.e. true", OIDCUtil.accessAllowed("client-id-no-access-group"));
        
        // case 2: Anonymous access not supported
        Assert.assertFalse("should not be allowed, i.e. false", OIDCUtil.accessAllowed("client-id-1-claim"));

        // case 3: subject is a member of the access group, should be allowed
        File auth1 = FileUtil.getFileFromResource("x509_CADCAuthtest1.pem", OIDCUtilTest.class);
        Subject subject = SSLUtil.createSubject(auth1);
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            @Override
            public Object run() throws Exception {
                Assert.assertTrue("should be allowed, i.e. true", OIDCUtil.accessAllowed("client-id"));
                return null;
            }
        });

        // case 4: subject is not a member of the access group, should not be allowed
        auth1 = FileUtil.getFileFromResource("x509_CADCRegtest1.pem", OIDCUtilTest.class);
        subject = SSLUtil.createSubject(auth1);
        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            @Override
            public Object run() throws Exception {
                Assert.assertFalse("should be allowed, i.e. true", OIDCUtil.accessAllowed("client-id"));
                return null;
            }
        });
    }
}
