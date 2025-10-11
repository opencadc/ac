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
 ************************************************************************
 */
package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.ac.server.oidc.OIDCUtil;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;


/**
 * @author majorb
 *
 */
public class OIDCIntTests {

    private static final Logger log = Logger.getLogger(OIDCIntTests.class);
    
    private static final String clientID = "arbutus-harbor";
    private static final String clientSecret = "harbor-secret";
    
    URL authorizeURL;
    URL tokenURL;
    URL publicKeyURL;
    URL userInfoURL;
    
    public OIDCIntTests() throws Exception {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.ac.integration", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.ac.server.oidc", Level.INFO);

        RegistryClient rc = new RegistryClient();
        URL authURL = rc.getServiceURL(URI.create(TestUtil.AC_SERVICE_ID), Standards.SECURITY_METHOD_OAUTH, AuthMethod.CERT);
        // find the OIDC config booktrap from the authURL
        int lastSlashIndex = authURL.toString().lastIndexOf("/");
        String oidcConfigURL = authURL.toString().substring(0, lastSlashIndex) + "/.well-known/openid-configuration";
        log.debug("getting oidc config from: " + oidcConfigURL);
        
        OutputStream out = new ByteArrayOutputStream();
        HttpGet get = new HttpGet(new URL(oidcConfigURL), out);
        get.run();
        
        JSONObject doc = new JSONObject(out.toString());
        authorizeURL = new URL(doc.getString("authorization_endpoint"));
        tokenURL = new URL(doc.getString("token_endpoint"));
        publicKeyURL = new URL(doc.getString("jwks_uri"));
        userInfoURL = new URL(doc.getString("userinfo_endpoint"));
        
        log.debug("authorize url: " + authorizeURL);
        log.debug("token url: " + tokenURL);
        log.debug("public key url: " + publicKeyURL);
        log.debug("user info url: " + userInfoURL);
    }
    //---------- Functions for testing and validating HTTP call output quality
    // This section includes functions that test specific fields returned from
    // code cadc-access-control-server/OIDCUtil.java and TokenAction.java

    private void testDocReturn(JSONObject doc) {

        // These values are generated in TokenAction.java
        String accessToken = doc.getString("access_token");
        String nextRefreshToken = doc.getString("refresh_token");
        String tokenType = doc.getString("token_type");
        String expiresIn = doc.getString("expires_in");
        String newIdToken = doc.getString("id_token");
        log.debug("access_token: " + accessToken);
        log.debug("refresh_token: " + nextRefreshToken);
        log.debug("token_type: " + tokenType);
        log.debug("expires_in: " + expiresIn);
        log.debug("id_token: " + newIdToken);
        Assert.assertNotNull(accessToken);
        Assert.assertNotNull(nextRefreshToken);
        Assert.assertNotNull(tokenType);
        Assert.assertNotNull(expiresIn);
        Assert.assertNotNull(newIdToken);
    }

    private String[] splitToken(String encodedToken) {
        // This reflects the expected structure of a JWT
        String[] parts = encodedToken.split("\\.");
        Assert.assertTrue(parts.length == 3);
        return parts;
    }

    private void testClaimContent(JSONObject claimsJSON, String issuerURL) {

        // These values are generated in OIDCUtil.java
        log.debug("issuerURL (iss): " + issuerURL + ": (" + claimsJSON.getString("iss") + ")");
        Assert.assertTrue(issuerURL.startsWith(claimsJSON.getString("iss")));
        log.debug("aud: " + claimsJSON.getString("aud"));
        Assert.assertEquals(clientID, claimsJSON.getString("aud"));
        log.debug("iat: " + claimsJSON.getLong("iat"));
        Assert.assertNotNull(claimsJSON.getLong("iat"));
        log.debug("exp: " + claimsJSON.getLong("exp"));
        Assert.assertNotNull(claimsJSON.getLong("exp"));
        log.debug("name: " + claimsJSON.getString("name"));
        Assert.assertEquals(TestUtil.getInstance().getOwnerUsername(), claimsJSON.getString("name"));
        log.debug("email: " + claimsJSON.getString("email"));
        Assert.assertNotNull(claimsJSON.getString("email"));
        log.debug("memberOf: " + claimsJSON.getJSONArray("memberOf"));
        Assert.assertNotNull(claimsJSON.getJSONArray("memberOf"));
    }

    private JSONObject getTokenBody(String encodedBodyPart) {
        // base64 decode body
        byte[] bodyBytes = Base64.getUrlDecoder().decode(encodedBodyPart);
        String bodyStr = new String(bodyBytes);
        log.debug("id_token body decoded: " + bodyStr);
        return new JSONObject(bodyStr);
    }

    //----------

    @Test
    public void testJWKSEndpoint() {
        log.info("start testJWKSEndpoint");

        // get the public keys
        // endpoint should be available anon
        OutputStream out = new ByteArrayOutputStream();
        log.debug("calling " + publicKeyURL);
        HttpGet get = new HttpGet(publicKeyURL, out);
        get.run();
        if (get.getThrowable() != null) {
            throw new RuntimeException(get.getThrowable());
        }
        log.debug("response code: " + get.getResponseCode());
        log.debug("response: " + out.toString());
        Assert.assertNotNull(out.toString());

        // Test Key ID value returned
        JSONObject keysJSON = new JSONObject(out.toString());
        JSONArray keysArray = keysJSON.getJSONArray("keys");
        Assert.assertTrue(keysArray.length() > 0);

        String expectedKID = OIDCUtil.KID_CLAIM_VALUE;

        boolean OIDCRSAKeyFound = false;
        String encodedKID = "";
        for (int i=0; i<keysArray.length(); i++) {

            JSONObject keyObject = keysArray.getJSONObject(i);

            // Verify KID value
            encodedKID = keyObject.getString("kid");

            if (encodedKID.equals(expectedKID)) {
                OIDCRSAKeyFound = true;
            }

        }
        if (!OIDCRSAKeyFound) {
            log.debug("kid from RSAKey encoded: " + encodedKID);
            log.debug("kid from RSAKey decoded: " + Base64.getUrlDecoder().decode(encodedKID));
            Assert.fail("could not find expected OIDC RSAKey associated with JWT kid value (did the key pair change?)" + expectedKID);
        }
        log.info("end testJWKSEndpoint");
    }
    
    @Test
    public void testValidateJWT() {
        log.info("start test for validating JWT");
        try {
            
            // Step 1: Get the authorization code
            String code = Subject.doAs(TestUtil.getInstance().getOwnerSubject(), new PrivilegedExceptionAction<String>() {
                @Override
                public String run() throws Exception {
                    
                    String callbackURL = "https://example.com";
                    
                    StringBuilder query = new StringBuilder();
                    query.append(authorizeURL.toString());
                    query.append("?client_id=" + clientID);
                    query.append("&redirect_uri=" + callbackURL);
                    query.append("&scope=openid%20email");
                    query.append("&response_type=code");
                    query.append("&state=12345");
                    log.debug("query being called: " + query.toString());
                    log.debug("query length: " + query.length());

                    HttpGet get = new HttpGet(new URL(query.toString()), false);
                    get.run();
                    if (get.getThrowable() != null) {
                        throw new RuntimeException(get.getThrowable());
                    }
                    log.debug("response code: " + get.getResponseCode());
                    String redirect = get.getResponseHeader("Location");
                    log.debug("redirect: " + redirect);
                    Assert.assertNotNull(redirect);
                    
                    String[] redirectParams = redirect.substring((callbackURL + "?").length()).split("&");
                    Assert.assertTrue(redirectParams.length == 2);
                    String state = null;
                    String code = null;
                    for (String param : redirectParams) {
                        if (param.startsWith("code=")) {
                            code = param.substring("code=".length());
                        }
                        if (param.startsWith("state=")) {
                            state = param.substring("state=".length());
                        }
                    }
                    log.debug("code: " + code);
                    log.debug("state: " + state);
                    Assert.assertNotNull(code);
                    Assert.assertNotNull(state);
                    Assert.assertTrue(state.equals("12345"));
                    
                    return code;
                }
            });
            
            // Step 2: Using the code, get the access, refresh, and id tokens
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("grant_type", "authorization_code");
            map.put("client_id", clientID);
            map.put("client_secret", clientSecret);
            map.put("redirect_uri", "callback");
            map.put("code", code);
            OutputStream out = new ByteArrayOutputStream();
            log.debug("calling: " + tokenURL.toString());
            HttpPost post = new HttpPost(tokenURL, map, out);
            post.run();
            if (post.getThrowable() != null) {
                throw new RuntimeException(post.getThrowable());
            }
            log.debug("response code: " + post.getResponseCode());
            log.debug("response: " + out.toString());

            // Step 3: validate all expected fields are populated
            JSONObject doc = new JSONObject(out.toString());

            testDocReturn(doc);
            String accessToken = doc.getString("access_token");
            String refreshToken = doc.getString("refresh_token");
            String idToken = doc.getString("id_token");

            // Step 4: test quality of values returned in doc

            // Test the quality of the token returned
            testIdToken(idToken);

            // test that /userinfo endpoint works with the
            // generated access token
            testUserInfoEndpoint(accessToken);

            // test that refreshToken allows access to /token endpoint
            testRefreshTokenEndpoint(refreshToken, idToken);

        } catch (Throwable t) {
            log.debug("unexpected: " + t.getMessage(), t);
            Assert.fail("unexpected: " + t.getMessage());
        }
        log.info("end test for validating JWT");
    }

    /**
     * Call the userInfoURL endpoint with the supplied accessToken.
     * Test quality of JSON returned.
     * @param accessToken
     * @throws Exception
     */
    public void testUserInfoEndpoint(String accessToken) throws Exception {
        // accessToken needs to be set as the Authorization header of
        // the HTTP call to the /userinfo endpoint.

        // Add challenge type to beginning of accessToken
        String accessAndChallengeToken = AuthenticationUtil.CHALLENGE_TYPE_BEARER + " " + accessToken;
        OutputStream out = new ByteArrayOutputStream();
        log.debug("calling: " + userInfoURL.toString());
        HttpGet post = new HttpGet(userInfoURL, out);
        post.setRequestProperty("Authorization", accessAndChallengeToken);
        post.run();
        if (post.getThrowable() != null) {
            throw new RuntimeException(post.getThrowable());
        }
        String outStr = out.toString();
        log.debug("USER INFO response code: " + post.getResponseCode());
        log.debug("USER INFO response: " + outStr);

        // Claim content should be as expected for owner user
        JSONObject userInfoObj = new JSONObject(outStr);
        testClaimContent(userInfoObj, userInfoURL.toString());
    }



    /**
     * Refresh an existing token. Test quality of tokenURL endpoint response,
     * and make sure the time stamp is at least the same as the existing.
     * @param refreshToken
     * @param oldIdToken
     * @throws Exception
     */
    public void testRefreshTokenEndpoint(String refreshToken, String oldIdToken) throws Exception {

        // Place minimum needed for a refresh_token grant type
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("grant_type", "refresh_token");
        map.put("refresh_token", refreshToken);
        map.put("client_id", clientID);
        map.put("client_secret", clientSecret);

        OutputStream out = new ByteArrayOutputStream();
        log.debug("calling: " + tokenURL.toString());
        HttpPost post = new HttpPost(tokenURL, map, out);
        post.run();
        if (post.getThrowable() != null) {
            throw new RuntimeException(post.getThrowable());
        }
        log.debug("response code: " + post.getResponseCode());
        log.debug("response: " + out.toString());

        JSONObject refreshResponsedoc = new JSONObject(out.toString());
        testDocReturn(refreshResponsedoc);

        // Verify the iat is later (or at least equal)
        String newIdToken = refreshResponsedoc.getString("id_token");
        String[] oldIdTokenParts = splitToken(oldIdToken);
        JSONObject oldIdTokenBody = getTokenBody(oldIdTokenParts[1]);
        long oldTokenIAT = oldIdTokenBody.getLong("iat");
        log.debug("iat from oldIdTokenBody: " + oldTokenIAT);

        String[] newIdTokenParts = splitToken(newIdToken);
        JSONObject newIdTokenBody = getTokenBody(newIdTokenParts[1]);
        long newTokenIAT = newIdTokenBody.getLong("iat");
        log.debug("iat from newIdTokenBody: " + newTokenIAT);

        // Chances are this test will run too fast, so the new token IAT will be
        // the same as the old. As long as it's not less than...
        Assert.assertTrue("iat from new token not later than old: "
                + newTokenIAT + ": " + oldTokenIAT,
            newTokenIAT >= oldTokenIAT);

        // Use existing testIDToken function to test quality of token returned
        testIdToken(newIdToken);
    }


    public void testIdToken(String idTokenEncoded) throws Exception {

        String[] parts = splitToken(idTokenEncoded);

        // base64 decode header for visual checking
        byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
        String header = new String(headerBytes);
        log.debug("id_token header decode: " + header);

        JSONObject headerJSON = new JSONObject(header);
        Assert.assertEquals("RS256", headerJSON.getString("alg"));

        String encodedKIDHdrClaim = headerJSON.getString("kid");
        log.debug("encoded kid header claim: " + encodedKIDHdrClaim);
        Assert.assertNotNull("kid claim header missing", encodedKIDHdrClaim);
        // check quality of it using OIDCUtil
        String expectedKID = OIDCUtil.KID_CLAIM_VALUE;
        Assert.assertTrue("oops! kid claim mangled: " + encodedKIDHdrClaim, expectedKID.equals(encodedKIDHdrClaim));
        
        // base64 decode body
        JSONObject body = getTokenBody(parts[1]);

        // Test claims are expected
        testClaimContent(body, tokenURL.toString());

        // get the public keys
        OutputStream out = new ByteArrayOutputStream();
        log.debug("calling " + publicKeyURL);
        HttpGet get = new HttpGet(publicKeyURL, out);
        get.run();
        if (get.getThrowable() != null) {
            throw new RuntimeException(get.getThrowable());
        }
        log.debug("response code: " + get.getResponseCode());
        log.debug("response: " + out.toString());
        Assert.assertNotNull(out.toString());

        JSONObject keysJSON = new JSONObject(out.toString());
        JSONArray keysArray = keysJSON.getJSONArray("keys");
        Assert.assertTrue(keysArray.length() > 0);
        
        boolean verified = false;
        boolean RSAKeyFound = false;
        String encodedKID = "";
        for (int i=0; i<keysArray.length(); i++) {

            JSONObject keyObject = keysArray.getJSONObject(i);

            // Verify KID value
            encodedKID = keyObject.getString("kid");

            if (encodedKID.equals(encodedKIDHdrClaim)) {
                RSAKeyFound = true;
                String modStr = keyObject.getString("n");
                String expStr = keyObject.getString("e");
                log.debug("modulus (n): " + modStr);
                log.debug("exp (e): " + expStr);
                // Using urlDecoder because that's what the nimbus JWT library uses
                // to encode
                byte exponentB[] = Base64.getUrlDecoder().decode(expStr);
                byte modulusB[] = Base64.getUrlDecoder().decode(modStr.trim());
                log.debug("modulus base64 decoded (n): " + modulusB.toString());
                log.debug("exp base64 decoded (e): " + exponentB.toString());

                try {
                    // generates a key 2048 long
                    // The BigInteger statements turn m1 and e2 into values the KeyFactory can use
                    PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(new BigInteger(1, modulusB), new BigInteger(1, exponentB)));

                    log.debug("public key: " + pub.toString());

                    Signature verifier = Signature.getInstance("SHA256withRSA");
                    verifier.initVerify(pub);

                    // Should be JWTheader . JWTpayload - not base 64 encoded
                    String sigToCheck = parts[0] + '.' + parts[1];
                    log.debug("sigToCheck string: " + sigToCheck);
                    verifier.update(sigToCheck.getBytes());

                    // Signature.verify needs base64 URL decoded JWT signature bytes
                    byte[] sigB64UrlDecoded = Base64.getUrlDecoder().decode(parts[2]);
                    log.debug("sigB64UrlDecoded bytes (parts[2] b64 url decoded): " + sigB64UrlDecoded);

                    if (verifier.verify(sigB64UrlDecoded)) {
                        verified = true;
                        log.debug("key " + i + "signature verification: true");
                    } else {
                        log.debug("key " + i + "signature verification: false");
                    }

                } catch (Exception e) {
                    log.debug("exception verifying jwt", e);
                }
            }
                
        }
        if (!verified) {
            Assert.fail("could not verify jwt");
        }
    }
}
