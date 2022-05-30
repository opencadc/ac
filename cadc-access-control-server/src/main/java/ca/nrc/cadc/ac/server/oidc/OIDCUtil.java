/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2020.                            (c) 2020.
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
package ca.nrc.cadc.ac.server.oidc;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapGroupPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapUserPersistence;
import ca.nrc.cadc.ac.server.oidc.RelyParty.Claim;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.SignedToken;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.util.RsaSignatureGenerator;
import ca.nrc.cadc.util.RsaSignatureVerifier;

import com.nimbusds.jose.util.BigIntegerUtils;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.lang.LegacyServices;
import io.jsonwebtoken.io.Serializer;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.AccessControlException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import java.security.interfaces.RSAPublicKey;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;
import org.json.JSONObject;
//import org.opencadc.gms.GroupClient;
import org.opencadc.gms.GroupURI;
//import org.opencadc.gms.GroupUtil;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

/**
 * 
 * Utilities for OIDC/OAuth2 support.
 * 
 * @author majorb
 *
 */
public class OIDCUtil {
    
    public static final String CONFIG = "ac-oidc-clients.properties";

    public static final String AUTHORIZE_TOKEN_SCOPE = "cadc:oauth2/authorize_token";
    public static final String REFRESH_TOKEN_SCOPE = "cadc:oauth2/refresh_token";
    public static final String ACCESS_TOKEN_SCOPE = "cadc:oauth2/access_token";
    
    public static final Integer ID_TOKEN_EXPIRY_MINUTES = 60*24*7*2; // 2 weeks
    public static final Integer AUTHORIZE_CODE_EXPIRY_MINUTES = 10;
    public static final Integer ACCESS_CODE_EXPIRY_MINUTES = 60*24*7*2; // 2 weeks
    public static final Integer REFRESH_TOKEN_EXPIRY_MINUTES = 60*24*7*52; // 1 year
    public static final Integer JWT_EXPIRY_MINUTES = 60*24*7*2; // 2 weeks
    
    //public static final String CLAIM_ISSUER_VALUE = "https://proto.canfar.net/ac";
    public static final String CLAIM_GROUPS_KEY = "memberOf";

    private static final String PUBLIC_KEY_NAME = "oidc-rsa256-pub.key";
    private static final String PRIVATE_KEY_NAME = "oidc-rsa256-priv.key";

    private static Set<PublicKey> publicKeys = null;
    private static Key privateKey = null;
    
    private static final Logger log = Logger.getLogger(OIDCUtil.class);
    
    // NOTE:  RelyParties should come from a properties file, ac.properties.  The other
    // current properties file ac-domains.properties should be transitioned to use this
    // single per-service file when rely parties are configured there.
    private static Map<String, RelyParty> relyParties = null;
    
    public static Set<PublicKey> getPublicKeys() {
        if (publicKeys == null) {
            File pubFile = FileUtil.getFileFromResource(PUBLIC_KEY_NAME, OIDCUtil.class);
            RsaSignatureVerifier verifier = new RsaSignatureVerifier(pubFile);
            publicKeys = verifier.getPublicKeys();
        }
        return publicKeys;
    }
    
    private static Key getPrivateKey() {
        if (privateKey == null) {
            File privFile = FileUtil.getFileFromResource(PRIVATE_KEY_NAME, OIDCUtil.class);
            RsaSignatureGenerator generator = new RsaSignatureGenerator(privFile);
            privateKey = generator.getPrivateKey();
        }
        return privateKey;
    }

    private static RsaSignatureGenerator getRsaSignatureGenerator() {
//        if (privateKey == null) {
            File privFile = FileUtil.getFileFromResource(PRIVATE_KEY_NAME, OIDCUtil.class);
            return new RsaSignatureGenerator(privFile);
//        }
        // TODO: not sure this is great
//        return null;
    }


    private static Set<String> getClientIDs(MultiValuedProperties config) {
        Set<String> clientIDs = new HashSet<String>();
        Set<String> keys = config.keySet();
        for (String k : keys) {
            clientIDs.add(k.split("\\.")[0]);
        }
        
        return clientIDs;
    }
    
    private static void checkKey(MultiValuedProperties config, Set<String> keys, String key) {
        if (!keys.contains(key)) {
            throw new IllegalStateException("missing key " + key + " in " + CONFIG);
        } else if (config.getProperty(key).get(0).isEmpty()) {
            throw new IllegalStateException("missing value for " + key + " in " + CONFIG);
        }
    }
    
    private static String getSecret(MultiValuedProperties config, Set<String> keys, String clientID) {
        String secretKey = clientID + ".secret";
        checkKey(config, keys, secretKey);
        return config.getProperty(secretKey).get(0);
    }
    
    private static String getDescription(MultiValuedProperties config, Set<String> keys, String clientID) {
        String descriptionKey = clientID + ".description";
        checkKey(config, keys, descriptionKey);
        return config.getProperty(descriptionKey).get(0);
    }
    
    private static boolean getSignDocuments(MultiValuedProperties config, Set<String> keys, String clientID) {
        String signDocumentsKey = clientID + ".sign-documents";
        checkKey(config, keys, signDocumentsKey);
        return Boolean.valueOf(config.getProperty(signDocumentsKey).get(0));
    }
    
    private static List<Claim> getClaims(MultiValuedProperties config, Set<String> keys, String clientID) {
        String claimsKey = clientID + ".claims";
        checkKey(config, keys, claimsKey);
        List<Claim> claims = new ArrayList<Claim>();
        final String[] claimsArray = config.getProperty(claimsKey).get(0).split(" ");
        for (String claim : claimsArray) {
            claims.add(RelyParty.Claim.getClaim(claim));
        }
        
        return claims;
    }
    
    private static void loadConfig() {
        log.debug("Reading RelyParties properties from: " + CONFIG);
        relyParties = new HashMap<String, RelyParty>();
        PropertiesReader pr = new PropertiesReader(CONFIG);
        MultiValuedProperties config = pr.getAllProperties();
        Set<String> keys = config.keySet();
        if (config == null || keys.isEmpty())
        {
            throw new RuntimeException("failed to read any OIDC property ");
        }
        
        Set<String> clientIDs = getClientIDs(config);
        for (String clientID : clientIDs) {
            final String secret = getSecret(config, keys, clientID);
            final String description = getDescription(config, keys, clientID);
            final boolean signDocuments = getSignDocuments(config, keys, clientID);
            List<Claim> claims = getClaims(config, keys, clientID);

            RelyParty relyParty = new RelyParty(clientID, secret, description, claims, signDocuments);
            
            // access group is optional
            String accessGroupKey = clientID + ".access-group";
            if (keys.contains(accessGroupKey)) {
                final String accessGroupString = config.getProperty(accessGroupKey).get(0);
                if (!accessGroupString.isEmpty()) {
                    GroupURI accessGroup = new GroupURI(URI.create(accessGroupString));
                    relyParty.setAccessGroup(accessGroup);
                }
            }

            relyParties.put(clientID, relyParty);
        }

    }
    
    public static RelyParty getRelyParty(String clientID) {
        if (relyParties == null) {
            // add all rely parties
            loadConfig();
        }

        return relyParties.get(clientID);
    }
    
    public static boolean accessAllowed(RelyParty rp) 
        throws AccessControlException, UserNotFoundException, GroupNotFoundException, TransientException {
        GroupURI accessGroup = rp.getAccessGroup();
        if (accessGroup == null) {
            // access group not specified, allow access
            return true;
        } else {
            LdapGroupPersistence ldapGroupPersistence = new LdapGroupPersistence();
            Collection<Group> groups = ldapGroupPersistence.getGroups(Role.MEMBER, accessGroup.getName());
            if (groups == null || groups.isEmpty()) {
                return false;
            } else {
                return true;
            }
        }
    }
    
    public static String getToken(String username, URI scope, int expiryMinutes) throws InvalidKeyException, IOException {
        HttpPrincipal p = new HttpPrincipal(username);
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, expiryMinutes);
        SignedToken token = new SignedToken(p, scope, c.getTime(), null);
        return SignedToken.format(token);
    }
    
    public static String getEmail(HttpPrincipal userID)
            throws AccessControlException, UserNotFoundException, TransientException {
        UserPersistence up = new LdapUserPersistence();
        User user = up.getUser(userID);
        if (user.personalDetails != null && user.personalDetails.email != null) {
            return user.personalDetails.email;
        }
        return "";
    }
    
    public static List<String> getGroupList() throws Exception {
        GroupPersistence gp = new LdapGroupPersistence();
        Collection<Group> groups = gp.getGroups(Role.MEMBER, null);
        List<String> groupNames = new ArrayList<String>();
        Iterator<Group> it = groups.iterator();
        while (it.hasNext()) {
            groupNames.add(it.next().getID().getName());
        }
        return groupNames;
    }

//    public static String buildToken(RelyParty rp, boolean isUserInfo) throws Exception {
//
//        String jwk = generateJWKString(rp, isUserInfo);
//        if (rp.isSignDocuments() || !isUserInfo) {
//            // function in here to build the JWS format, base 64 encoding and all
//            // if isSignDocuments, do extra signing step using base header.payload
//        } else {
//            // provided the JWK is all that's needed, ... maybe the call to that function happens elsewhere
//            // so it's clear that a token isn't being used in that case?
//        }
//
//    }

    // 5/6/22 thought: pilfer DefaultJwtbuilder code, make the Claims object
    // convertible to JSON, or grabbable, or, and re-write the compact code
    // so it's contained in there.
    
    public static String buildIDToken(RelyParty rp, boolean isUserInfo) throws Exception {
        
        final Subject subject = AuthenticationUtil.getCurrentSubject();
        
        NumericPrincipal numericPrincipal = subject.getPrincipals(NumericPrincipal.class).iterator().next();
        HttpPrincipal useridPrincipal = subject.getPrincipals(HttpPrincipal.class).iterator().next();
        String email = OIDCUtil.getEmail(useridPrincipal);
        Calendar calendar = Calendar.getInstance();
        
//        if (rp.isSignDocuments() || !isUserInfo) {
            // This is an implementation of the nimbus JWTBuilder interface
            // includes logging, ability to get JSON string of claims object (payload)
            // uses Java Base64 encoding and cadc-util RSASignature* classes
            // Much of the code is pulled from the DefatulJwtBuilder class
            RsaSignatureGenerator rsaSigGen = getRsaSignatureGenerator();
            CadcJWTBuilder builder = new CadcJWTBuilder(rsaSigGen);
//            builder.claim("sub", numericPrincipal.getName());
//            builder.claim("iss", getClaimIssuer());

//            if (rp.getClientID() != null) {
//                builder.claim("aud", rp.getClientID());
//            }

            // should this be same as iss?
//            https://developer.okta.com/docs/guides/build-self-signed-jwt/java/main/
        // TODO: what happens if clientid is null? (apparently it can be.)
            String clientID = rp.getClientID();
            builder.setAudience(getClaimIssuer())
                .setIssuedAt(calendar.getTime())
                .setIssuer(clientID)
                .setSubject(clientID)
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "RSA256");

            builder.claim("sub", numericPrincipal.getName());
            // Set expiry date
            calendar.add(Calendar.MINUTE, OIDCUtil.ID_TOKEN_EXPIRY_MINUTES);
            builder.setExpiration(calendar.getTime());
//            builder.claim("aud", getClaimIssuer());
//            if (rp.getClientID() != null) {
//                builder.claim("iss", rp.getClientID());
//            }

//            builder.claim("iat", calendar.getTime());
//            builder.claim("exp", calendar.getTime());
            if (rp.getClaims().contains(RelyParty.Claim.NAME)) {
                builder.claim(RelyParty.Claim.NAME.getValue(), useridPrincipal.getName());
            }
            if (rp.getClaims().contains(RelyParty.Claim.EMAIL)) {
                builder.claim(RelyParty.Claim.EMAIL.getValue(), email);
            }
            if (rp.getClaims().contains(RelyParty.Claim.GROUPS)) {
                builder.claim(RelyParty.Claim.GROUPS.getValue(), getGroupList());
            }

            // replace this section with functions that use our signing facilities in cadc-util,
            // replace the 'builder' section above with a function that will construct the JWK format
            // correctly.
            // make unit tests for both

        if (rp.isSignDocuments() || !isUserInfo) {

            // Have this in here so a JWT without a signature can still
            // be generated
            if (rp.isSignDocuments()) {
                // TODO: put our own signing library stuff in here
                builder.signWith(OIDCUtil.getPrivateKey());
            }

            // Build the base64 encoded JWT string
            return builder.compact();

        } else {
            // this code is builing the payload json
            // TODO: header json needs to be built as well
//            JSONObject json = new JSONObject();
//            json.put("sub", numericPrincipal.getName());
//            json.put("iss", getClaimIssuer());
//            if (rp.getClientID() != null) {
//                json.put("aud", rp.getClientID());
//            }
//            json.put("iat", calendar.getTime());
//            calendar.add(Calendar.MINUTE, OIDCUtil.ID_TOKEN_EXPIRY_MINUTES);
//            json.put("exp", calendar.getTime());
//            if (rp.getClaims().contains(RelyParty.Claim.NAME)) {
//                json.put(RelyParty.Claim.NAME.getValue(), useridPrincipal.getName());
//            }
//            if (rp.getClaims().contains(RelyParty.Claim.EMAIL)) {
//                json.put(RelyParty.Claim.EMAIL.getValue(), email);
//            }
//            if (rp.getClaims().contains(RelyParty.Claim.GROUPS)) {
//                json.put(RelyParty.Claim.GROUPS.getValue(), getGroupList());
//            }
//
//            return json.toString();

            return builder.getClaimsJSONStr();
        }

    }
    
    /**
     * Return the baseURL to the service (this service) running OAuth.
     * @return The baseURL of the OAuth service.
     * @throws IOException
     * @throws ResourceNotFoundException
     */
    static String getClaimIssuer() throws IOException, ResourceNotFoundException {
        LocalAuthority localAuthority = new LocalAuthority();
        URI serviceURI = localAuthority.getServiceURI(Standards.SECURITY_METHOD_OAUTH.toString());
        RegistryClient regClient = new RegistryClient();
        String oauthURL = regClient.getAccessURL(serviceURI).toString();
        // remove the last path element for the base URL
        int lastSlash = oauthURL.lastIndexOf("/");
        return oauthURL.substring(0, lastSlash);
    }
    
    static String getClaimDescriptionString(List<Claim> claims) {
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Claim c : claims) {
            if (count > 0) {
                sb.append(", ");
            }
            count++;
            sb.append(c.getDescription());
        }
        return sb.toString();
    }

    public static String buildJwkJSON(RSAPublicKey key, String keyID) {
        StringBuilder jwkJSON = new StringBuilder();
        // {"kty":"RSA","e":"AQAB","use":"sig","kid":"4dc4b6e5-71fc-4e85-9862-5acd1e707d7d","alg":"RS256","n":"sc73IJCnuaob7BB1JlWnDbkwMe7B5VsGKXSXO9HxtI-DaYjwc9LNRpIq-x4N3biN1cknat-ZBjYoWgWpT4KBZvNd1f8hQM-9BqDcEgwoQL8DotYiZJ0trvba_BC8wOwNNbMrUT-mHkba3lqb3jJNgRf5NXmIL1BbmtoB3jepi1q48ZQK-Njt7KFLUjwgsmYvPQ0BYjYE0iU9qD-JwWJrlrjitx4qM_XiWjNNOW_hbIZqtjNh6EN0KytwHWLKsZouPyH3-MzSD6Se7N5JAQ1_J5OFlAB-CHFLbylSd6_6Pi3zSm3t3xXJ-61kDHnscYlbRea0e7-b00z5a2tSvcQ_cQ"}  ]}

        jwkJSON.append("{\"kty\":\"RSA\",\"use\":\"sig\",");
        jwkJSON.append("\"alg\":\"RSA\"");
        jwkJSON.append("\"kid\":\"");
        jwkJSON.append(keyID);
        jwkJSON.append("\",\"");
        jwkJSON.append("\"n\":\"");

//        BigInteger a = new BigInteger(key.getModulus());

        byte[] nBytes = Base64.getUrlEncoder().encode(BigIntegerUtils.toBytesUnsigned(key.getModulus()));
        jwkJSON.append(nBytes.toString());
        jwkJSON.append("\",\"");
        byte[] eBytes = Base64.getUrlEncoder().encode(BigIntegerUtils.toBytesUnsigned(key.getPublicExponent()));


        jwkJSON.append(keyID);
        jwkJSON.append("\",\"");

        StringBuilder json = new StringBuilder();

        json.append("{");
        json.append("  \"keys\": [");
        json.append(jwkJSON);
        json.append("  ]");
        json.append("}");

        log.debug("JWKS:\n" + json.toString());
        return json.toString();

    }
    
}
