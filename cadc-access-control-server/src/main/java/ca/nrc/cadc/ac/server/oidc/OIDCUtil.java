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
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapGroupPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapUserPersistence;
import ca.nrc.cadc.ac.server.oidc.RelyParty.Claim;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.SignedToken;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.util.RsaSignatureGenerator;
import ca.nrc.cadc.util.RsaSignatureVerifier;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.AccessControlException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Utilities for OIDC/OAuth2 support.
 *
 * @author majorb
 */
public class OIDCUtil {

    public static final String CONFIG = "ac-oidc-clients.properties";

    public static final String AUTHORIZE_TOKEN_SCOPE = "cadc:oauth2/authorize_token";
    public static final String REFRESH_TOKEN_SCOPE = "cadc:oauth2/refresh_token";
    public static final String ACCESS_TOKEN_SCOPE = "cadc:oauth2/access_token";

    public static final Integer ID_TOKEN_EXPIRY_MINUTES = 60 * 24 * 7 * 2; // 2 weeks
    public static final Integer AUTHORIZE_CODE_EXPIRY_MINUTES = 10;
    public static final Integer ACCESS_CODE_EXPIRY_MINUTES = 60 * 24 * 7 * 2; // 2 weeks
    public static final Integer REFRESH_TOKEN_EXPIRY_MINUTES = 60 * 24 * 7 * 52; // 1 year
    public static final Integer JWT_EXPIRY_MINUTES = 60 * 24 * 7 * 2; // 2 weeks

    //public static final String CLAIM_ISSUER_VALUE = "https://proto.canfar.net/ac";
    public static final String CLAIM_GROUPS_KEY = "memberOf";

    private static final String PUBLIC_KEY_NAME = "oidc-rsa256-pub.key";
    private static final String PRIVATE_KEY_NAME = "oidc-rsa256-priv.key";
    public static final String KID_CLAIM_VALUE = "cadc-key-1.0";

    private static Set<PublicKey> publicKeys = null;
    private static Key privateKey = null;

    private static final Logger log = Logger.getLogger(OIDCUtil.class);

    // NOTE:  RelyParties should come from a properties file, ac.properties.  The other
    // current properties file ac-domains.properties should be transitioned to use this
    // single per-service file when rely parties are configured there.
    private static Map<String, RelyParty> relyParties = null;

    public static Set<PublicKey> getPublicKeys() {
        if (publicKeys == null) {
            File pubFile = new File(System.getProperty("user.home") + "/config/" + PUBLIC_KEY_NAME);
            RsaSignatureVerifier verifier = new RsaSignatureVerifier(pubFile);
            publicKeys = verifier.getPublicKeys();
        }
        return publicKeys;
    }

    private static Key getPrivateKey() {
        if (privateKey == null) {
            File privFile = new File(System.getProperty("user.home") + "/config/" + PRIVATE_KEY_NAME);
            RsaSignatureGenerator generator = new RsaSignatureGenerator(privFile);
            privateKey = generator.getPrivateKey();
        }
        return privateKey;
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
        if (config == null || keys.isEmpty()) {
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
        return OIDCUtil.getToken(username, scope, expiryMinutes, null);
    }

    public static String getToken(String username, URI scope, int expiryMinutes, List<String> domains)
            throws InvalidKeyException, IOException {
        HttpPrincipal p = new HttpPrincipal(username);
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, expiryMinutes);
        SignedToken token = new SignedToken(p, scope, c.getTime(), domains);
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

    private static Map<String, Object> buildTokenClaimsSet(RelyParty rp, String requestURI) throws Exception {
        final Subject subject = AuthenticationUtil.getCurrentSubject();

        String claimIssuer = requestURI.substring(0, requestURI.lastIndexOf("/"));
        NumericPrincipal numericPrincipal = subject.getPrincipals(NumericPrincipal.class).iterator().next();
        HttpPrincipal useridPrincipal = subject.getPrincipals(HttpPrincipal.class).iterator().next();
        String email = OIDCUtil.getEmail(useridPrincipal);
        Calendar calendar = Calendar.getInstance();
        String clientID = rp.getClientID();

        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("aud", clientID);
        claimsMap.put("iat", calendar.getTime());
        claimsMap.put("iss", claimIssuer);
        claimsMap.put("sub", numericPrincipal.getName());

        calendar.add(Calendar.MINUTE, OIDCUtil.ID_TOKEN_EXPIRY_MINUTES);
        claimsMap.put("exp", calendar.getTime());  // exp

        if (rp.getClaims().contains(RelyParty.Claim.NAME)) {
            claimsMap.put(RelyParty.Claim.NAME.getValue(), useridPrincipal.getName());
        }
        if (rp.getClaims().contains(RelyParty.Claim.EMAIL)) {
            claimsMap.put(RelyParty.Claim.EMAIL.getValue(), email);
        }
        if (rp.getClaims().contains(RelyParty.Claim.GROUPS)) {
            claimsMap.put(RelyParty.Claim.GROUPS.getValue(), getGroupList());
        }

        return claimsMap;
    }

    /**
     * Build JSON string with User Info - includes full JWT claims set
     *
     * @param rp
     * @return
     * @throws Exception
     */
    public static String buildUserInfoResponse(RelyParty rp, String requestURI) throws Exception {

        Map<String, Object> claimsMap = buildTokenClaimsSet(rp, requestURI);
        return new ObjectMapper().writeValueAsString(claimsMap);
    }

    /**
     * Build JWT string, sign if the RelyParty is set to require signing
     *
     * @param rp
     * @return
     * @throws Exception
     */
    public static String buildIDToken(RelyParty rp, String requestURI) throws Exception {

        Map<String, Object> claimsMap = buildTokenClaimsSet(rp, requestURI);
        JwtBuilder builder = Jwts.builder();
        builder.setClaims(claimsMap);

        builder.setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "RSA256");

        Set<PublicKey> pubKeys = OIDCUtil.getPublicKeys();
        RSAPublicKey key = ((RSAPublicKey) pubKeys.iterator().next());
        // This value is used to retrieve the corresponding RSA key
        builder.setHeaderParam("kid", KID_CLAIM_VALUE);

        if (rp.isSignDocuments()) {
            return builder.signWith(OIDCUtil.getPrivateKey(), SignatureAlgorithm.RS256).compact();
        } else {
            return builder.compact();
        }
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

}
