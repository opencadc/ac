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
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapGroupPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapUserPersistence;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.SignedToken;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.RsaSignatureGenerator;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.AccessControlException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * 
 * Utilities for OIDC/OAuth2 support.
 * 
 * @author majorb
 *
 */
public class OIDCUtil {
    
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
    
    private static RsaSignatureGenerator keyGenerator = null;
    
    private static final Logger log = Logger.getLogger(OIDCUtil.class);
    
    // NOTE:  RelyParties should come from a properties file, ac.properties.  The other
    // current properties file ac-domains.properties should be transitioned to use this
    // single per-service file when rely parties are configured there.
    private static final Map<String, RelyParty> relyParties;
    
    static {
        // add all rely parties
        relyParties = new HashMap<String, RelyParty>();
        relyParties.put("arbutus-harbor", new RelyParty("arbutus-harbor", "harbor-secret"));
    }
    
    private static void initKeys() {
        keyGenerator = new RsaSignatureGenerator();
    }
    
    public static Set<PublicKey> getPublicKeys() {
        if (keyGenerator == null) {
            initKeys();
        }
        return keyGenerator.getPublicKeys();
    }
    
    public static Key getPrivateKey() {
        if (keyGenerator == null) {
            initKeys();
        }
        return keyGenerator.getPrivateKey();
    }
    
    
    
    public static RelyParty getRelyParty(String clientID) {
        return relyParties.get(clientID);
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
    
    public static String buildIDToken(String clientID) throws Exception {
        
        final Subject subject = AuthenticationUtil.getCurrentSubject();
        
        NumericPrincipal numericPrincipal = subject.getPrincipals(NumericPrincipal.class).iterator().next();
        HttpPrincipal useridPrincipal = subject.getPrincipals(HttpPrincipal.class).iterator().next();
        String email = OIDCUtil.getEmail(useridPrincipal);
        
        JwtBuilder builder = Jwts.builder();
        builder.claim("iss", getClaimIssuer());
        builder.claim("sub", numericPrincipal.getName());
        Calendar calendar = Calendar.getInstance();
        builder.claim("iat", calendar.getTime());
        calendar.add(Calendar.MINUTE, OIDCUtil.ID_TOKEN_EXPIRY_MINUTES);
        builder.claim("exp", calendar.getTime());
        builder.claim("name", useridPrincipal.getName());
        builder.claim("email", email);
        builder.claim("memberOf", getGroupList());
        builder.claim("aud", clientID);
        String jws = builder.signWith(OIDCUtil.getPrivateKey()).compact();
        return jws;
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
    
}
