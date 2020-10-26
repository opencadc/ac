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
import ca.nrc.cadc.auth.DelegationToken.ScopeValidator;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.InvalidDelegationTokenException;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

/**
 * 
 * Return user info claims.
 * 
 * @author majorb
 *
 */
public class UserInfoAction extends RestAction {
    
    private static final Logger log = Logger.getLogger(UserInfoAction.class);

    @Override
    public void doAction() throws Exception {
        
        final Subject subject = AuthenticationUtil.getCurrentSubject();
        log.debug("Subject: " + subject);
        
        if (subject == null || subject.getPrincipals().isEmpty()) {
            throw new NotAuthenticatedException("unauthorized");
        }
        
        NumericPrincipal numericPrincipal = subject.getPrincipals(NumericPrincipal.class).iterator().next();
        HttpPrincipal useridPrincipal = subject.getPrincipals(HttpPrincipal.class).iterator().next();
        String email = OIDCUtil.getEmail(useridPrincipal);
        
        log.debug("building jwt");
        JwtBuilder builder = Jwts.builder();
        builder.claim("iss", OIDCUtil.CLAIM_ISSUER_VALUE);
        builder.claim("sub", numericPrincipal.getName());
        Calendar calendar = Calendar.getInstance();
        builder.claim("iat", calendar.getTime());
        calendar.add(Calendar.MINUTE, OIDCUtil.ID_TOKEN_EXPIRY_MINUTES);
        builder.claim("exp", calendar.getTime());
        builder.claim("name", useridPrincipal.getName());
        builder.claim("email", email);
        builder.claim("memberOf", getGroupList());
        //builder.claim("aud", clientID);
        String jws = builder.signWith(OIDCUtil.privateSigningKey).compact();
        
        log.debug("set headers and return json: \n" + jws);
        syncOutput.setHeader("Content-Type", "application/jwt");
        syncOutput.setHeader("Cache-Control", "no-store");
        syncOutput.setHeader("Pragma", "no-cache");
      
        OutputStreamWriter writer = new OutputStreamWriter(syncOutput.getOutputStream());
        writer.write(jws);
        writer.flush();
        
//        
//        // Authenticate the Client
//        log.debug("authenticating client");
//        final String clientID = syncInput.getParameter("client_id");
//        // (our config makes clients post the secret: "token_endpoint_auth_methods_supported: client_secret_post")
//        String clientSecret = syncInput.getParameter("client_secret");
//        if (clientID == null || clientSecret == null) {
//            sendError("invalid_client");
//            return;
//        }
//        RelyParty rp = OIDCUtil.getRelyParty(clientID);
//        if (rp == null || !rp.getClientSecret().equals(clientSecret)) {
//            sendError("invalid_client");
//            return;
//        }
//        
//        // Check the grant type
//        String grantType = syncInput.getParameter("grant_type");
//        log.debug("checking grant type: " + grantType);
//        // TODO: support refresh_token grant_type
//        if (!"authorization_code".equals(grantType)) {
//            log.debug("returning unsupported_grant_type");
//            sendError("unsupported_grant_type");
//            return;
//        }
//        
//        // TODO: Ensure the Authorization Code was issued to the authenticated Client.
//        
//        // Verify that the Authorization Code is valid.
//        log.debug("validating code");
//        String code = syncInput.getParameter("code");
//        DelegationToken dt = null;
//        if (code == null) {
//            sendError("invalid_request");
//            return;
//        }
//        
//        try {
//            dt = DelegationToken.parse(code, null, new TokenScopeValidator());
//        } catch (InvalidDelegationTokenException e) {
//            log.debug("Invalid delegation Token", e);
//            sendError("invalid_scope");
//            return;
//        }
//
//        // TODO: If possible, verify that the Authorization Code has not been previously used.
//        
//        // TODO: Ensure that the redirect_uri parameter value is identical to the redirect_uri
//        //   parameter value that was included in the initial Authorization Request. If the
//        //   redirect_uri parameter value is not present when there is only one registered redirect_uri
//        //   value, the Authorization Server MAY return an error (since the Client should have included
//        //   the parameter) or MAY proceed without an error (since OAuth 2.0 permits the parameter to be
//        //   omitted in this case).
//        
//        // TODO: Verify that the Authorization Code used was issued in response to an OpenID Connect
//        //   Authentication Request (so that an ID Token will be returned from the Token Endpoint).
//        
//        // Create and run as the target subject
//        final HttpPrincipal useridPrincipal = dt.getPrincipalByClass(HttpPrincipal.class);
//        Subject subject = new Subject();
//        subject.getPrincipals().add(useridPrincipal);
//        AuthMethod authMethod = AuthMethod.TOKEN;
//        subject.getPublicCredentials().add(authMethod);
//        log.debug("augmenting user subject");
//        subject = AuthenticationUtil.augmentSubject(subject);
//        final NumericPrincipal numericPrincipal = subject.getPrincipals(NumericPrincipal.class).iterator().next();
//
//        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
//            @Override
//            public Object run() throws Exception {
//                
//                String email = getEmail(useridPrincipal);
//                String jwt = createJWT(useridPrincipal.getName(), email, numericPrincipal.getName(), clientID);
//                
//                log.debug("set headers and return json: \n" + jwt);
//                syncOutput.setHeader("Content-Type", "application/json");
//                syncOutput.setHeader("Cache-Control", "no-store");
//                syncOutput.setHeader("Pragma", "no-cache");
//                
//                OutputStreamWriter writer = new OutputStreamWriter(syncOutput.getOutputStream());
//                writer.write(jwt.toString());
//                writer.flush();
//                return null;
//            }
//        });
        
    }
    
    private String createJWT(String userid, String email, String numericID, String clientID) throws Exception {
        
        log.debug("building jwt");
        JwtBuilder builder = Jwts.builder();
        builder.claim("iss", OIDCUtil.CLAIM_ISSUER_VALUE);
        builder.claim("sub", numericID);
        Calendar calendar = Calendar.getInstance();
        builder.claim("iat", calendar.getTime());
        calendar.add(Calendar.MINUTE, OIDCUtil.ID_TOKEN_EXPIRY_MINUTES);
        builder.claim("exp", calendar.getTime());
        builder.claim("name", userid);
        builder.claim("email", email);
        builder.claim("memberOf", getGroupList());
        builder.claim("aud", clientID);
        String jws = builder.signWith(OIDCUtil.privateSigningKey).compact();
        
        log.debug("building access token");
        // NOTE: These tokens should be more static than our current delegation tokens
        // where the expiry date is built in.  
        URI scope = URI.create(OIDCUtil.ACCESS_TOKEN_SCOPE);
        String accessToken = OIDCUtil.getToken(userid, scope, OIDCUtil.ACCESS_CODE_EXPIRY_MINUTES);
        
        StringBuilder json = new StringBuilder();
        json.append("{ ");
        json.append("  \"access_token\": \"" + accessToken + "\",");
        // TODO: add refresh_token
        json.append("  \"token_type\": \"Bearer\",");
        json.append("  \"expires_in\": \"").append(OIDCUtil.JWT_EXPIRY_MINUTES).append("\",");
        json.append("  \"id_token\": \"").append(jws).append("\"");
        json.append(" }");
        
        return json.toString();
    }

    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }
    
    private void sendError(String message) throws IOException {
        syncOutput.setHeader("Content-Type", "application/json");
        syncOutput.setHeader("Cache-Control", "no-store");
        syncOutput.setHeader("Pragma", "no-cache");
        syncOutput.setCode(400);
        OutputStreamWriter writer = new OutputStreamWriter(syncOutput.getOutputStream());
        String jsonErrorMsg = "{ \"error\": \"" + message + "\" }";
        log.debug("returning error:\n" + jsonErrorMsg);
        writer.write(jsonErrorMsg);
        writer.flush();
    }
    
    private List<String> getGroupList() throws Exception {
        GroupPersistence gp = new LdapGroupPersistence();
        Collection<Group> groups = gp.getGroups(Role.MEMBER, null);
        List<String> groupNames = new ArrayList<String>();
        Iterator<Group> it = groups.iterator();
        int count = 0;
        // limit to 15 groups for now
        while (it.hasNext() && count < 16) {
            groupNames.add(it.next().getID().getName());
            count++;
        }
        return groupNames;
    }
    
    private String getEmail(HttpPrincipal userID)
            throws AccessControlException, UserNotFoundException, TransientException {
        UserPersistence up = new LdapUserPersistence();
        User user = up.getUser(userID);
        if (user.personalDetails != null && user.personalDetails.email != null) {
            return user.personalDetails.email;
        }
        return "";
    }

    class TokenScopeValidator extends ScopeValidator {
        @Override
        public void verifyScope(URI scope, String requestURI) throws InvalidDelegationTokenException {
            URI expected = URI.create(OIDCUtil.AUTHORIZE_TOKEN_SCOPE);
            if (!expected.equals(scope)) {
                throw new InvalidDelegationTokenException("invalid scope");
            }
        }
    }

}
