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

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.InvalidSignedTokenException;
import ca.nrc.cadc.auth.SignedToken;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

/**
 * 
 * Verify authorization code and issue an OAuth2 token.   This class responds to
 * HTTP POST calls.
 * 
 * @author majorb
 *
 */
public class TokenAction extends RestAction {
    
    private static final Logger log = Logger.getLogger(TokenAction.class);

    @Override
    public void doAction() throws Exception {
        
        if (log.isDebugEnabled()) {
            log.debug("params:");
            for (String s : syncInput.getParameterNames()) {
                log.debug("param: " + s + "=" + syncInput.getParameter(s));
            }
        }
        
        // Authenticate the Client
        log.debug("authenticating client");
        final String clientID = syncInput.getParameter("client_id");
        // (our config makes clients post the secret: "token_endpoint_auth_methods_supported: client_secret_post")
        String clientSecret = syncInput.getParameter("client_secret");
        if (clientID == null || clientSecret == null) {
            log.debug("invalid_client: clientID: " + clientID + " clientSecret: " + clientSecret);
            sendError("invalid_client");
            return;
        }
        RelyParty rp = OIDCUtil.getRelyParty(clientID);
        if (rp == null) {
            log.debug("invalid_client: rely party not found");
            sendError("invalid_client");
            return;
        }
        if (!rp.getClientSecret().equals(clientSecret)) {
            log.debug("invalid_client: invalid secret");
            sendError("invalid_client");
            return;
        }
        
        // Check the grant type
        String grantType = syncInput.getParameter("grant_type");
        log.debug("checking grant type: " + grantType);
        SignedToken st = null;
        
        if ("refresh_token".equals(grantType)) {
            
            String refreshToken = syncInput.getParameter("refresh_token");
            if (refreshToken == null) {
                sendError("invalid_request");
                return;
            }
            
            try {
                st = SignedToken.parse(refreshToken);
            } catch (InvalidSignedTokenException e) {
                log.debug("Invalid refresh Token", e);
                sendError("invalid_scope");
                return;
            }
            
        } else if ("authorization_code".equals(grantType)) {
            // Verify that the Authorization Code is valid.
            log.debug("validating code");
            String code = syncInput.getParameter("code");
            if (code == null) {
                sendError("invalid_request");
                return;
            }
            
            // TODO: Ensure the Authorization Code was issued to the authenticated Client.
            
            try {
                st = SignedToken.parse(code);
            } catch (InvalidSignedTokenException e) {
                log.debug("Invalid signed Token", e);
                sendError("invalid_scope");
                return;
            }
            
        } else {
            log.debug("returning unsupported_grant_type");
            sendError("unsupported_grant_type");
            return;
        }

        // TODO: If possible, verify that the Authorization Code has not been previously used.
        
        // TODO: Ensure that the redirect_uri parameter value is identical to the redirect_uri
        //   parameter value that was included in the initial Authorization Request. If the
        //   redirect_uri parameter value is not present when there is only one registered redirect_uri
        //   value, the Authorization Server MAY return an error (since the Client should have included
        //   the parameter) or MAY proceed without an error (since OAuth 2.0 permits the parameter to be
        //   omitted in this case).
        
        // TODO: Verify that the Authorization Code used was issued in response to an OpenID Connect
        //   Authentication Request (so that an ID Token will be returned from the Token Endpoint).
        
        // Create and run as the target subject
        final HttpPrincipal useridPrincipal = st.getPrincipalByClass(HttpPrincipal.class);
        Subject subject = new Subject();
        subject.getPrincipals().add(useridPrincipal);
        AuthMethod authMethod = AuthMethod.TOKEN;
        subject.getPublicCredentials().add(authMethod);
        log.debug("augmenting user subject");
        subject = AuthenticationUtil.augmentSubject(subject);

        Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            @Override
            public Object run() throws Exception {
                
                String jwt = createJWT(useridPrincipal.getName(), rp);
                
                log.debug("set headers and return json: \n" + jwt);
                syncOutput.setHeader("Content-Type", "application/json");
                syncOutput.setHeader("Cache-Control", "no-store");
                syncOutput.setHeader("Pragma", "no-cache");
                
                OutputStreamWriter writer = new OutputStreamWriter(syncOutput.getOutputStream());
                writer.write(jwt.toString());
                writer.flush();
                return null;
            }
        });
        
    }
    
    private String createJWT(String userid, RelyParty rp) throws Exception {
        
        log.debug("building jwt");
        String jws = OIDCUtil.buildIDToken(rp, syncInput.getRequestURI());
        
        log.debug("building access token");
        
        // include the clientID in the scope for use by the UserInfo endpoint.
        URI accessTokenScope = URI.create(OIDCUtil.ACCESS_TOKEN_SCOPE +"/" + rp.getClientID());
        URI refreshTokenScope = URI.create(OIDCUtil.REFRESH_TOKEN_SCOPE);
        String accessToken = OIDCUtil.getToken(userid, accessTokenScope, OIDCUtil.ACCESS_CODE_EXPIRY_MINUTES);
        String refreshToken = OIDCUtil.getToken(userid, refreshTokenScope, OIDCUtil.REFRESH_TOKEN_EXPIRY_MINUTES);
        
        StringBuilder json = new StringBuilder();
        json.append("{ ");
        json.append("  \"access_token\": \"" + accessToken + "\",");
        json.append("  \"refresh_token\": \"" + refreshToken + "\",");
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

//    class TokenScopeValidator extends ScopeValidator {
//        @Override
//        public void verifyScope(URI scope, String requestURI) throws InvalidDelegationTokenException {
//            URI expected = URI.create(OIDCUtil.AUTHORIZE_TOKEN_SCOPE);
//            if (!expected.equals(scope)) {
//                throw new InvalidDelegationTokenException("invalid scope");
//            }
//        }
//    }
//    
//    class RefreshTokenScopeValidator extends ScopeValidator {
//        @Override
//        public void verifyScope(URI scope, String requestURI) throws InvalidDelegationTokenException {
//            URI expected = URI.create(OIDCUtil.REFRESH_TOKEN_SCOPE);
//            if (!expected.equals(scope)) {
//                throw new InvalidDelegationTokenException("invalid scope");
//            }
//        }
//    }

}
