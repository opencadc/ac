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
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.rest.RestAction;
import ca.nrc.cadc.util.PropertiesReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 * Authorize the RelyParty to obtain a OAuth2 token by ensuring
 * the client is authenticated and has given consent.
 * Subclasses AuthorizeGetAction and AuthorizePostAction collect the incoming
 * parameters.
 *
 * @author majorb
 */
public abstract class AuthorizeAction extends RestAction {

    private static final Logger log = Logger.getLogger(AuthorizeAction.class);

    private static final String CODE_REPSONSE_TYPE = "code";
    private static final String TOKEN_REPSONSE_TYPE = "token";
    private static final String IDTOKEN_REPSONSE_TYPE = "id_token";

    private static final String OIDC_SCOPE = "openid";
    private static final String VO_SINGLESIGNON_SCOPE = "vo-sso";

    public static final String DOMAINS_PROP_FILE = "ac-domains.properties";

    protected String scope;
    protected String responseType;
    protected String clientID;
    protected String redirectURI;
    protected String state;
    protected String responseMode;
    protected String nonce;
    protected String display;
    protected String prompt;
    protected String maxAge;
    protected String uiLocales;
    protected String idTokenHint;
    protected String loginHint;
    protected String acrValues;

    protected abstract void loadRequestInput();

    @Override
    public void doAction() throws Exception {

        loadRequestInput();
        logRequestInput();

        if (responseType == null) {
            AuthorizeError error = missingParameter("response_type");
            sendError(error);
            return;
        }

        // determine the request flow using response_type and scope
        if (CODE_REPSONSE_TYPE.equals(responseType)) {

            if (scope == null) {
                AuthorizeError error = missingParameter("scope");
                sendError(error);
                return;
            }

            // ensure oidc code flow in scope
            String[] scopes = scope.split("\\s+");
            if (!Arrays.asList(scopes).contains(OIDC_SCOPE)) {
                AuthorizeError error = new AuthorizeError();
                error.error = "invalid_scope";
                sendError(error);
                return;
            }

            doOpenIDCodeFlow();

        } else if (TOKEN_REPSONSE_TYPE.equals(responseType) || IDTOKEN_REPSONSE_TYPE.equals(responseType)) {

            doCLIFlow();

        } else {
            AuthorizeError error = new AuthorizeError();
            error.error = "unsupported_response_type";
            sendError(error);
            return;
        }
    }

    private void doOpenIDCodeFlow() throws Exception {

        // check required params
        if (redirectURI == null) {
            AuthorizeError error = missingParameter("redirect_uri");
            sendError(error);
            return;
        }

        if (clientID == null) {
            AuthorizeError error = missingParameter("client_id");
            sendError(error);
            return;
        }

        // check client id
        RelyParty rp = OIDCUtil.getRelyParty(clientID);
        if (rp == null) {
            AuthorizeError authError = new AuthorizeError();
            authError.error = "unauthorized_client";
            sendError(authError);
            return;
        }

        if (!"login".equals(prompt)) {
            // TODO: check if already logged in using id_token_hint
        }

        // if not logged in, check value of prompt
        if ("none".equals(prompt)) {
            AuthorizeError error = new AuthorizeError();
            error.error = "login_required";
            sendError(error);
            return;
        }

        // see if the request is already authenticated
        Subject s = AuthenticationUtil.getCurrentSubject();
        AuthMethod authMethod = AuthenticationUtil.getAuthMethodFromCredentials(s);
        if (authMethod.equals(AuthMethod.ANON)) {

            // Use RegistryClient to get URL of login page, as configured in reg-applications.properties
            // on the server hosting ac.
            RegistryClient rc = new RegistryClient();
            URL loginURL = rc.getAccessURL(RegistryClient.Query.APPLICATIONS, new URI("ivo://cadc.nrc.ca/login"));
            StringBuilder redirect = new StringBuilder();
            redirect.append(loginURL.toExternalForm());
            redirect.append("#redirect_uri=");

            redirect.append(redirectURI);
            if (loginHint != null) {
                redirect.append("&username=");
                redirect.append(loginHint);
            }
            if (state != null) {
                redirect.append("&state=");
                redirect.append(state);
            }
            redirect.append("&clientid=").append(NetUtil.encode(clientID));
            redirect.append("&client=").append(NetUtil.encode(rp.getClientDescription()));
            String claimDesc = OIDCUtil.getClaimDescriptionString(rp.getClaims());
            redirect.append("&claims=").append(NetUtil.encode(claimDesc));

            log.debug("redirecting to " + redirect.toString());
            syncOutput.setCode(302);
            syncOutput.setHeader("Location", redirect);

        } else {

            // if authenticated (only possible by cookie) skip login form
            // formulate the authenticate redirect response

            // perform group check on rp.accessGroup 
            if (!OIDCUtil.accessAllowed(rp)) {
                AuthorizeError authError = new AuthorizeError();
                authError.error = "login failed, not a member of " + rp.getAccessGroup();
                sendError(authError);
                return;
            }

            Set<HttpPrincipal> useridPrincipals = s.getPrincipals(HttpPrincipal.class);
            String username = useridPrincipals.iterator().next().getName();

            StringBuilder redirect = new StringBuilder(redirectURI);
            URI scope = URI.create(OIDCUtil.AUTHORIZE_TOKEN_SCOPE);
            String code = OIDCUtil.getToken(username, scope, OIDCUtil.AUTHORIZE_CODE_EXPIRY_MINUTES);
            redirect.append("?code=");
            redirect.append(code);
            if (state != null) {
                redirect.append("&state=");
                redirect.append(state);
            }
            syncOutput.setCode(302);
            syncOutput.setHeader("Location", redirect);
        }

    }

    private void doCLIFlow() throws Exception {

        // see if the request is authenticated
        Subject s = AuthenticationUtil.getCurrentSubject();
        AuthMethod authMethod = AuthenticationUtil.getAuthMethodFromCredentials(s);
        if (authMethod.equals(AuthMethod.ANON)) {

            // 401 and Authenticate headers set by cadc-rest
            throw new NotAuthenticatedException("login_requried");

        } else {

            Set<HttpPrincipal> useridPrincipals = s.getPrincipals(HttpPrincipal.class);
            String username = useridPrincipals.iterator().next().getName();

            if (TOKEN_REPSONSE_TYPE.equals(responseType)) {

                // only 'vo-sso' scope supported for token responseType
                if (scope != null && !VO_SINGLESIGNON_SCOPE.equals(scope)) {
                    AuthorizeError error = new AuthorizeError();
                    error.error = "invalid_scope";
                    sendError(error);
                    return;
                }

                URI scope = URI.create(OIDCUtil.ACCESS_TOKEN_SCOPE);
                PropertiesReader propReader = new PropertiesReader(AuthorizeAction.DOMAINS_PROP_FILE);
                List<String> domainValues = propReader.getAllProperties().getProperty("domains");

                final List<String> domainList;
                if (domainValues != null && (domainValues.size() > 0)) {
                    domainList = Arrays.asList(domainValues.get(0).split(" "));
                } else {
                    domainList = null;
                }

                String token = OIDCUtil.getToken(username, scope, OIDCUtil.ACCESS_CODE_EXPIRY_MINUTES, domainList);

                // write to header and body
                syncOutput.setHeader("X-Auth-Token", token);
                OutputStream out = syncOutput.getOutputStream();
                OutputStreamWriter writer = new OutputStreamWriter(out);
                writer.write(token);
                writer.flush();

            } else if (IDTOKEN_REPSONSE_TYPE.equals(responseType)) {

                // check client id
                RelyParty rp = OIDCUtil.getRelyParty(clientID);
                if (rp == null) {
                    AuthorizeError authError = new AuthorizeError();
                    authError.error = "unauthorized_client";
                    sendError(authError);
                    return;
                }

//                String jws = OIDCUtil.buildIDToken(rp, false);
                String jws = OIDCUtil.buildIDToken(rp, syncInput.getRequestURI());

                // write to header and body
                syncOutput.setHeader("X-Auth-Token", jws);
                OutputStream out = syncOutput.getOutputStream();
                OutputStreamWriter writer = new OutputStreamWriter(out);
                writer.write(jws);
                writer.flush();

            }

        }

    }

    private void logRequestInput() {
        log.debug("scope: " + scope);
        log.debug("response_type: " + responseType);
        log.debug("client_id: " + clientID);
        log.debug("redirect_uri: " + redirectURI);
        log.debug("state: " + state);
        log.debug("response_mode: " + responseMode);
        log.debug("nonce: " + nonce);
        log.debug("display: " + display);
        log.debug("prompt: " + prompt);
        log.debug("max_age: " + maxAge);
        log.debug("ui_locales: " + uiLocales);
        log.debug("id_token_hint: " + idTokenHint);
        log.debug("login_hint: " + loginHint);
        log.debug("acr_values: " + acrValues);
    }

    private AuthorizeError missingParameter(String param) {
        AuthorizeError error = new AuthorizeError();
        error.error = "invalid_request";
        error.errorDescription = "missing required parameter '" + param + "'";
        return error;
    }

    private void sendError(AuthorizeError error) throws UnsupportedEncodingException {
        if (redirectURI == null) {
            String msg = error.error;
            if (error.errorDescription != null) {
                msg = msg + ": " + error.errorDescription;
            }
            throw new IllegalArgumentException(msg);
        }
        StringBuilder redirect = new StringBuilder(redirectURI);
        redirect.append("?error=");
        redirect.append(error.error);
        if (error.errorDescription != null) {
            redirect.append("&error_description=");
            redirect.append(URLEncoder.encode(error.errorDescription, "utf-8"));
        }
        if (state != null) {
            redirect.append("&state=");
            redirect.append(state);
        }
        syncOutput.setCode(302);
        syncOutput.setHeader("Location", redirect.toString());
    }

    private class AuthorizeError {
        String error;
        String errorDescription;
        //String error_uri;  // for when a web page explains the error
    }

}
