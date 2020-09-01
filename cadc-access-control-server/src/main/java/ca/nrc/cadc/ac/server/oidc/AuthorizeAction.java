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

import ca.nrc.cadc.rest.RestAction;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import org.apache.log4j.Logger;

/**
 * 
 * Authorize the RelyParty to obtain a OAuth2 token by ensuring
 * the client is authenticated and has given consent.
 *
 * @author majorb
 *
 */
public abstract class AuthorizeAction extends RestAction {
    
    private static final Logger log = Logger.getLogger(AuthorizeAction.class);
    
    protected String scope;
    protected String response_type;
    protected String client_id;
    protected String redirect_uri;
    protected String state;
    protected String response_mode;
    protected String nonce;
    protected String display;
    protected String prompt;
    protected String max_age;
    protected String ui_locales;
    protected String id_token_hint;
    protected String login_hint;
    protected String acr_values;
    
    protected abstract void loadRequestInput();
    
    @Override
    public void doAction() throws Exception {
        
        loadRequestInput();
        AuthorizeError validateError = validateRequestInput();
        if (validateError != null) {
            sendError(validateError);
            return;
        }
        
        // check client id
        RelyParty rp = OIDCUtil.getRelyParty(client_id);
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
        
        // send redirect to username/password form
        StringBuilder redirect = new StringBuilder("oidc-login.html#redirect_uri=");
        redirect.append(redirect_uri);
        if (login_hint != null) {
            redirect.append("&username=");
            redirect.append(login_hint);
        }
        if (state != null) {
            redirect.append("&state=");
            redirect.append(state);
        }
        syncOutput.setCode(302);
        syncOutput.setHeader("Location", redirect);

    }
    
    private AuthorizeError validateRequestInput() {
        log.debug("scope: " + scope);
        log.debug("response_type: " + response_type);
        log.debug("client_id: " + client_id);
        log.debug("redirect_uri: " + redirect_uri);
        log.debug("state: " + state);
        log.debug("response_mode: " + response_mode);
        log.debug("nonce: " + nonce);
        log.debug("display: " + display);
        log.debug("prompt: " + prompt);
        log.debug("max_age: " + max_age);
        log.debug("ui_locales: " + ui_locales);
        log.debug("id_token_hint: " + id_token_hint);
        log.debug("login_hint: " + login_hint);
        log.debug("acr_values: " + acr_values);
        
        // check required params
        if (redirect_uri == null) {
            return missingParameter("redirect_uri");
        }
        if (scope == null) {
            return missingParameter("scope");
        }
        if (response_type == null) {
            return missingParameter("response_type");
        }
        if (client_id == null) {
            return missingParameter("client_id");
        }
        
        // TODO: check other values
        return null;
    }
    
    private AuthorizeError missingParameter(String param) {
        AuthorizeError error = new AuthorizeError();
        error.error = "invalid_request";
        error.error_description = "missing required parameter '" + param + "'";
        return error;
    }
    
    private void sendError(AuthorizeError error) throws UnsupportedEncodingException {
        if (redirect_uri == null) {
            throw new IllegalArgumentException("missing required param 'redirect_uri'");
        }
        StringBuilder redirect = new StringBuilder(redirect_uri);
        redirect.append("?error=");
        redirect.append(error.error);
        if (error.error_description != null) {
            redirect.append("&error_description=");
            redirect.append(URLEncoder.encode(error.error_description, "utf-8"));
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
        String error_description;
        //String error_uri;  // for when a web page explains the error
    }

}
