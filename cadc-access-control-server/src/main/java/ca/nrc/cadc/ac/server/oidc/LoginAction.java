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

import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.ldap.LdapUserPersistence;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;

import java.net.URI;
import java.security.AccessControlException;

import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;

/**
 * 
 * Authenticate username password and redirect to the RelyParty.  This class responds
 * to HTTP POST calls.
 *
 * @author majorb
 *
 */
public class LoginAction extends RestAction {
    
    private static final Logger log = Logger.getLogger(LoginAction.class);

    @Override
    public void doAction() throws Exception {

        String redirectURI = syncInput.getParameter("redirect_uri");
        String state = syncInput.getParameter("state");
        String username = syncInput.getParameter("username");
        String password = syncInput.getParameter("password");
        String clientID = syncInput.getParameter("clientid");
        log.debug("redirect_uri: " + redirectURI);
        log.debug("state: " + state);
        log.debug("username: " + username);
        if (redirectURI == null) {
            throw new IllegalArgumentException("missing required param 'redirect_uri'");
        }
        if (username == null) {
            throw new IllegalArgumentException("missing required param 'username'");
        }
        if (password == null) {
            throw new IllegalArgumentException("missing required param 'password'");
        }
        
        UserPersistence userPersistence = new LdapUserPersistence();
        Boolean loginResult = null;
        try {
            loginResult = userPersistence.doLogin(username, password);
        } catch (AccessControlException e) {
            throw new AccessControlException("login failed");
        }
        if (loginResult == null || !loginResult) {
            // doLogin() method API is awkward -- don't think loginResult can be null but
            // check just in case.
            throw new AccessControlException("login failed");
        }
        
        // TODO Alinga
        // Add group check on rp.accessGroup here
        // (will require client_id to be passed from AuthorizeAction, to oidc-login.html, to here)
        if (!OIDCUtil.accessAllowed(clientID)) {
            GroupURI accessGroup = OIDCUtil.getRelyParty(clientID).getAccessGroup();
            String msg = "login failed, group access check failed, not a member of " + accessGroup;
            throw new AccessControlException(msg);
        }
        
        // formulate the authenticate redirect response
        StringBuilder redirect = new StringBuilder(redirectURI);
        URI scope = URI.create(OIDCUtil.AUTHORIZE_TOKEN_SCOPE);
        String code = OIDCUtil.getToken(username, scope, OIDCUtil.AUTHORIZE_CODE_EXPIRY_MINUTES);
        redirect.append("?code=");
        redirect.append(code);
        if (state != null) {
            redirect.append("&state=");
            redirect.append(state);
        }
        log.debug("redirecting to: " + redirect);
        syncOutput.setCode(302);
        syncOutput.setHeader("Location", redirect);
    }
    
    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }

}
