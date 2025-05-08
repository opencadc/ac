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

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;
import java.io.OutputStreamWriter;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 * Return user info claims.  This class responds to HTTP GET calls.
 *
 * @author majorb
 */
public class UserInfoAction extends RestAction {

    private static final Logger log = Logger.getLogger(UserInfoAction.class);

    @Override
    public void doAction() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("params:");
            for (String s : syncInput.getParameterNames()) {
                log.debug("param: " + s + "=" + syncInput.getParameter(s));
            }
        }

        final Subject subject = AuthenticationUtil.getCurrentSubject();
        log.debug("Subject: " + subject);

        // Subject is set as part of authentication in cadc-util:
        // The access token is passed in as an Authorization HTTP header,
        // the userID is parsed out of that and is set as the principal
        // of the current subject.
        if (subject == null || subject.getPrincipals().isEmpty()) {
            throw new NotAuthenticatedException("unauthorized");
        }

        // validate the scope and extract the client id
        Set<AuthorizationToken> tokens = subject.getPublicCredentials(AuthorizationToken.class);
        String clientID = null;
        for (AuthorizationToken t : tokens) {
            log.debug("Token: " + t);

            if (t.getScope() != null) {
                String tScope = t.getScope().toString();
                if (tScope.startsWith(OIDCUtil.ACCESS_TOKEN_SCOPE) &&
                        tScope.length() > OIDCUtil.ACCESS_TOKEN_SCOPE.length()) {
                    int slashIndex = tScope.lastIndexOf("/");
                    if (slashIndex == OIDCUtil.ACCESS_TOKEN_SCOPE.length()) {
                        clientID = tScope.substring(slashIndex + 1);
                    }
                }
            }
        }

        log.debug("clientID: " + clientID);
        if (clientID == null) {
            throw new NotAuthenticatedException("invalid scope");
        }
        RelyParty rp = OIDCUtil.getRelyParty(clientID);
        if (rp == null) {
            throw new NotAuthenticatedException("invalid scope");
        }

        String jsonJWTClaims = OIDCUtil.buildUserInfoResponse(rp, syncInput.getRequestURI());
        log.debug("set headers and return json: \n" + jsonJWTClaims);

        // signed
        //syncOutput.setHeader("Content-Type", "application/jwt");

        // unsigned
        syncOutput.setHeader("Content-Type", "application/json");
        syncOutput.setHeader("Cache-Control", "no-store");
        syncOutput.setHeader("Pragma", "no-cache");

        OutputStreamWriter writer = new OutputStreamWriter(syncOutput.getOutputStream());
        writer.write(jsonJWTClaims);
        writer.flush();

    }

    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }

}
