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
        
        // TODO: big hack:  "arbutus-harbor" is the clientID and this needs to come from the current subject
        // instead of being hard-coded.  This needs to be fixed before a second RelyParty can be added.
        String jws = OIDCUtil.buildIDToken("arbutus-harbor");
        
        log.debug("set headers and return json: \n" + jws);
        syncOutput.setHeader("Content-Type", "application/jwt");
        syncOutput.setHeader("Cache-Control", "no-store");
        syncOutput.setHeader("Pragma", "no-cache");
      
        OutputStreamWriter writer = new OutputStreamWriter(syncOutput.getOutputStream());
        writer.write(jws);
        writer.flush();
        
    }
    
    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
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
