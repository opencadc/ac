/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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
 *  $Revision: 4 $
 *
 ************************************************************************
 */
package ca.nrc.cadc.ac.server.web.users;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import java.io.InputStream;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

public class CreateUserAction extends AbstractUserAction {
    private static final Logger log = Logger.getLogger(CreateUserAction.class);
    private final InputStream inputStream;

    CreateUserAction(final InputStream inputStream) {
        super();
        this.inputStream = inputStream;
    }


    boolean canSelfCreate(final User user) {
        // Only OpenID and X509 users can create their own CADC accounts automatically and for their identities only
        Subject sub = AuthenticationUtil.getCurrentSubject();
        if (sub == null || sub.getPrincipals().isEmpty()) {
            log.debug("Can't self-create CADC account: no subject or principals");
            return false; // no subject or principals
        }
        if (sub.getPrincipals().size() != 1) {
            log.debug("Can't self-create CADC account: subject has multiple principals");
            return false; // multiple principals
        }

        Principal subPrinc = sub.getPrincipals().iterator().next();
        if (!(subPrinc instanceof X500Principal) && !(subPrinc instanceof OpenIdPrincipal)) {
            log.debug("Can't self-create CADC account: subject principal is not X500 or OpenID");
            return false; // not X500 or OpenID principal
        }

        return user.getIdentities().size() == 1 && user.getIdentities().contains(subPrinc);
    }

    public void doAction() throws Exception {
        final User user = readUser(this.inputStream);

        if (!isPrivilegedSubject && !canSelfCreate(user)) {
            throw new AccessControlException("non-privileged user cannot create a user");
        }


        final User returnUser = userPersistence.addUser(user);

        syncOut.setCode(201);
        writeUser(returnUser);
        Set<X500Principal> x500Principals = user.getIdentities(X500Principal.class);
        if (!x500Principals.isEmpty()) {
            X500Principal x500Principal = x500Principals.iterator().next();
            logUserInfo(x500Principal.getName());
            this.logInfo.setMessage("User created: " + x500Principal.getName());
        }
    }

}
