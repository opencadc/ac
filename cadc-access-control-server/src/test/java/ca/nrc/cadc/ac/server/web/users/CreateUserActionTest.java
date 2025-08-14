/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2025.                            (c) 2025.
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
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.util.StringUtil;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CreateUserActionTest {
    @Test
    public void testCanSelfCreate() throws Exception {
        Subject subject = new Subject();
        User user = new User();
        CreateUserAction cau = new CreateUserAction(null);

        assertFalse("Self-create no subject", cau.canSelfCreate(user));
        assertFalse("Self-create with anon subject", canSelfCreateAsUser(subject, user));
        assertFalse("Self-create with no user identities", canSelfCreateAsUser(subject, user));

        user.getIdentities().add(new OpenIdPrincipal(new URL("http://issuer.com/"), "testuser"));
        assertFalse("Self-create without matching subject credentials", canSelfCreateAsUser(subject, user));
        subject.getPrincipals().add(new OpenIdPrincipal(new URL("http://issuer.com/"), "testuser"));
        assertTrue("Self-create with matching OpenId principal", canSelfCreateAsUser(subject, user));

        X500Principal x500Principal = new X500Principal("CN=testuser, O=Test Org, C=CA");
        subject.getPrincipals().add(x500Principal);
        assertFalse("Self-create with multiple principals", canSelfCreateAsUser(subject, user));
        subject.getPrincipals().clear();
        subject.getPrincipals().add(x500Principal);
        assertFalse("Self-create with no matching credentials", canSelfCreateAsUser(subject, user));

        user.getIdentities().clear();
        user.getIdentities().add(new X500Principal("CN=testuser, O=Test Org, C=CA"));
        assertTrue("Self-create with user subject", canSelfCreateAsUser(subject, user));

        // make identities not match
        user.getIdentities().clear();
        user.getIdentities().add(new X500Principal("CN=testuser2, O=Test Org, C=CA"));
        assertFalse("Self-create when credentials don't match", canSelfCreateAsUser(subject, user));

        // add extra HttpPrincipal to Subject
        subject.getPrincipals().add(new HttpPrincipal("testuser"));
        assertFalse("Self-create no subject with subject 2 OpenIDPrincipals", cau.canSelfCreate(user));
        subject.getPrincipals().clear();
        subject.getPrincipals().add(new PosixPrincipal(1000));
        assertFalse("Self-create with Posix Principal", canSelfCreateAsUser(subject, user));
    }

    private boolean canSelfCreateAsUser(Subject subject, User user) throws Exception {
        return (boolean)Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
                CreateUserAction cau = new CreateUserAction(null);
                return cau.canSelfCreate(user);
            }
        });
    }
}
