/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2017.                            (c) 2017.
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

package ca.nrc.cadc.ac;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author pdowler
 */
public class ACIdentityManagerTest {

    private static final Logger log = Logger.getLogger(ACIdentityManagerTest.class);

    static {
        Log4jInit.setLevel("ca.nrc.cadc.auth", Level.INFO);
    }

    public ACIdentityManagerTest() {
    }

    /**
     * A user with only a certificate in the subject should be allowed to
     * continue and be identified as having an auth method of 'cert'.
     */
    @Test
    public void testCertOnlyUser() {
        try {
            String dn = "cn=testuser, ou=cadc, o=nrc";
            IdentityManager ai = new ACIdentityManager();
            Subject subject = new Subject();
            subject.getPrincipals().add(new X500Principal(dn));
            subject.getPublicCredentials().add(AuthMethod.CERT);
            subject = ai.validate(subject);

            Assert.assertEquals(AuthMethod.CERT, AuthenticationUtil.getAuthMethod(subject));
        } catch (Exception ex) {
            log.error("unexpected exception", ex);
            Assert.fail("Unexpected exception: " + ex);
        }
    }
    
    @Test
    public void testToSubject() {
        try {
            final NumericPrincipal expected = new NumericPrincipal(new UUID(0L, 123L));
            Object[] num = new Object[] {
                Integer.valueOf(123), Long.valueOf(123L), "123"
            };
            
            
            ACIdentityManager im = new ACIdentityManager();
            for (Object o : num) {
                Subject s = im.toSubjectImpl(o);
                Assert.assertNotNull(s);
                Set<NumericPrincipal> pset = s.getPrincipals(NumericPrincipal.class);
                Assert.assertFalse(pset.isEmpty());
                NumericPrincipal np = pset.iterator().next();
                Assert.assertEquals(expected, np);
            }
            
            // x509 DN handling
            String dn = "cn=testuser, ou=cadc, o=nrc";
            X500Principal ex500 = new X500Principal(dn);
            Subject s = im.toSubjectImpl(dn);
            Assert.assertNotNull(s);
            Set<X500Principal> pset = s.getPrincipals(X500Principal.class);
            Assert.assertFalse(pset.isEmpty());
            X500Principal xp = pset.iterator().next();
            Assert.assertTrue(AuthenticationUtil.equals(ex500, xp));
        } catch (Exception ex) {
            log.error("unexpected exception", ex);
            Assert.fail("Unexpected exception: " + ex);
        }
    }
}
