/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2023.                            (c) 2023.
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

package org.opencadc.auth;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationTokenPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.PrincipalExtractor;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.StringUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author pdowler
 */
public class StandardIdentityManagerTest {
    private static final Logger log = Logger.getLogger(StandardIdentityManagerTest.class);

    static {
        Log4jInit.setLevel("ca.nrc.cadc.auth", Level.INFO);
        Log4jInit.setLevel("org.opencadc.auth", Level.INFO);
    }
    
    private X509CertificateChain chain;
    
    public StandardIdentityManagerTest() throws Exception {
        String certFilename = System.getProperty("user.name") + ".pem";
        File pem = FileUtil.getFileFromResource(certFilename, StandardIdentityManagerTest.class);
        this.chain = SSLUtil.readPemCertificateAndKey(pem);
        
        System.setProperty(IdentityManager.class.getName(), StandardIdentityManager.class.getName());
    }
    
    @Test
    public void testAnon() {
        try {
            Subject s = AuthenticationUtil.getAnonSubject();
            log.info("orig: " + s);
            final StandardIdentityManager im = new StandardIdentityManager();
            
            Subject validated = im.validate(s);
            log.info("validated: " + validated);
            Assert.assertTrue(validated.getPrincipals().isEmpty());
            
            Subject augmented = im.augment(validated);
            log.info("augmented: " + augmented);
            Assert.assertTrue(augmented.getPrincipals().isEmpty());
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }
    
    @Test
    public void testX509() {
        try {
            Subject validated = AuthenticationUtil.getSubject(new DummyPrincipalExtractor(true, false), false);
            final StandardIdentityManager im = new StandardIdentityManager();
            log.info("validated: " + validated);
            Assert.assertFalse("x509 DN", validated.getPrincipals(X500Principal.class).isEmpty());
            
            Subject augmented = im.augment(validated);
            log.info("augmented: " + augmented);
            Assert.assertFalse("x509 DN", validated.getPrincipals(X500Principal.class).isEmpty());
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }
    
    @Test
    public void testAccessToken() {
        try {
            Subject validated = AuthenticationUtil.getSubject(new DummyPrincipalExtractor(false, true), false);
            final StandardIdentityManager im = new StandardIdentityManager();
            log.info("validated: " + validated);
            Assert.assertFalse("oidc uuid", validated.getPrincipals(NumericPrincipal.class).isEmpty());
            Assert.assertFalse("oidc username", validated.getPrincipals(HttpPrincipal.class).isEmpty());
            
            Subject augmented = im.augment(validated);
            log.info("augmented: " + augmented);
            Assert.assertFalse("oidc uuid", validated.getPrincipals(NumericPrincipal.class).isEmpty());
            Assert.assertFalse("oidc username", validated.getPrincipals(HttpPrincipal.class).isEmpty());
            
            final Object owner = im.toOwner(augmented);
            Subject s = im.toSubject(owner);
            log.info("owner round trip: " + s);
            Assert.assertNotNull(s);
            Assert.assertFalse(s.getPrincipals(NumericPrincipal.class).isEmpty());
            Assert.assertTrue(s.getPrincipals(HttpPrincipal.class).isEmpty());
            
            // test using current subject as cache for augment
            Subject as = Subject.doAs(augmented, (PrivilegedExceptionAction<Subject>) () -> im.toSubject(owner));
            log.info("owner round trip inside doAs(augmented): " + as);
            Assert.assertNotNull(as);
            Assert.assertFalse(as.getPrincipals(NumericPrincipal.class).isEmpty());
            Assert.assertFalse(as.getPrincipals(HttpPrincipal.class).isEmpty());
            
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }
    
    private class DummyPrincipalExtractor implements PrincipalExtractor {

        private boolean x509;
        private boolean oidc;
        
        public DummyPrincipalExtractor(boolean x509, boolean oidc) {
            this.x509 = x509;
            this.oidc = oidc;
        }
        
        @Override
        public Set<Principal> getPrincipals() {
            Set<Principal> ret = new HashSet<>();
            if (x509) {
                ret.add(chain.getPrincipal());
            }
            if (oidc) {
                File tt = new File("test-access-token.txt");
                try {
                    
                    String st = StringUtil.readFromInputStream(new FileInputStream(tt), "UTF-8").trim();
                    AuthorizationTokenPrincipal atp = new AuthorizationTokenPrincipal("authorization", "bearer " + st);
                    ret.add(atp);
                } catch (IOException ex) {
                    throw new RuntimeException("failed to read " + tt.getName(), ex);
                }
            }
            return ret;
        }

        @Override
        public X509CertificateChain getCertificateChain() {
            if (x509) {
                return chain;
            }
            return null;
        }
        
    }
}
