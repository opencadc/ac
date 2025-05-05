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

package org.opencadc.permissions;

import ca.nrc.cadc.util.Base64;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.RsaSignatureGenerator;
import java.io.File;
import java.net.URI;
import java.security.AccessControlException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class TokenToolTest {

    private static final Logger log = Logger.getLogger(TokenToolTest.class);

    static {
        Log4jInit.setLevel("org.opencadc.permissions", Level.INFO);
    }

    static File pubKeyFile;
    static File privateKeyFile;

    @BeforeClass
    public static void initKeys() throws Exception {
        log.info("Creating test key pair");
        String keysDir = "build/resources/test";
        pubKeyFile = new File(keysDir + "/pub.key");
        privateKeyFile = new File(keysDir + "/priv.key");
        RsaSignatureGenerator.genKeyPair(pubKeyFile, privateKeyFile, 1024);
        log.info("Created keys: " + pubKeyFile.getAbsolutePath() + " " + privateKeyFile.getAbsolutePath());
    }

    @AfterClass
    public static void cleanupKeys() throws Exception {
        if (pubKeyFile != null) {
            pubKeyFile.delete();
        }
        if (privateKeyFile != null) {
            privateKeyFile.delete();
        }
    }

    @Test
    public void testRoundTripToken() {
        try {

            final String[] uris = new String[]{
                "cadc:TEST/file.fits",
                "cadc:TEST/file.fits",
                "mast:HST/long/file/path/preview.png",
                "mast:HST/long/file/path/preview.png",
                "cadc:TEST/file.fits",
                "cadc:TEST/file.fits",};
            List<Class<? extends Grant>> grants = new ArrayList<Class<? extends Grant>>();
            grants.add(ReadGrant.class);
            grants.add(WriteGrant.class);
            grants.add(ReadGrant.class);
            grants.add(WriteGrant.class);
            grants.add(ReadGrant.class);
            grants.add(WriteGrant.class);

            String[] users = new String[]{
                "user",
                "user",
                "user",
                "user",
                "C=CA, O=Grid, OU=nrc-cnrc.gc.ca, CN=Brian Major",
                "C=CA, O=Grid, OU=nrc-cnrc.gc.ca, CN=Brian Major",};

            // keys in file
            TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
            TokenTool ver = new TokenTool(pubKeyFile);
            // keys in memory
            KeyPair keyPair = RsaSignatureGenerator.getKeyPair(4096);
            TokenTool memGen = new TokenTool(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
            TokenTool memVer = new TokenTool(keyPair.getPublic().getEncoded());

            for (int i = 0; i < uris.length; i++) {
                String uri = uris[i];
                Class<? extends Grant> grant = grants.get(i);
                String user = users[i];
                String token = gen.generateToken(URI.create(uri), grant, user);
                String actUser = ver.validateToken(token, URI.create(uri), grant);
                Assert.assertEquals("user", user, actUser);
                String token2 = memGen.generateToken(URI.create(uri), grant, user);
                String actUser2 = memVer.validateToken(token2, URI.create(uri), grant);
                Assert.assertEquals("user", actUser, actUser2);
            }

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testRoundTripTokenAnonUser() throws Exception {
        String uri = "cadc:TEST/file.fits";
        Class<? extends Grant> grant = ReadGrant.class;
        TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
        TokenTool ver = new TokenTool(pubKeyFile);
        String token = gen.generateToken(URI.create(uri), grant, null);
        String actUser = ver.validateToken(token, URI.create(uri), grant);
        Assert.assertEquals("user", null, actUser);
    }
    
    @Test
    public void testVarArgsValidate() throws Exception {
        String uri = "cadc:TEST/file.fits";
        Class<? extends Grant> grant = ReadGrant.class;
        Class<? extends Grant> otherGrant = WriteGrant.class;
        TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
        TokenTool ver = new TokenTool(pubKeyFile);
        String token = gen.generateToken(URI.create(uri), grant, null);
        
        String actUser1 = ver.validateToken(token, URI.create(uri), grant, otherGrant);
        Assert.assertEquals("user", null, actUser1);
        
        String actUser2 = ver.validateToken(token, URI.create(uri), otherGrant, grant);
        Assert.assertEquals("user", null, actUser2);
    }

    @Test
    public void testWrongURI() {
        try {

            String uri = "cadc:TEST/file.fits";
            Class readGrant = ReadGrant.class;
            String user = "user";
            TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
            TokenTool ver = new TokenTool(pubKeyFile);
            String token = gen.generateToken(URI.create(uri), readGrant, user);
            try {
                ver.validateToken(token, URI.create("cadc:TEST/file2.fits"), readGrant);
                Assert.fail("Should have failed with wrong uri");
            } catch (AccessControlException e) {
                // expected
            }

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testWrongGrant() {
        try {

            String uri = "cadc:TEST/file.fits";
            Class readGrant = ReadGrant.class;
            String user = "user";
            TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
            TokenTool ver = new TokenTool(pubKeyFile);
            String token = gen.generateToken(URI.create(uri), readGrant, user);
            try {
                ver.validateToken(token, URI.create(uri), WriteGrant.class);
                Assert.fail("Should have failed with wrong method");
            } catch (AccessControlException e) {
                // expected
            }

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testTamperMetadata() {
        try {

            String uri = "cadc:TEST/file.fits";
            Class readGrant = ReadGrant.class;
            String user = "user";
            TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
            TokenTool ver = new TokenTool(pubKeyFile);
            String token = gen.generateToken(URI.create(uri), readGrant, user);
            String[] parts = token.split("~");
            String newToken = TokenTool.base64URLEncode(new String(Base64.encode("junk".getBytes()))) + "~" + parts[1];
            try {
                ver.validateToken(newToken, URI.create(uri), readGrant);
                Assert.fail("Should have failed with invalid metadata");
            } catch (AccessControlException e) {
                // expected
            }

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testTamperSignature() {
        try {

            String uri = "cadc:TEST/file.fits";
            Class readGrant = ReadGrant.class;
            String user = "user";
            TokenTool gen = new TokenTool(pubKeyFile, privateKeyFile);
            TokenTool ver = new TokenTool(pubKeyFile);
            String token = gen.generateToken(URI.create(uri), readGrant, user);
            String[] parts = token.split("~");
            String newToken = parts[0] + "~" + TokenTool.base64URLEncode(new String(Base64.encode("junk".getBytes())));
            try {
                ver.validateToken(newToken, URI.create(uri), readGrant);
                Assert.fail("Should have failed with invalid signature");
            } catch (AccessControlException e) {
                // expected
            }

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

}
