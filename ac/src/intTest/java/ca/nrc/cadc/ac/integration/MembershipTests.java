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
 ************************************************************************
 */
package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.URI;
import java.net.URL;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author majorb
 *
 */
public class MembershipTests {
    
    private static final Logger log = Logger.getLogger(MembershipTests.class);
    
    static String TEST_GROUP1 = "CADC_TEST1-Staff";
    static String TEST_GROUP2 = "CADC_TEST2-Staff";
    Subject subject;
    URL searchURL;
    
    public MembershipTests() throws Exception {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        File auth1 = FileUtil
                .getFileFromResource("user1.pem", MembershipTests.class);
        subject = SSLUtil.createSubject(auth1);
        RegistryClient rc = new RegistryClient();
        searchURL = rc.getServiceURL(URI.create("ivo://cadc.nrc.ca/gms"), Standards.GMS_SEARCH_01, AuthMethod.CERT);
    }
    
    @Test
    public void testIsMemberTrue() {
        try {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    URL isMemberURL = new URL(searchURL.toString() + "?group=" + TEST_GROUP1);
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    HttpGet get = new HttpGet(isMemberURL, out);
                    get.run();
                    Assert.assertEquals(200, get.getResponseCode());
                    Assert.assertEquals("text/plain", get.getContentType());
                    String response = out.toString();
                    Assert.assertEquals(TEST_GROUP1, response.trim());
                    return null;
                }
            });
        } catch (Throwable t) {
            log.info("unexpected: " + t.getMessage(), t);
            Assert.fail("unexpected: " + t.getMessage());
        }
    }
    
    @Test
    public void testIsMemberFalse() {
        try {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    URL isMemberURL = new URL(searchURL.toString() + "?group=foo");
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    HttpGet get = new HttpGet(isMemberURL, out);
                    get.run();
                    Assert.assertEquals(200, get.getResponseCode());
                    Assert.assertEquals("text/plain", get.getContentType());
                    String response = out.toString();
                    Assert.assertEquals("", response.trim());
                    return null;
                }
            });
        } catch (Throwable t) {
            log.info("unexpected: " + t.getMessage(), t);
            Assert.fail("unexpected: " + t.getMessage());
        }
    }
    
    @Test
    public void testGetMemberships() {
        try {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    HttpGet get = new HttpGet(searchURL, out);
                    get.run();
                    Assert.assertEquals(200, get.getResponseCode());
                    Assert.assertEquals("text/plain", get.getContentType());
                    String response = out.toString();
                    String[] groups = response.split("\n");
                    boolean found1 = false, found2 = false;
                    for (String group : groups) {
                        if (TEST_GROUP1.equals(group)) {
                            found1 = true;
                        }
                        if (TEST_GROUP2.equals(group)) {
                            found2 = true;
                        }
                    }
                    Assert.assertTrue(found1);
                    Assert.assertTrue(found2);
                    return null;
                }
            });
        } catch (Throwable t) {
            log.info("unexpected: " + t.getMessage(), t);
            Assert.fail("unexpected: " + t.getMessage());
        }
    }

}
