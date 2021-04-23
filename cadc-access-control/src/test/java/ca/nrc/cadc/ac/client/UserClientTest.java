/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
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

package ca.nrc.cadc.ac.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.*;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.reg.Capabilities;
import ca.nrc.cadc.reg.client.RegistryClient;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;


public class UserClientTest
{

    private static final Logger log = Logger.getLogger(UserClientTest.class);

    private URI umsServiceURI;

    @BeforeClass
    public static void setupClass()
    {
        System.setProperty(PropertiesReader.class
                                   .getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass()
    {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    public UserClientTest()
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        LocalAuthority localAuthority = new LocalAuthority();
        umsServiceURI = localAuthority
                .getServiceURI(Standards.UMS_USERS_01.toString());
    }

    @Test
    public void testConstructor()
    {
        // case 1: test construction with a null URL
        try
        {
            new UserClient(null);
            Assert.fail("Null service URI should throw an illegalArgumentException.");
        }
        catch (IllegalArgumentException iae)
        {
            Assert.assertTrue(iae.getMessage().contains("cannot be null"));
        }
        catch (Throwable t)
        {
            Assert.fail("Unexpected exception: " + t.getMessage());
        }

        // case 2: serviceURI with a fragment
        try
        {
            URI uri = new URI("http://foo.com/bar?test#fragment");
            new UserClient(uri);
            Assert.fail("Service URI containing a fragment should throw an illegalArgumentException.");
        }
        catch (IllegalArgumentException iae)
        {
            Assert.assertTrue(iae.getMessage()
                                      .contains("fragment not allowed"));
        }
        catch (Throwable t)
        {
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
    }

    @Test
    public void testSubjectWithNoPrincipal()
    {
        try
        {
            // test subject augmentation given a subject with no principal
            Subject subject = new Subject();
            this.createUserClient().augmentSubject(subject);
            Assert.assertEquals("Should have no principal.", 0, subject
                    .getPrincipals().size());
        }
        catch (Throwable t)
        {
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
    }


    @Test
    public void testSubjectWithUnsupportedPrincipal()
    {
        Principal principal = new JMXPrincipal("APIName");
        try
        {
            // test subject augmentation given a subject with more than one principal
            Subject subject = new Subject();
            subject.getPrincipals().add(principal);
            this.createUserClient().augmentSubject(subject);
            Assert.fail("Expecting an IllegalArgumentException.");
        }
        catch (IllegalArgumentException e)
        {
            String expected = "Subject has unsupported principal";
            Assert.assertTrue(e.getMessage().startsWith(expected));
        }
        catch (Throwable t)
        {
            Assert.fail("Unexpected exception: " + t.getMessage());
        }
    }

    protected UserClient createUserClient() throws URISyntaxException,
                                                   MalformedURLException
    {
        return new UserClient(umsServiceURI);

    }

    @Test
    public void testGetSinglePrincipal()
    {
        try
        {
            UserClient c = new UserClient(umsServiceURI);

            Subject s = new Subject();
            s.getPrincipals().add(new HttpPrincipal("bob"));
            Principal p = c.getPrincipal(s);
            Assert.assertTrue(p instanceof HttpPrincipal);
            Assert.assertEquals("bob", p.getName());
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t);
        }
    }

    @Test
    public void testGetMultiplePrincipals1()
    {
        try
        {
            UserClient c = new UserClient(umsServiceURI);

            Subject s = new Subject();
            s.getPrincipals().add(new HttpPrincipal("bob"));
            UUID uuid = UUID.randomUUID();
            s.getPrincipals().add(new NumericPrincipal(uuid));
            Principal p = c.getPrincipal(s);
            Assert.assertTrue(p instanceof NumericPrincipal);
            Assert.assertEquals(uuid.toString(), p.getName());
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t);
        }
    }

    @Test
    public void testGetMultiplePrincipals2()
    {
        try
        {
            UserClient c = new UserClient(umsServiceURI);
            UUID uuid = UUID.randomUUID();

            Subject s = createSubject(
                    new Principal[]
                            {
                                    new NumericPrincipal(uuid),
                                    new HttpPrincipal("bob")
                            });

            final Principal p = c.getPrincipal(s);

            Assert.assertTrue(p instanceof NumericPrincipal);
            Assert.assertEquals(uuid.toString(), p.getName());
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t);
        }
    }

    @Test
    public void testWhoAmI() throws Exception
    {
        final String userXMLData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                   + "<user>\n"
                                   + "  <internalID>\n"
                                   + "    <uri>ivo://cadc.nrc.ca/gms?00000000-0000-0000-0000-000000000088</uri>\n"
                                   + "  </internalID>\n"
                                   + "  <identities>\n"
                                   + "    <identity type=\"HTTP\">testuser</identity>\n"
                                   + "    <identity type=\"CADC\">00000000-0000-0000-0000-000000000088</identity>\n"
                                   + "    <identity type=\"X500\">CN=testuser_e7f,OU=cadc,O=hia,C=ca</identity>\n"
                                   + "  </identities>\n"
                                   + "  <personalDetails>\n"
                                   + "    <firstName>Test</firstName>\n"
                                   + "    <lastName>User</lastName>\n"
                                   + "    <email>Test.User@nrc-cnrc.gc.ca</email>\n"
                                   + "    <address>5071 West Saanich Road</address>\n"
                                   + "    <institute>NSI-HIA</institute>\n"
                                   + "    <city>Victoria</city>\n"
                                   + "    <country>Canada</country>\n"
                                   + "  </personalDetails>\n"
                                   + "</user>";

        final OutputStream bos = new ByteArrayOutputStream();

        final URL serviceURL = new URL("http://myhost.com/users");

        final RegistryClient registryClient = new RegistryClient()
        {
            /**
             * @param resourceIdentifier
             * @param standardID
             * @param authMethod
             * @deprecated
             */
            @Override
            public URL getServiceURL(URI resourceIdentifier, URI standardID, AuthMethod authMethod)
            {
                return serviceURL;
            }
        };

        final UserClient testSubject = new UserClient(umsServiceURI)
        {
            @Override
            protected OutputStream getOutputStream()
            {
                return bos;
            }

            @Override
            protected HttpDownload download(URL url, OutputStream outputStream)
                    throws IOException
            {
                outputStream.write(userXMLData.getBytes());
                outputStream.flush();

                return new HttpDownload(url, outputStream)
                {
                    /**
                     * Get the ultimate (possibly after retries) HTTP response code.
                     *
                     * @return HTTP response code or -1 if no HTTP call made
                     */
                    @Override
                    public int getResponseCode()
                    {
                        return 200;
                    }
                };
            }

            @Override
            protected RegistryClient getRegistryClient()
            {
                return registryClient;
            }
        };

        final Subject s = createSubject(new Principal[]
                                                {
                                                        new CookiePrincipal("CADC-SSO", "COOKIESESSIONID")
                                                });

        s.getPublicCredentials().add(
                new SSOCookieCredential("COOKIESESSIONID", "my.domain", new Date(System.currentTimeMillis() + 1000*60*60*24)));

        final User u =
                Subject.doAs(s, new PrivilegedExceptionAction<User>()
                {
                    @Override
                    public User run() throws Exception
                    {
                        return testSubject.whoAmI();
                    }
                });

        Assert.assertEquals("Wrong HTTP principal.",
                            "testuser", u.getHttpPrincipal().getName());

        final Set<X500Principal> x500Principals =
                u.getIdentities(X500Principal.class);

        Assert.assertEquals("Wrong X500 Principal.",
                            "CN=testuser_e7f,OU=cadc,O=hia,C=ca",
                            x500Principals.toArray(new X500Principal[1])[0].getName());
    }

    Subject createSubject(final Principal[] principals)
    {
        final Subject subject = new Subject();

        subject.getPrincipals().addAll(Arrays.asList(principals));
        return subject;
    }

    @Test
    public void testGetMultiplePrincipals3()
    {
        try
        {
            UserClient c = new UserClient(umsServiceURI);

            Subject s = new Subject();
            UUID uuid = UUID.randomUUID();
            s.getPrincipals().add(new NumericPrincipal(uuid));
            s.getPrincipals().add(new X500Principal("CN=majorb"));
            s.getPrincipals().add(new HttpPrincipal("bob"));
            Principal p = c.getPrincipal(s);
            Assert.assertTrue(p instanceof X500Principal);
            Assert.assertEquals("CN=majorb", p.getName());
        }
        catch (Throwable t)
        {
            log.error("Unexpected exception", t);
            Assert.fail("Unexpected exception: " + t);
        }
    }
}
