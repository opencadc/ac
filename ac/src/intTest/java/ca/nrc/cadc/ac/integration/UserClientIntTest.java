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

package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.client.UserClient;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.BasicX509TrustManager;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.RunnableAction;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpDelete;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import ca.nrc.cadc.util.Log4jInit;
import java.io.File;
import java.net.URI;
import java.net.URL;
import java.security.AccessControlException;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Enumeration;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;


public class UserClientIntTest
{
    private static final Logger log = Logger.getLogger(UserClientIntTest.class);

    private Principal x500Principal;
    private Principal httpPrincipal;
    private Principal numericPrincipal;

    private URI serviceURI;
    private UserClient userClient;

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    public UserClientIntTest()
    {
        Enumeration<Object> keys = System.getProperties().keys();

        try
        {
            serviceURI = new URI(TestUtil.AC_SERVICE_ID);

            this.userClient = new UserClient(serviceURI);

            Set<X500Principal> x500 = TestUtil.getInstance().getAugmentedOwnerSubject().getPrincipals(X500Principal.class);
            Assert.assertEquals("Single X500Principal expected in owner subject", 1, x500.size());
            this.x500Principal = x500.iterator().next();

            Set<HttpPrincipal> http = TestUtil.getInstance().getAugmentedOwnerSubject().getPrincipals(HttpPrincipal.class);
            Assert.assertEquals("Single HttpPrincipal expected in owner subject", 1, http.size());
            this.httpPrincipal = http.iterator().next();

            Set<NumericPrincipal> numeric = TestUtil.getInstance().getAugmentedOwnerSubject().getPrincipals(NumericPrincipal.class);
            Assert.assertEquals("Single NumericPrincipal expected in owner subject", 1, numeric.size());
            this.numericPrincipal = numeric.iterator().next();
        }
        catch(Exception unexpected)
        {
            log.error("setup failure", unexpected);
            throw new RuntimeException("setup failure", unexpected);
        }
    }

    protected void verifyAugmentedSubject(final Subject subject)
    {
        boolean hasHttpPrincipal = false;
        boolean hasX500Principal = false;
        boolean hasNumericPrincipal = false;
        Set<Principal> principals = subject.getPrincipals();
        for (Principal principal : principals)
        {
        	if (principal instanceof HttpPrincipal)
        	{
        		hasHttpPrincipal = true;
        	}
        	else if (principal instanceof X500Principal)
        	{
        		hasX500Principal = true;
        	}
        	else if (principal instanceof NumericPrincipal)
        	{
        		hasNumericPrincipal = true;
        	}
        }

        Assert.assertTrue("Missing HttpPrincipals", hasHttpPrincipal);
        Assert.assertTrue("Missing X500Principals", hasX500Principal);
        Assert.assertTrue("Missing NumericPrincipals", hasNumericPrincipal);
    }

    protected void testAugmentSubject(Principal p) throws Exception
    {
        try
        {
            final Subject target = new Subject();
            target.getPrincipals().add(p);
    		System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
    		Subject.doAs(TestUtil.getInstance().getPrivSubject(), new PrivilegedExceptionAction<Object>()
	    		{
					@Override
					public Object run() throws Exception
					{
						userClient.augmentSubject(target);
						return null;
					}

	    		});
            this.verifyAugmentedSubject(target);
        }
        catch(IllegalArgumentException e)
        {
        	throw e;
        }
        catch(Exception e)
        {
            log.error("unexpected", e);
            Assert.fail("Caught an unexpected exception: " + e.getMessage());
            throw e;
        }
    	finally
    	{
    		System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
    	}
    }

    @Test
    public void testAugmentSubjectWithX500Principal() throws Exception
    {
        // test subject augmentation given an X500Principal
    	this.testAugmentSubject(this.x500Principal);
    }

    @Test
    public void testAugmentSubjectWithHttpPrincipal() throws Exception
    {
        // test subject augmentation given an HttpPrincipal
    	this.testAugmentSubject(this.httpPrincipal);
    }

    @Test
    public void testAugmentSubjectWithNumericPrincipal() throws Exception
    {
        // test subject augmentation given a NumericPrincipal
    	this.testAugmentSubject(this.numericPrincipal);
    }

    @Test
    public void testListUsersAnonymous()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            UserClient userClient = new UserClient(serviceURI);
            try
            {
                userClient.getDisplayUsers();
                Assert.fail("Should have received access control exception");
            }
            catch (AccessControlException e)
            {
                // expected
            }
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

    @Test
    public void testListGroupsAnonCert()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            try
            {
                Subject.doAs(TestUtil.getInstance().getAnonSubject(), new PrivilegedExceptionAction<Object>()
                {
                    @Override
                    public Object run() throws Exception
                    {
                        try
                        {
                            UserClient userClient = new UserClient(serviceURI);
                            userClient.getDisplayUsers();
                            throw new Exception("Should have received access control exception");
                        }
                        catch (AccessControlException e)
                        {
                            // expected
                            return null;
                        }
                    }
                });
            }
            catch (Exception e)
            {
                log.error("test failed", e);
                Assert.fail(e.getMessage());
            }
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

    @Test
    public void testListGroupsWithAccount()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            Subject.doAs(TestUtil.getInstance().getOwnerSubject(), new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    UserClient userClient = new UserClient(serviceURI);


                    userClient.getDisplayUsers();
                    // the above should work
                    return null;
                }
            });
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

    @Test
    public void testCreateX509UserNullPrincipal()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            Subject.doAs(TestUtil.getInstance().getOwnerSubject(), new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    UserClient userClient = new UserClient(serviceURI);
                    try
                    {
                        userClient.createUser(null);
                        Assert.fail("should have failed");
                    }
                    catch (IllegalArgumentException e)
                    {
                        // expected
                    }
                    return null;
                }
            });
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

    @Test
    public void testCreateX509UserUnprivilegedAccount()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            Subject.doAs(TestUtil.getInstance().getOwnerSubject(), new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    UserClient userClient = new UserClient(serviceURI);
                    try
                    {
                        X500Principal p = new X500Principal(x500Principal.getName());
                        userClient.createUser(p);
                        Assert.fail("should have failed");
                    }
                    catch (AccessControlException e)
                    {
                        // expected
                    }
                    return null;
                }
            });
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

    @Test
    public void testCreateX509UserAlreadyExists()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            Subject.doAs(TestUtil.getInstance().getPrivSubject(), new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    UserClient userClient = new UserClient(serviceURI);
                    try
                    {
                        X500Principal p = new X500Principal(x500Principal.getName());
                        userClient.createUser(p);
                        Assert.fail("should have failed");
                    }
                    catch (UserAlreadyExistsException e)
                    {
                        // expected
                    }
                    return null;
                }
            });
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

    @Test
    public void testCreateX509UserSuccess()
    {
        try
        {
            System.setProperty(BasicX509TrustManager.class.getName() + ".trust", "true");
            Subject.doAs(TestUtil.getInstance().getPrivSubject(), new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    UserClient userClient = new UserClient(serviceURI);
                    String cn = "dn" + System.currentTimeMillis() + "1";
                    String dn = "CN=" + cn + ",OU=cadc,O=hia,C=ca";
                    X500Principal p = new X500Principal(dn);
                    try
                    {
                        User u = userClient.createUser(p);
                        Assert.assertNotNull(u);
                        Assert.assertNotNull(u.getID());
                        Assert.assertTrue(!u.getIdentities(X500Principal.class).isEmpty());
                        Assert.assertTrue(!u.getIdentities(NumericPrincipal.class).isEmpty());
                    }
                    finally
                    {
                        // delete the user
                        RegistryClient registryClient = new RegistryClient();
                        URL serviceURL = registryClient
                            .getServiceURL(serviceURI, Standards.UMS_USERS_01, AuthMethod.CERT);

                        String path = "/" + NetUtil.encode(dn) + "?idType=" + AuthenticationUtil.getPrincipalType(p);
                        URL deleteURL = new URL(serviceURL.toExternalForm() + "/" + path);

                        HttpDelete del = new HttpDelete(deleteURL, false);
                        Subject.doAs(TestUtil.getInstance().getPrivSubject(), new RunnableAction(del));

                        int responseCode = del.getResponseCode();
                        if (responseCode != 200)
                            log.warn("Could not delete test user");
                    }
                    return null;
                }
            });
        }
        catch (Exception e)
        {
            log.error("unexpected", e);
            Assert.fail(e.getMessage());
        }
        finally
        {
            System.clearProperty(BasicX509TrustManager.class.getName() + ".trust");
        }
    }

}
