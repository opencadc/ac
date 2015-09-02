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

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.Set;

import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import ca.nrc.cadc.ac.*;
import ca.nrc.cadc.auth.HttpPrincipal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.xml.UserReader;
import ca.nrc.cadc.auth.CookiePrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.HttpDownload;


/**
 * Client class for performing user searching and user actions
 * with the access control web service.
 */
public class UserClient
{
    private static final Logger log = Logger.getLogger(UserClient.class);

    // socket factory to use when connecting
    private SSLSocketFactory sslSocketFactory;
    private SSLSocketFactory mySocketFactory;
    private String baseURL;

    /**
     * Constructor.
     *
     * @param baseURL The URL of the supporting access control web service
     *                obtained from the registry.
     */
    public UserClient(final String baseURL)
            throws IllegalArgumentException
    {
        if (baseURL == null)
        {
            throw new IllegalArgumentException("baseURL is required");
        }
        try
        {
            new URL(baseURL);
        }
        catch (MalformedURLException e)
        {
            throw new IllegalArgumentException("URL is malformed: " +
                                               e.getMessage());
        }

        if (baseURL.endsWith("/"))
        {
            this.baseURL = baseURL.substring(0, baseURL.length() - 1);
        }
        else
        {
            this.baseURL = baseURL;
        }
    }

    /**
     * This method takes a subject with at least one valid principal, 
     * uses the ac user web service to get all the other 
     * associated principals which are then added to the subject.
     *
     * @param subject           The Subject to pull Princials for.
     */
    public void augmentSubject(Subject subject)
    {
        URL url = this.getURL(subject);
    	log.debug("augmentSubject request to " + url.toString());    	
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpDownload download = new HttpDownload(url, out);

        download.setSSLSocketFactory(getSSLSocketFactory());
        download.run();
     
        this.handleThrowable(download);
        this.augmentSubject(subject, this.getPrincipals(out));
    }
    
    protected void augmentSubject(Subject subject, Set<Principal> principals)
    {
        if (principals.isEmpty())
        {
        	String name = subject.getPrincipals().iterator().next().getName();
        	String msg = "No UserIdentity in LDAP server for principal: " + name;
        	throw new IllegalStateException(msg);
        }
        
    	for (Principal principal : principals)
    	{
    		if (principal instanceof HttpPrincipal)
    		{
    			subject.getPrincipals().add((HttpPrincipal)principal);
    		}
    		else if (principal instanceof X500Principal)
    		{
    			subject.getPrincipals().add((X500Principal)principal);
    		}
    		else if (principal instanceof NumericPrincipal)
    		{
    			subject.getPrincipals().add((NumericPrincipal)principal);
    		}
    		else if (principal instanceof CookiePrincipal)
    		{
    			subject.getPrincipals().add((CookiePrincipal)principal);
    		}
            else
            {
        		final String msg = "Subject has unsupported principal " +
        				principal.getName() + 
        				", not one of (X500, Cookie, HTTP or Cadc).";
		        throw new IllegalStateException(msg);
            }
    	}
    }
    
    protected Set<Principal> getPrincipals(ByteArrayOutputStream out)
    {
    	try
    	{
	        String userXML = new String(out.toByteArray(), "UTF-8");
	        log.debug("userXML Input to getPrincipals(): " + userXML);
	        
	        User<Principal> user = new UserReader().read(userXML);
	        return user.getIdentities();
    	}
    	catch (Exception e)
    	{
    		throw new RuntimeException(e);
    	}
    }
    
    protected void handleThrowable(HttpDownload download)
    {
    	Throwable throwable = download.getThrowable();
        if (throwable != null)
        {
            log.debug("handleThrowable(): throwable (" + download
                    .getResponseCode() + ")", throwable);
            throw new IllegalStateException(throwable.getMessage());
        }
    }
    
    protected URL getURL(Subject subject)
    {
		try 
		{
		    String userID = subject.getPrincipals().iterator().next().getName();
		    String encodedUserID = URLEncoder.encode(userID, "UTF-8");
			URL url = new URL(this.baseURL + "/users/" + encodedUserID + 
					"?idType=" + this.getIdType(subject) + "&detail=identity");
			log.debug("getURL(): returned url ="
					+ ""
					+ " " + url.toString());
			return url;
		} 
		catch (UnsupportedEncodingException e) 
		{
			throw new RuntimeException(e);
		}
		catch (MalformedURLException e)
		{
			throw new RuntimeException(e);
		}
    }
    
    protected String getIdType(Subject subject)
    {
    	Set<Principal> principals = subject.getPrincipals();
    	if (principals.size() > 0)
    	{
        	String idTypeStr = null;
    		Principal principal = principals.iterator().next();
            if (principal instanceof HttpPrincipal)
            {
            	idTypeStr = IdentityType.USERNAME.getValue();
            }
            else if (principal instanceof X500Principal)
            {
            	idTypeStr = IdentityType.X500.getValue();
            }
            else if (principal instanceof NumericPrincipal)
            {
            	idTypeStr = IdentityType.CADC.getValue();
            }
            else if (principal instanceof CookiePrincipal)
            {
            	idTypeStr = IdentityType.COOKIE.getValue();
            }   		
            else
            {
        		final String msg = "Subject has unsupported principal " +
        				principal.getName() + 
        				", not one of (X500, Cookie, HTTP or Cadc).";
		        throw new IllegalArgumentException(msg);
            }
            
            return idTypeStr;
    	}
    	else
    	{
    		final String msg = "Subject has no principal.";
    		throw new IllegalArgumentException(msg);
    	}
    }

    /**
     * @param sslSocketFactory the sslSocketFactory to set
     */
    public void setSSLSocketFactory(SSLSocketFactory sslSocketFactory)
    {
        if (mySocketFactory != null)
        {
            throw new IllegalStateException(
            		"Illegal use of GMSClient: cannot set SSLSocketFactory " +
                    "after using one created from Subject");
        }
        this.sslSocketFactory = sslSocketFactory;
        clearCache();
    }

    private int subjectHashCode = 0;

    private SSLSocketFactory getSSLSocketFactory()
    {
        AccessControlContext ac = AccessController.getContext();
        Subject s = Subject.getSubject(ac);

        // no real Subject: can only use the one from setSSLSocketFactory
        if (s == null || s.getPrincipals().isEmpty())
        {
            return sslSocketFactory;
        }

        // lazy init
        if (this.mySocketFactory == null)
        {
            log.debug("getSSLSocketFactory: " + s);
            this.mySocketFactory = SSLUtil.getSocketFactory(s);
            this.subjectHashCode = s.hashCode();
        }
        else
        {
            int c = s.hashCode();
            if (c != subjectHashCode)
            {
                throw new IllegalStateException(
                		"Illegal use of " + this.getClass().getSimpleName() +
                		": subject change not supported for internal " +
                		"SSLSocketFactory");
            }
        }
        return this.mySocketFactory;
    }

    protected void clearCache()
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);

        if (subject != null)
        {
            log.debug("Clearing cache");
            subject.getPrivateCredentials().clear();
        }
    }
}
