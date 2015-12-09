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
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.xml.UserReader;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.NetUtil;


/**
 * Client class for performing user searching and user actions
 * with the access control web service.
 */
public class UserClient
{
    private static final Logger log = Logger.getLogger(UserClient.class);

    // socket factory to use when connecting
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
    	Principal principal = this.getPrincipal(subject);
    	if (principal != null)
    	{
	        URL url = this.getURL(principal);
	    	log.debug("augmentSubject request to " + url.toString());
	        ByteArrayOutputStream out = new ByteArrayOutputStream();
	        HttpDownload download = new HttpDownload(url, out);
	        download.run();

	        int responseCode = download.getResponseCode();
	        if (responseCode == 404) // not found
	        {
	            return;
	        }
	        if (responseCode != 200)
	        {
	            String message = "Error calling /ac to augment subject";
	            if (download.getThrowable() != null)
	            {
	                throw new IllegalStateException(message, download.getThrowable());
	            }
	            throw new IllegalStateException(message);
	        }

	        subject.getPrincipals().clear();
	        subject.getPrincipals().addAll(this.getPrincipals(out));
    	}
    }



    protected Principal getPrincipal(final Subject subject)
    {
        if (subject == null || subject.getPrincipals() == null || subject.getPrincipals().isEmpty())
        {
            return null;
        }

        if (subject.getPrincipals().size() == 1)
        {
            return subject.getPrincipals().iterator().next();
        }

        // in the case that there is more than one principal in the
        // subject, favor x500 principals then numeric principals
        Set<X500Principal> x500Principals = subject.getPrincipals(X500Principal.class);
        if (x500Principals.size() > 0)
        {
            return x500Principals.iterator().next();
        }

        Set<NumericPrincipal> numericPrincipals = subject.getPrincipals(NumericPrincipal.class);
        if (numericPrincipals.size() > 0)
        {
            return numericPrincipals.iterator().next();
        }

        // just return the first one
        return subject.getPrincipals().iterator().next();
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

    protected URL getURL(Principal principal)
    {
		try
		{
		    String userID = principal.getName();
			URL url = new URL(this.baseURL + "/users/" + NetUtil.encode(userID) +
					"?idType=" + this.getIdType(principal) + "&detail=identity");
			log.debug("getURL(): returned url ="
					+ ""
					+ " " + url.toString());
			return url;
		}
		catch (MalformedURLException e)
		{
			throw new RuntimeException(e);
		}
    }

    protected String getIdType(Principal principal)
    {
		String idTypeStr = AuthenticationUtil.getPrincipalType(principal);
        if (idTypeStr == null)
        {
    		final String msg = "Subject has unsupported principal " +
    				principal.getName();
	        throw new IllegalArgumentException(msg);
        }

        return idTypeStr;
    }
}
