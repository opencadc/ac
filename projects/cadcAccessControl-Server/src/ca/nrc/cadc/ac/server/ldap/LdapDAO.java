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
package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.net.TransientException;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import org.apache.log4j.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Set;


public abstract class LdapDAO
{
	private static final Logger logger = Logger.getLogger(LdapDAO.class);
	
    private LDAPConnection conn;

    LdapConfig config;
    DN subjDN = null;

    public LdapDAO(LdapConfig config)
    {
        if (config == null)
        {
            throw new IllegalArgumentException("LDAP config required");
        }
        this.config = config;
    }

    public void close()
    {
        if (conn != null)
        {
            conn.close();
        }
    }

    protected LDAPConnection getConnection()
            throws LDAPException, AccessControlException
    {
        if (conn == null)
        {
            conn = new LDAPConnection(getSocketFactory(), config.getServer(),
                                      config.getPort());
            conn.bind(config.getAdminUserDN(), config.getAdminPasswd());
        }

        return conn;
    }

    private SocketFactory getSocketFactory()
    {
        final SocketFactory socketFactory;

        if (config.isSecure())
        {
            socketFactory = createSSLSocketFactory();
        }
        else
        {
            socketFactory = SocketFactory.getDefault();
        }

        return socketFactory;
    }

    private SSLSocketFactory createSSLSocketFactory()
    {
        try
        {
            return new com.unboundid.util.ssl.SSLUtil().
                    createSSLSocketFactory();
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException("Unexpected error.", e);
        }
    }

    protected DN getSubjectDN() throws LDAPException
    {
        if (subjDN == null)
        {
            Subject callerSubject =
                    Subject.getSubject(AccessController.getContext());
            if (callerSubject == null)
            {
                throw new AccessControlException("Caller not authenticated.");
            }

            Set<Principal> principals = callerSubject.getPrincipals();
            if (principals.isEmpty())
            {
                throw new AccessControlException("Caller not authenticated.");
            }

            String ldapField = null;
            for (Principal p : principals)
            {
                if (p instanceof HttpPrincipal)
                {
                    ldapField = "(uid=" + p.getName() + ")";
                    break;
                }
                if (p instanceof NumericPrincipal)
                {
                    ldapField = "(numericid=" + p.getName() + ")";
                    break;
                }
                if (p instanceof X500Principal)
                {
                    ldapField = "(distinguishedname=" + p.getName() + ")";
                    break;
                }
                if (p instanceof OpenIdPrincipal)
                {
                    ldapField = "(openid=" + p.getName() + ")";
                    break;
                }
            }

            if (ldapField == null)
            {
                throw new AccessControlException("Identity of caller unknown.");
            }

            SearchResult searchResult =
                    getConnection().search(config.getUsersDN(), SearchScope.ONE,
                            "(&(objectclass=cadcaccount)(objectclass=inetorgperson)" 
                            + ldapField + ")", 
                            "entrydn");

            if (searchResult.getEntryCount() < 1)
            {
                throw new AccessControlException(
                        "No LDAP account when search with rule " + ldapField);
            }

            subjDN = (searchResult.getSearchEntries().get(0))
                    .getAttributeValueAsDN("entrydn");
        }
        return subjDN;
    }

    /**
     * Checks the Ldap result code, and if the result is not SUCCESS,
     * throws an appropriate exception. This is the place to decide on
     * mapping between ldap errors and exception types
     *
     * @param code          The code returned from an LDAP request.
     * @throws TransientException
     */
    protected static void checkLdapResult(ResultCode code)
            throws TransientException
    {
    	logger.debug("Ldap result: " + code);
        System.out.println("Ldap result: " + code);

        if (code == ResultCode.INSUFFICIENT_ACCESS_RIGHTS)
        {
            throw new AccessControlException("Not authorized ");
        }
        else if (code == ResultCode.INVALID_CREDENTIALS)
        {
            throw new AccessControlException("Invalid credentials ");
        }
        else if ((code == ResultCode.SUCCESS) || (code == ResultCode.NO_SUCH_OBJECT))
        {
            // all good. nothing to do
        }
        else if (code == ResultCode.PARAM_ERROR)
        {
            throw new IllegalArgumentException("Error in Ldap parameters ");
        }
        else if (code == ResultCode.BUSY || code == ResultCode.CONNECT_ERROR)
        {
            throw new TransientException("Connection problems ");
        }
        else
        {
            throw new RuntimeException("Ldap error (" + code.getName() + ")");
        }
    }

}
