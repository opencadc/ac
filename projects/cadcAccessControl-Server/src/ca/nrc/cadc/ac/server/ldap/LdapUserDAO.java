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

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.net.TransientException;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

public class LdapUserDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapUserDAO.class);

    // Map of identity type to LDAP attribute
    private Map<Class<?>, String> attribType = new HashMap<Class<?>, String>();

    public LdapUserDAO(LdapConfig config)
    {
        super(config);
        this.attribType.put(HttpPrincipal.class, "cn");
        this.attribType.put(X500Principal.class, "distinguishedname");
        this.attribType.put(NumericPrincipal.class, "entryid");
    }

    /**
     * Get the user specified by userID.
     * 
     * @param userID The unique userID.
     * @return User instance.
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public User<T> getUser(T userID)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        String searchField = (String) attribType.get(userID.getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        searchField = "(" + searchField + "=" + userID.getName() + ")";

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest = new SearchRequest(config.getUsersDN(), 
                    SearchScope.SUB, searchField, 
                    new String[] {"cn", "entryid", "entrydn", "dn"});

            searchRequest.addControl(
                    new ProxiedAuthorizationV1RequestControl(getSubjectDN()));

            searchResult = getConnection().searchForEntry(searchRequest);
        }
        catch (LDAPException e)
        {
            e.printStackTrace();
        }

        if (searchResult == null)
        {
            String msg = "User not found " + userID.toString();
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        User<T> user = new User<T>(userID);
        user.getIdentities().add(
                new HttpPrincipal(searchResult.getAttributeValue("cn")));

        user.getIdentities().add(
                new NumericPrincipal(
                        searchResult.getAttributeValueAsInteger("entryid")));

        return user;
    }

    /**
     * Returns a member user identified by the X500Principal only.
     * @param userDN
     * @return
     * @throws UserNotFoundException
     * @throws LDAPException
     */
    User<X500Principal> getMember(DN userDN)
        throws UserNotFoundException, LDAPException
    {
        SearchResultEntry searchResult = getConnection().getEntry(
                userDN.toNormalizedString(), 
                        (String[]) this.attribType.values().toArray(
                                new String[this.attribType.values().size()]));

        if (searchResult == null)
        {
            String msg = "User not found " + userDN;
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        User<X500Principal> user = new User<X500Principal>(
                new X500Principal(searchResult.getAttributeValue(
                        (String) attribType.get(X500Principal.class))));

        return user;
    }

    DN getUserDN(User<? extends Principal> user)
        throws LDAPException, UserNotFoundException
    {
        String searchField = (String) attribType.get(user.getUserID().getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                "Unsupported principal type " + user.getUserID().getClass());
        }

        searchField = "(" + searchField + "=" + 
                      user.getUserID().getName() + ")";

        SearchRequest searchRequest = 
                new SearchRequest(this.config.getUsersDN(), SearchScope.SUB, 
                                 searchField, new String[] {"entrydn"});

        searchRequest.addControl(
                new ProxiedAuthorizationV1RequestControl(getSubjectDN()));

        SearchResultEntry searchResult = 
                getConnection().searchForEntry(searchRequest);

        if (searchResult == null)
        {
            String msg = "User not found " + user.getUserID().toString();
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        return searchResult.getAttributeValueAsDN("entrydn");
    }

}
