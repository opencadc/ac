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

import java.security.AccessControlException;
import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;

import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;

public class LdapUserDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapUserDAO.class);

    // Map of identity type to LDAP attribute
    private Map<Class<?>, String> userLdapAttrib = new HashMap<Class<?>, String>();
    
    // User attributes returned to the GMS
    private static final String LDAP_FNAME = "givenname";
    private static final String LDAP_LNAME = "sn";
    //TODO to add the rest
    private String[] userAttribs = new String[]{LDAP_FNAME, LDAP_LNAME};
    private String[] memberAttribs = new String[]{LDAP_FNAME, LDAP_LNAME};

    public LdapUserDAO(LdapConfig config)
    {
        super(config);
        this.userLdapAttrib.put(HttpPrincipal.class, "uid");
        this.userLdapAttrib.put(X500Principal.class, "distinguishedname");
        
        // add the id attributes to user and member attributes
        String[] princs = userLdapAttrib.values().toArray(new String[userLdapAttrib.values().size()]);
        String[] tmp = new String[userAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(userAttribs, 0, tmp, princs.length, userAttribs.length);
        userAttribs = tmp;
        
        tmp = new String[memberAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(memberAttribs, 0, tmp, princs.length, memberAttribs.length);
        memberAttribs = tmp;
    }

    /**
     * Get the user specified by userID.
     *
     * @param userID The userID.
     *
     * @return User instance.
     * 
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> getUser(T userID)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        String searchField = (String) userLdapAttrib.get(userID.getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        searchField = "(&(objectclass=cadcaccount)(" + searchField + "=" + userID.getName() + "))";

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest = new SearchRequest(config.getUsersDN(), 
                    SearchScope.SUB, searchField, userAttribs);
 
            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            searchResult = getConnection().searchForEntry(searchRequest);
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
        }

        if (searchResult == null)
        {
            String msg = "User not found " + userID.toString();
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        User<T> user = new User<T>(userID);
        user.getIdentities().add(
                new HttpPrincipal(searchResult.getAttributeValue(userLdapAttrib
                        .get(HttpPrincipal.class))));
        
        String fname = searchResult.getAttributeValue(LDAP_FNAME);
        String lname = searchResult.getAttributeValue(LDAP_LNAME);
        user.details.add(new PersonalDetails(fname, lname));
        //TODO populate user with the other returned personal or posix attributes
        return user;
    }   

    /**
     * Get all groups the user specified by userID belongs to.
     * 
     * @param userID The userID.
     * @param isAdmin
     * 
     * @return Collection of Group instances.
     * 
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public Collection<DN> getUserGroups(final T userID, final boolean isAdmin)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        Collection<DN> groupDNs = new HashSet<DN>();
        try
        {
            String searchField = (String) userLdapAttrib.get(userID.getClass());
            if (searchField == null)
            {
                throw new IllegalArgumentException(
                        "Unsupported principal type " + userID.getClass());
            }

            User<T> user = getUser(userID);            
            Filter filter = Filter.createANDFilter(
                        Filter.createEqualityFilter(searchField, 
                                                    user.getUserID().getName()),
                        Filter.createPresenceFilter("memberOf"));

            SearchRequest searchRequest = 
                    new SearchRequest(config.getUsersDN(), SearchScope.SUB, 
                                      filter, "memberOf");

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));

            SearchResultEntry searchResult = 
                    getConnection().searchForEntry(searchRequest);
            
            DN parentDN;
            if (isAdmin)
            {
                parentDN = new DN(config.getAdminGroupsDN());
            }
            else
            {
                parentDN = new DN(config.getGroupsDN());
            }
            
            if (searchResult != null)
            {
                String[] members = searchResult.getAttributeValues("memberOf");
                if (members != null)
                {
                    for (String member : members)
                    {
                        DN groupDN = new DN(member);
                        if (groupDN.isDescendantOf(parentDN, false))
                        {
                            groupDNs.add(groupDN);
                        }
                    }
                }
            } 
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
        }
        return groupDNs;
    }
    
    /**
     * Check whether the user is a member of the group.
     *
     * @param userID The userID.
     * @param groupID The groupID.
     *
     * @return true or false
     *
     * @throws UserNotFoundException If the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public boolean isMember(T userID, String groupID)
        throws UserNotFoundException, TransientException,
               AccessControlException
    {
        try
        {
            String searchField = (String) userLdapAttrib.get(userID.getClass());
            if (searchField == null)
            {
                throw new IllegalArgumentException(
                        "Unsupported principal type " + userID.getClass());
            }

            User<T> user = getUser(userID);
            Filter filter = Filter.createANDFilter(
                        Filter.createEqualityFilter(searchField, 
                                                    user.getUserID().getName()),
                        Filter.createEqualityFilter("memberOf", groupID));

            SearchRequest searchRequest = 
                    new SearchRequest(config.getUsersDN(), SearchScope.SUB, 
                                      filter, new String[] {"cn"});

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" + 
                            getSubjectDN().toNormalizedString()));
            
            SearchResultEntry searchResults = 
                    getConnection().searchForEntry(searchRequest);
            
            if (searchResults == null)
            {
                return false;
            }
            return true;
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
        }
        return false;
    }
    
//    public boolean isMember(T userID, String groupID)
//        throws UserNotFoundException, TransientException,
//               AccessControlException
//    {
//        try
//        {
//            String searchField = (String) userLdapAttrib.get(userID.getClass());
//            if (searchField == null)
//            {
//                throw new IllegalArgumentException(
//                        "Unsupported principal type " + userID.getClass());
//            }
//
//            User<T> user = getUser(userID);
//            DN userDN = getUserDN(user);
//
//            CompareRequest compareRequest = 
//                    new CompareRequest(userDN.toNormalizedString(), 
//                                      "memberOf", groupID);
//            
//            compareRequest.addControl(
//                    new ProxiedAuthorizationV2RequestControl("dn:" + 
//                            getSubjectDN().toNormalizedString()));
//            
//            CompareResult compareResult = 
//                    getConnection().compare(compareRequest);
//            return compareResult.compareMatched();
//        }
//        catch (LDAPException e)
//        {
//            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
//            throw new RuntimeException("Unexpected LDAP exception", e);
//        }
//    }
    
    /**
     * Returns a member user identified by the X500Principal only. The
     * returned object has the fields required by the GMS.
     * Note that this method binds as a proxy user and not as the 
     * subject.
     * @param userDN
     * @return
     * @throws UserNotFoundException
     * @throws LDAPException
     */
    User<X500Principal> getMember(DN userDN)
        throws UserNotFoundException, LDAPException
    {
        Filter filter = 
            Filter.createEqualityFilter("entrydn", 
                                        userDN.toNormalizedString());
        
        SearchRequest searchRequest = 
                new SearchRequest(this.config.getUsersDN(), SearchScope.SUB, 
                                  filter, memberAttribs);
        
        SearchResultEntry searchResult = 
                getConnection().searchForEntry(searchRequest);

        if (searchResult == null)
        {
            String msg = "Member not found " + userDN;
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        User<X500Principal> user = new User<X500Principal>(
                new X500Principal(searchResult.getAttributeValue(
                        (String) userLdapAttrib.get(X500Principal.class))));
        String princ = searchResult.getAttributeValue(
                (String) userLdapAttrib.get(HttpPrincipal.class));
        if (princ != null)
        {
            user.getIdentities().add(new HttpPrincipal(princ));
        }
        String fname = searchResult.getAttributeValue(LDAP_FNAME);
        String lname = searchResult.getAttributeValue(LDAP_LNAME);
        user.details.add(new PersonalDetails(fname, lname));
        return user;
    }
    

    DN getUserDN(User<? extends Principal> user)
        throws UserNotFoundException, TransientException
    {
        String searchField = (String) userLdapAttrib.get(user.getUserID().getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                "Unsupported principal type " + user.getUserID().getClass());
        }

        searchField = "(" + searchField + "=" + 
                      user.getUserID().getName() + ")";

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest = new SearchRequest(this.config.getUsersDN(), SearchScope.SUB, 
                             searchField, new String[] {"entrydn"});
        

            searchResult = 
                getConnection().searchForEntry(searchRequest);

        } catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode(), e.getDiagnosticMessage());
        }
        

        if (searchResult == null)
        {
            String msg = "User not found " + user.getUserID().toString();
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        return searchResult.getAttributeValueAsDN("entrydn");
    }

}
