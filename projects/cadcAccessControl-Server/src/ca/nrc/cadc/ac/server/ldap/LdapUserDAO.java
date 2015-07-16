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

import ca.nrc.cadc.ac.*;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.TransientException;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

public class LdapUserDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapUserDAO.class);

    // Map of identity type to LDAP attribute
    private final Map<Class<?>, String> userLdapAttrib = new HashMap<Class<?>, String>();

    // Returned User attributes
    protected static final String LDAP_OBJECT_CLASS = "objectClass";
    protected static final String LDAP_INET_ORG_PERSON = "inetOrgPerson";
    protected static final String LDAP_CADC_ACCOUNT = "cadcaccount";
    protected static final String LDAP_POSIX_ACCOUNT = "posixaccount";
    protected static final String LDAP_NSACCOUNTLOCK = "nsaccountlock";
    protected static final String LDAP_MEMBEROF = "memberOf";
    protected static final String LDAP_ENTRYDN = "entrydn";
    protected static final String LDAP_COMMON_NAME = "cn";
    protected static final String LDAP_DISTINGUISHED_NAME = "distinguishedName";
    protected static final String LADP_USER_PASSWORD = "userPassword";
    protected static final String LDAP_FIRST_NAME = "givenName";
    protected static final String LDAP_LAST_NAME = "sn";
    protected static final String LDAP_ADDRESS = "address";
    protected static final String LDAP_CITY = "city";
    protected static final String LDAP_COUNTRY = "country";
    protected static final String LDAP_EMAIL = "email";
    protected static final String LDAP_INSTITUTE = "institute";
    protected static final String LDAP_UID = "uid";
    protected static final String LDAP_UID_NUMBER = "uidNumber";
    protected static final String LDAP_GID_NUMBER = "gidNumber";
    protected static final String LDAP_HOME_DIRECTORY = "homeDirectory";
    protected static final String LDAP_LOGIN_SHELL = "loginShell";
    
    private String[] userAttribs = new String[]
    {
        LDAP_FIRST_NAME, LDAP_LAST_NAME, LDAP_ADDRESS, LDAP_CITY, LDAP_COUNTRY,
        LDAP_EMAIL, LDAP_INSTITUTE, LDAP_UID, LDAP_UID_NUMBER, LDAP_GID_NUMBER,
        LDAP_HOME_DIRECTORY, LDAP_LOGIN_SHELL
    };
    private String[] memberAttribs = new String[]
    {
        LDAP_FIRST_NAME, LDAP_LAST_NAME
    };

    public LdapUserDAO(LdapConfig config)
    {
        super(config);
        this.userLdapAttrib.put(HttpPrincipal.class, LDAP_UID);
        this.userLdapAttrib.put(X500Principal.class, LDAP_DISTINGUISHED_NAME);

        // add the id attributes to user and member attributes
        String[] princs = userLdapAttrib.values()
                .toArray(new String[userLdapAttrib.values().size()]);
        String[] tmp = new String[userAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(userAttribs, 0, tmp, princs.length,
                         userAttribs.length);
        userAttribs = tmp;

        tmp = new String[memberAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(memberAttribs, 0, tmp, princs.length,
                         memberAttribs.length);
        memberAttribs = tmp;
    }
    
    /**
     * 
     * @return
     * @throws TransientException 
     */
    public Collection<HttpPrincipal> getCadcIDs() throws TransientException
    {
        try
        {
            Filter filter = Filter.createPresenceFilter("uid");
            String [] attributes = new String[] {"uid"};
            
            SearchRequest searchRequest = 
                    new SearchRequest(config.getUsersDN(), 
                                      SearchScope.SUB, filter, attributes);
    
            SearchResult searchResult = null;
            try
            {
                searchResult = getConnection().search(searchRequest);
            }
            catch (LDAPSearchException e)
            {
                if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT)
                {
                    logger.debug("Could not find users root", e);
                    throw new IllegalStateException("Could not find users root");
                }
            }
            
            LdapDAO.checkLdapResult(searchResult.getResultCode());
            Collection<HttpPrincipal> userIDs = new HashSet<HttpPrincipal>();
            for (SearchResultEntry next : searchResult.getSearchEntries())
            {
                userIDs.add(new HttpPrincipal(next.getAttributeValue("uid")));
            }
            
            return userIDs;
        }
        catch (LDAPException e1)
        {
            logger.debug("getCadcIDs Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
            throw new IllegalStateException("Unexpected exception: " + 
                    e1.getMatchedDN(), e1);
        }
        
    }


    /**
     * Add the specified user..
     *
     * @param userRequest The user to add.
     * @return User instance.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> addUser(final UserRequest<T> userRequest)
        throws TransientException
    {
        final User<T> user = userRequest.getUser();
        final Class userType = user.getUserID().getClass();
        String searchField = userLdapAttrib.get(userType);
        if (searchField == null)
        {
            throw new IllegalArgumentException("Unsupported principal type " + userType);
        }
        
        try
        {
            // add new user
            DN userDN = getUserRequestsDN(user.getUserID().getName());
            List<Attribute> attributes = new ArrayList<Attribute>();
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_ORG_PERSON);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_CADC_ACCOUNT);
            addAttribute(attributes, LDAP_COMMON_NAME, user.getUserID().getName());
            addAttribute(attributes, LDAP_DISTINGUISHED_NAME, userDN.toNormalizedString());
            addAttribute(attributes, LADP_USER_PASSWORD, userRequest.getPassword());

            for (UserDetails details : user.details)
            {
                if (details.getClass() == PersonalDetails.class)
                {
                    PersonalDetails pd = (PersonalDetails) details;
                    addAttribute(attributes, LDAP_FIRST_NAME, pd.getFirstName());
                    addAttribute(attributes, LDAP_LAST_NAME, pd.getLastName());
                    addAttribute(attributes, LDAP_ADDRESS, pd.address);
                    addAttribute(attributes, LDAP_CITY, pd.city);
                    addAttribute(attributes, LDAP_COUNTRY, pd.country);
                    addAttribute(attributes, LDAP_EMAIL, pd.email);
                    addAttribute(attributes, LDAP_INSTITUTE, pd.institute);
                }
                else if (details.getClass() == PosixDetails.class)
                {
                    PosixDetails pd = (PosixDetails) details;
                    addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_POSIX_ACCOUNT);
                    addAttribute(attributes, LDAP_UID, Long.toString(pd.getUid()));
                    addAttribute(attributes, LDAP_UID_NUMBER, Long.toString(pd.getUid()));
                    addAttribute(attributes, LDAP_GID_NUMBER, Long.toString(pd.getGid()));
                    addAttribute(attributes, LDAP_HOME_DIRECTORY, pd.getHomeDirectory());
                    addAttribute(attributes, LDAP_LOGIN_SHELL, pd.loginShell);
                }
            }
        
            AddRequest addRequest = new AddRequest(userDN, attributes);
            LDAPResult result = getConnection().add(addRequest);
            LdapDAO.checkLdapResult(result.getResultCode());
            
            // AD: Search results sometimes come incomplete if
            // connection is not reset - not sure why.
            getConnection().reconnect();
            try
            {
                 return getUser(user.getUserID(), config.getUserRequestsDN());
            }
            catch (UserNotFoundException e)
            {
                throw new RuntimeException("BUG: new user " + userDN.toNormalizedString() +
                                           " not found, result " + result.getResultCode());
            }
        }
        catch (LDAPException e)
        {
            System.out.println("LDAPe: " + e);
            System.out.println("LDAPrc: " + e.getResultCode());
            logger.debug("addUser Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
            throw new RuntimeException("Unexpected LDAP exception", e);
        }
    }

    /**
     * Get the user specified by userID.
     *
     * @param userID The userID.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> getUser(final T userID)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        return getUser(userID, config.getUsersDN());
    }

    /**
     * Get the user specified by userID.
     *
     * @param userID The userID.
     * @param usersDN The LDAP tree to search.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    private User<T> getUser(final T userID, final String usersDN)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        String searchField = userLdapAttrib.get(userID.getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        searchField = "(&(objectclass=inetorgperson)(" + 
                      searchField + "=" + userID.getName() + "))";
        logger.debug(searchField);

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest = 
                    new SearchRequest(usersDN, SearchScope.SUB,
                                     searchField, userAttribs);

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl(
                            "dn:" + getSubjectDN().toNormalizedString()));

            searchResult = getConnection().searchForEntry(searchRequest);
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        if (searchResult == null)
        {
            String msg = "User not found " + userID.toString();
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        User<T> user = new User<T>(userID);
        user.getIdentities().add(new HttpPrincipal(searchResult
                .getAttributeValue(userLdapAttrib.get(HttpPrincipal.class))));

        String fname = searchResult.getAttributeValue(LDAP_FIRST_NAME);
        String lname = searchResult.getAttributeValue(LDAP_LAST_NAME);
        PersonalDetails personaDetails = new PersonalDetails(fname, lname);
        personaDetails.address = searchResult.getAttributeValue(LDAP_ADDRESS);
        personaDetails.city = searchResult.getAttributeValue(LDAP_CITY);
        personaDetails.country = searchResult.getAttributeValue(LDAP_COUNTRY);
        personaDetails.email = searchResult.getAttributeValue(LDAP_EMAIL);
        personaDetails.institute = searchResult.getAttributeValue(LDAP_INSTITUTE);
        user.details.add(personaDetails);
        
        Long uid = searchResult.getAttributeValueAsLong(LDAP_UID_NUMBER);
        Long gid = searchResult.getAttributeValueAsLong(LDAP_GID_NUMBER);
        String homeDirectory = searchResult.getAttributeValue(LDAP_HOME_DIRECTORY);
        if (uid != null && gid != null && homeDirectory != null)
        {
            PosixDetails posixDetails = new PosixDetails(uid, gid, homeDirectory);
            posixDetails.loginShell = searchResult.getAttributeValue(LDAP_LOGIN_SHELL);
            user.details.add(posixDetails);
        }
        
        return user;
    }
    
    /**
     * Get all group names.
     * 
     * @return A collection of strings
     * 
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public Collection<String> getUserNames()
        throws TransientException
    {
        try
        {
            Filter filter = Filter.createPresenceFilter(LDAP_COMMON_NAME);
            String [] attributes = new String[] {LDAP_COMMON_NAME, LDAP_NSACCOUNTLOCK};
            
            SearchRequest searchRequest = 
                    new SearchRequest(config.getGroupsDN(), 
                                      SearchScope.SUB, filter, attributes);
    
            SearchResult searchResult = null;
            try
            {
                searchResult = getConnection().search(searchRequest);
            }
            catch (LDAPSearchException e)
            {
                if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT)
                {
                    logger.debug("Could not find groups root", e);
                    throw new IllegalStateException("Could not find groups root");
                }
            }
            
            LdapDAO.checkLdapResult(searchResult.getResultCode());
            List<String> groupNames = new ArrayList<String>();
            for (SearchResultEntry next : searchResult.getSearchEntries())
            {
                if (!next.hasAttribute(LDAP_NSACCOUNTLOCK))
                {
                    groupNames.add(next.getAttributeValue(LDAP_COMMON_NAME));
                }
            }
            
            return groupNames;
        }
        catch (LDAPException e1)
        {
        	logger.debug("getGroupNames Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
            throw new IllegalStateException("Unexpected exception: " + e1.getMatchedDN(), e1);
        }
    }
    
    /**
     * Updated the user specified by User.
     *
     * @param user
     *
     * @return User instance.
     * 
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> modifyUser(User<T> user)
        throws UserNotFoundException, TransientException, 
               AccessControlException
    {
        return null;
    }
    
    /**
     * Delete the user specified by userID.
     *
     * @param userID The userID.
     * 
     * @throws UserNotFoundException when the user is not found.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void deleteUser(final T userID)
        throws UserNotFoundException, TransientException, 
               AccessControlException
    {
        
    }

    /**
     * Get all groups the user specified by userID belongs to.
     *
     * @param userID  The userID.
     * @param isAdmin
     * @return Collection of Group instances.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred., e.getMessage(
     * @throws AccessControlException If the operation is not permitted.
     */
    public Collection<DN> getUserGroups(final T userID, final boolean isAdmin)
            throws UserNotFoundException, TransientException,
                   AccessControlException
    {
        Collection<DN> groupDNs = new HashSet<DN>();
        try
        {
            String searchField = userLdapAttrib.get(userID.getClass());
            if (searchField == null)
            {
                throw new IllegalArgumentException(
                        "Unsupported principal type " + userID.getClass());
            }

            User<T> user = getUser(userID);
            Filter filter = Filter.createANDFilter(
                    Filter.createEqualityFilter(searchField,
                                                user.getUserID().getName()),
                    Filter.createPresenceFilter(LDAP_MEMBEROF));

            SearchRequest searchRequest =
                    new SearchRequest(config.getUsersDN(), SearchScope.SUB,
                                      filter, LDAP_MEMBEROF);

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" +
                                                             getSubjectDN()
                                                                     .toNormalizedString()));

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
                String[] members = searchResult.getAttributeValues(LDAP_MEMBEROF);
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
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        return groupDNs;
    }

    /**
     * Check whether the user is a member of the group.
     *
     * @param userID  The userID.
     * @param groupID The groupID.
     * @return true or false
     * @throws UserNotFoundException  If the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public boolean isMember(T userID, String groupID)
            throws UserNotFoundException, TransientException,
                   AccessControlException
    {
        try
        {
            String searchField = userLdapAttrib.get(userID.getClass());
            if (searchField == null)
            {
                throw new IllegalArgumentException(
                        "Unsupported principal type " + userID.getClass());
            }

            User<T> user = getUser(userID);
            Filter filter = Filter.createANDFilter(
                    Filter.createEqualityFilter(searchField,
                                                user.getUserID().getName()),
                    Filter.createEqualityFilter(LDAP_MEMBEROF, groupID));

            SearchRequest searchRequest =
                    new SearchRequest(config.getUsersDN(), SearchScope.SUB,
                                      filter, LDAP_COMMON_NAME);

            searchRequest.addControl(
                    new ProxiedAuthorizationV2RequestControl("dn:" +
                                                             getSubjectDN()
                                                                     .toNormalizedString()));

            SearchResultEntry searchResults =
                    getConnection().searchForEntry(searchRequest);

            return (searchResults != null);
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        return false;
    }

    /**
     * Returns a member user identified by the X500Principal only. The
     * returned object has the fields required by the GMS.
     * Note that this method binds as a proxy user and not as the
     * subject.
     *
     * @param userDN
     * @return
     * @throws UserNotFoundException
     * @throws LDAPException
     */
    User<X500Principal> getMember(DN userDN)
            throws UserNotFoundException, LDAPException
    {
        Filter filter =
                Filter.createEqualityFilter(LDAP_ENTRYDN,
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
                        userLdapAttrib.get(X500Principal.class))));
        String princ = searchResult.getAttributeValue(
                userLdapAttrib.get(HttpPrincipal.class));
        if (princ != null)
        {
            user.getIdentities().add(new HttpPrincipal(princ));
        }
        String fname = searchResult.getAttributeValue(LDAP_FIRST_NAME);
        String lname = searchResult.getAttributeValue(LDAP_LAST_NAME);
        user.details.add(new PersonalDetails(fname, lname));
        return user;
    }


    DN getUserDN(User<? extends Principal> user)
            throws UserNotFoundException, TransientException
    {
        String searchField =
                userLdapAttrib.get(user.getUserID().getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + user.getUserID()
                            .getClass());
        }
        
        // change the DN to be in the 'java' format
        if (user.getUserID() instanceof X500Principal)
        {
            X500Principal orderedPrincipal = AuthenticationUtil.getOrderedForm(
                (X500Principal) user.getUserID());
            searchField = "(" + searchField + "=" + orderedPrincipal.toString() + ")";
        }
        else
        {
            searchField = "(" + searchField + "=" + user.getUserID().getName()
                    + ")";
        }
        
        logger.debug("Search field is: " + searchField);

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest =
                    new SearchRequest(this.config.getUsersDN(), SearchScope.SUB,
                                      searchField, LDAP_ENTRYDN);


            searchResult =
                    getConnection().searchForEntry(searchRequest);

        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        if (searchResult == null)
        {
            String msg = "User not found " + user.getUserID().getName();
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        return searchResult.getAttributeValueAsDN(LDAP_ENTRYDN);
    }
    
    protected DN getUserDN(final String userID)
        throws LDAPException, TransientException
    {
        try
        {
            return new DN(LDAP_UID + "=" + userID + "," + config.getUsersDN());
        }
        catch (LDAPException e)
        {
        	logger.debug("getUserDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(userID + " not a valid user ID");
    }

    protected DN getUserRequestsDN(final String userID)
        throws LDAPException, TransientException
    {
        try
        {
            return new DN(LDAP_UID + "=" + userID + "," + config.getUserRequestsDN());
        }
        catch (LDAPException e)
        {
            logger.debug("getUserRequestsDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(userID + " not a valid user ID");
    }
    
    void addAttribute(List<Attribute> attributes, final String name, final String value)
    {
        if (value != null && !value.isEmpty())
        {
            attributes.add(new Attribute(name, value));
        }
    }

}
