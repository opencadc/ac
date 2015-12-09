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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserDetails;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.util.StringUtil;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;


/**
 *
 * @author pdowler
 * @param <T>
 */
public class LdapUserDAO<T extends Principal> extends LdapDAO
{
    private static final Logger logger = Logger.getLogger(LdapUserDAO.class);

    private final Profiler profiler = new Profiler(LdapUserDAO.class);

    // Map of identity type to LDAP attribute
    private final Map<Class<?>, String> userLdapAttrib = new HashMap<Class<?>, String>();

    // Returned User attributes
    protected static final String LDAP_OBJECT_CLASS = "objectClass";
    protected static final String LDAP_INET_USER = "inetuser";
    protected static final String LDAP_INET_ORG_PERSON = "inetOrgPerson";
    protected static final String LDAP_CADC_ACCOUNT = "cadcaccount";
    protected static final String LDAP_NSACCOUNTLOCK = "nsaccountlock";
    protected static final String LDAP_MEMBEROF = "memberOf";
    protected static final String LDAP_ENTRYDN = "entrydn";
    protected static final String LDAP_COMMON_NAME = "cn";
    protected static final String LDAP_DISTINGUISHED_NAME = "distinguishedName";
    protected static final String LDAP_NUMERICID = "numericid";
    protected static final String LADP_USER_PASSWORD = "userPassword";
    protected static final String LDAP_FIRST_NAME = "givenName";
    protected static final String LDAP_LAST_NAME = "sn";
    protected static final String LDAP_ADDRESS = "address";
    protected static final String LDAP_CITY = "city";
    protected static final String LDAP_COUNTRY = "country";
    protected static final String LDAP_EMAIL = "email";
    protected static final String LDAP_INSTITUTE = "institute";
    protected static final String LDAP_UID = "uid";

    private String[] userAttribs = new String[]
    {
            LDAP_FIRST_NAME, LDAP_LAST_NAME, LDAP_ADDRESS, LDAP_CITY,
            LDAP_COUNTRY, LDAP_EMAIL, LDAP_INSTITUTE
    };
    private String[] firstLastAttribs = new String[]
    {
            LDAP_FIRST_NAME, LDAP_LAST_NAME
    };
    private String[] identityAttribs = new String[]
    {
        LDAP_UID, LDAP_DISTINGUISHED_NAME, LDAP_NUMERICID, LDAP_ENTRYDN,
        LDAP_MEMBEROF // for group cache
    };

    public LdapUserDAO(LdapConnections connections)
    {
        super(connections);
        this.userLdapAttrib.put(HttpPrincipal.class, LDAP_UID);
        this.userLdapAttrib.put(X500Principal.class, LDAP_DISTINGUISHED_NAME);
        this.userLdapAttrib.put(NumericPrincipal.class, LDAP_NUMERICID);

        // add the id attributes to user and member attributes
        String[] princs = userLdapAttrib.values()
                .toArray(new String[userLdapAttrib.values().size()]);
        String[] tmp = new String[userAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(userAttribs, 0, tmp, princs.length,
                         userAttribs.length);
        userAttribs = tmp;

        tmp = new String[firstLastAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(firstLastAttribs, 0, tmp, princs.length,
                         firstLastAttribs.length);
        firstLastAttribs = tmp;
    }

    /**
     * Verifies the username and password for an existing User.
     *
     * @param username username to verify.
     * @param password password to verify.
     * @return Boolean
     * @throws TransientException
     * @throws UserNotFoundExceptionjoellama
     */
    public Boolean doLogin(final String username, final String password)
        throws TransientException, UserNotFoundException
    {
        try
        {
            BindRequest bindRequest = new SimpleBindRequest(
                getUserDN(username, config.getUsersDN()), new String(password));

            LDAPConnection conn = this.getUnboundReadConnection();
            BindResult bindResult = conn.bind(bindRequest);

            if (bindResult != null && bindResult.getResultCode() == ResultCode.SUCCESS)
            {
                return Boolean.TRUE;
            }
            else
            {
                throw new AccessControlException("Invalid username or password");
            }
        }
        catch (LDAPException e)
        {
            logger.debug("doLogin Exception: " + e, e);

            if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS)
            {
                throw new AccessControlException("Invalid password");
            }
            else if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT)
            {
                throw new AccessControlException("Invalid username");
            }
            else if (e.getResultCode() == ResultCode.UNWILLING_TO_PERFORM)
            {
                throw new AccessControlException("Account inactivated");
            }

            throw new RuntimeException("Unexpected LDAP exception", e);
        }
    }

    /**
     * Add the specified user to the active user tree.
     *
     * @param userRequest                 The user to add.
     * @throws TransientException         If an temporary, unexpected problem occurred.
     * @throws UserAlreadyExistsException If the user already exists.
     */
    public void addUser(final UserRequest<T> userRequest)
            throws TransientException, UserAlreadyExistsException
    {
        try
        {
            getUser(userRequest.getUser().getUserID(), config.getUsersDN());
            final String error = userRequest.getUser().getUserID().getName() +
                " found in " + config.getUsersDN();
            throw new UserAlreadyExistsException(error);
        }
        catch (UserNotFoundException e1) {}

        addUser(userRequest, config.getUsersDN());
    }

    /**
     *Add the specified user to the pending user tree.
     *
     * @param userRequest                   The user to add.
     * @throws TransientException           If an temporary, unexpected problem occurred.
     * @throws UserAlreadyExistsException   If the user already exists.
     */
    public void addPendingUser(final UserRequest<T> userRequest)
            throws TransientException, UserAlreadyExistsException
    {
        // check current users
        try
        {
            getUser(userRequest.getUser().getUserID(), config.getUsersDN(), false);
            final String error = userRequest.getUser().getUserID().getName() +
                                 " found in " + config.getUsersDN();
            throw new UserAlreadyExistsException(error);
        }
        catch (UserNotFoundException ok) { }

        // check pending users
        try
        {
            getUser(userRequest.getUser().getUserID(), config.getUserRequestsDN(), false);
            final String error = userRequest.getUser().getUserID().getName() +
                " found in " + config.getUserRequestsDN();
            throw new UserAlreadyExistsException(error);
        }
        catch (UserNotFoundException ok) { }

        addUser(userRequest, config.getUserRequestsDN());
    }

    private void addUser(final UserRequest<T> userRequest, final String usersDN)
        throws TransientException, UserAlreadyExistsException
    {
        final User<T> user = userRequest.getUser();
        final Class userType = user.getUserID().getClass();
        final String searchField = userLdapAttrib.get(userType);

        if (searchField == null)
        {
            throw new IllegalArgumentException("Unsupported principal type " + userType);
        }

        try
        {
            List<Attribute> attributes = new ArrayList<Attribute>();
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_ORG_PERSON);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_USER);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_CADC_ACCOUNT);
            addAttribute(attributes, LDAP_COMMON_NAME, user.getUserID().getName());
            addAttribute(attributes, LADP_USER_PASSWORD, new String(userRequest.getPassword()));
            addAttribute(attributes, LDAP_NUMERICID, String.valueOf(genNextNumericId()));
            for (Principal princ : user.getIdentities())
            {
                if (princ instanceof X500Principal)
                {
                    addAttribute(attributes, LDAP_DISTINGUISHED_NAME, princ.getName());
                }
            }
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
                    throw new UnsupportedOperationException(
                        "Support for users PosixDetails not available");
                }
            }

            DN userDN = getUserDN(user.getUserID().getName(), usersDN);
            AddRequest addRequest = new AddRequest(userDN, attributes);
            LDAPResult result = getReadWriteConnection().add(addRequest);
            LdapDAO.checkLdapResult(result.getResultCode());
        }
        catch (LDAPException e)
        {
            logger.error("addUser Exception: " + e, e);
            LdapUserDAO.checkUserLDAPResult(e.getResultCode());
            throw new RuntimeException("Unexpected LDAP exception", e);
        }
    }

    /**
     * Get the user specified by userID.
     *
     * @param userID The userID.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found in the main tree.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> getUser(final T userID)
            throws UserNotFoundException, TransientException,
                   AccessControlException
    {
        return getUser(userID, config.getUsersDN());
    }

    /**
     * Obtain a user who is awaiting approval.
     *
     * @param userID        The user ID of the pending user.
     * @return              A User instance awaiting approval.
     *
     * @throws UserNotFoundException  when the user is not found in the user request tree.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> getPendingUser(final T userID)
            throws UserNotFoundException, TransientException,
                   AccessControlException
    {
        return getUser(userID, config.getUserRequestsDN());
    }

    /**
     * Get the user specified by userID.
     *
     * @param userID  The userID.
     * @param usersDN The LDAP tree to search.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    private User<T> getUser(final T userID, final String usersDN)
        throws UserNotFoundException, TransientException,
        AccessControlException
    {

        return getUser(userID, usersDN, true);
    }
    /**
     * Get the user specified by userID.
     *
     * @param userID  The userID.
     * @param usersDN The LDAP tree to search.
     * @param proxy Whether to proxy the search as the calling Subject.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    private User<T> getUser(final T userID, final String usersDN, final boolean proxy)
        throws UserNotFoundException, TransientException,
        AccessControlException
    {
        String searchField = userLdapAttrib.get(userID.getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        SearchResultEntry searchResult = null;
        Filter filter = null;
        try
        {
            filter = Filter.createEqualityFilter(searchField, userID.getName());
            logger.debug("search filter: " + filter);

            SearchRequest searchRequest =
                    new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);

            //if (proxy)
            //{
            //    String proxyDN = "dn:" + getSubjectDN().toNormalizedString();
            //    logger.debug("Proxying auth as: " + proxyDN);
            //    searchRequest.addControl(new ProxiedAuthorizationV2RequestControl(proxyDN));
            //}

            searchResult = getReadOnlyConnection().searchForEntry(searchRequest);
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        if (searchResult == null)
        {
            // determine if the user is not there of if the calling user
            // doesn't have permission to see it
            SearchRequest searchRequest =
                    new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);
            try
            {
                searchResult = getReadOnlyConnection().searchForEntry(searchRequest);
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
            throw new AccessControlException("Permission denied");
        }

        User<T> user = new User<T>(userID);
        String username = searchResult.getAttributeValue(userLdapAttrib.get(HttpPrincipal.class));
        logger.debug("username: " + username);
        user.getIdentities().add(new HttpPrincipal(username));

        Integer numericID = searchResult.getAttributeValueAsInteger(userLdapAttrib.get(NumericPrincipal.class));
        logger.debug("Numeric id: " + numericID);
        if (numericID == null)
        {
            // If the numeric ID does not return it means the user
            // does not have permission
            throw new AccessControlException("Permission denied");
        }
        user.getIdentities().add(new NumericPrincipal(numericID));

        String x500str = searchResult.getAttributeValue(userLdapAttrib.get(X500Principal.class));
        logger.debug("x500principal: " + x500str);

        if (x500str != null)
            user.getIdentities().add(new X500Principal(x500str));

        String fname = searchResult.getAttributeValue(LDAP_FIRST_NAME);
        String lname = searchResult.getAttributeValue(LDAP_LAST_NAME);
        PersonalDetails personaDetails = new PersonalDetails(fname, lname);
        personaDetails.address = searchResult.getAttributeValue(LDAP_ADDRESS);
        personaDetails.city = searchResult.getAttributeValue(LDAP_CITY);
        personaDetails.country = searchResult.getAttributeValue(LDAP_COUNTRY);
        personaDetails.email = searchResult.getAttributeValue(LDAP_EMAIL);
        personaDetails.institute = searchResult.getAttributeValue(LDAP_INSTITUTE);
        user.details.add(personaDetails);

        return user;
    }

    public User<T> getAugmentedUser(final T userID)
        throws UserNotFoundException, TransientException
    {
        String searchField = userLdapAttrib.get(userID.getClass());
        profiler.checkpoint("getAugmentedUser.getSearchField");
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                "Unsupported principal type " + userID.getClass());
        }

        try
        {
            Filter filter = Filter.createEqualityFilter(searchField, userID.getName());
            profiler.checkpoint("getAugmentedUser.createFilter");
            logger.debug("search filter: " + filter);

            SearchRequest searchRequest = new SearchRequest(
                config.getUsersDN(), SearchScope.ONE, filter, identityAttribs);
            profiler.checkpoint("getAugmentedUser.createSearchRequest");

            SearchResultEntry searchResult = getReadOnlyConnection().searchForEntry(searchRequest);
            profiler.checkpoint("getAugmentedUser.searchForEntry");

            if (searchResult == null)
            {
                String msg = "User not found " + userID.toString();
                logger.debug(msg);
                throw new UserNotFoundException(msg);
            }

            User<T> user = new User<T>(userID);
            user.getIdentities().add(new HttpPrincipal(
                searchResult.getAttributeValue(LDAP_UID)));
            int numericID = searchResult.getAttributeValueAsInteger(LDAP_NUMERICID);
            logger.debug("numericID is " + numericID);
            user.getIdentities().add(new NumericPrincipal(numericID));
            String dn = searchResult.getAttributeValue(LDAP_DISTINGUISHED_NAME);
            if (dn != null)
            {
                user.getIdentities().add(new X500Principal(dn));
            }
            user.getIdentities().add(new DNPrincipal(searchResult.getAttributeValue(LDAP_ENTRYDN)));

            // cache memberOf values in the user
            GroupMemberships gms = new GroupMemberships(user);
            user.appData = gms; // add even if empty
            String[] mems = searchResult.getAttributeValues(LDAP_MEMBEROF);
            if (mems != null && mems.length > 0)
            {
                DN adminDN = new DN(config.getAdminGroupsDN());
                DN groupsDN = new DN(config.getGroupsDN());
                List<Group> memberOf = new ArrayList<Group>();
                List<Group> adminOf = new ArrayList<Group>();
                for (String m : mems)
                {
                    DN groupDN = new DN(m);
                    if (groupDN.isDescendantOf(groupsDN, false))
                        memberOf.add(createGroupFromDN(groupDN));
                    else if (groupDN.isDescendantOf(adminDN, false))
                        adminOf.add(createGroupFromDN(groupDN));
                }
                gms.add(adminOf, Role.ADMIN);
                gms.add(memberOf, Role.MEMBER);
            }
            profiler.checkpoint("getAugmentedUser.mapIdentities");
            return user;
        }
        catch (LDAPException e)
        {
            logger.debug("getGroup Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
            throw new RuntimeException("BUG: checkLdapResult didn't throw an exception");
        }
        finally
        {
            profiler.checkpoint("Done getAugmentedUser");
        }
    }

    // some pretty horrible hacks to avoid querying LDAP for group details...
    private Group createGroupFromDN(DN groupDN)
    {
        String cn = groupDN.getRDNString();
        String[] parts = cn.split("=");
        if (parts.length == 2 && parts[0].equals("cn"))
        {
            return new Group(parts[1]);
        }
        throw new RuntimeException("BUG: failed to extract group name from " + groupDN
                .toString());
    }

    /**
     * Get all users from the active tree.
     *
     * @return A Collection of User's.
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public Collection<User<Principal>> getUsers()
        throws AccessControlException, TransientException
    {
        return getUsers(config.getUsersDN());
    }

    /**
     * Get all users from the pending tree.
     *
     * @return A Collection of User's.
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public Collection<User<Principal>> getPendingUsers()
        throws AccessControlException, TransientException
    {
        return getUsers(config.getUserRequestsDN());
    }

    private Collection<User<Principal>> getUsers(final String usersDN)
        throws AccessControlException, TransientException
    {
        final Collection<User<Principal>> users = new ArrayList<User<Principal>>();

        Filter filter =  Filter.createPresenceFilter(LDAP_UID);
        logger.debug("search filter: " + filter);

        final String[] attributes = new String[]
            { LDAP_UID, LDAP_FIRST_NAME, LDAP_LAST_NAME };
        final SearchRequest searchRequest =
            new SearchRequest(usersDN, SearchScope.ONE, filter, attributes);

        try
        {
            final SearchResult searchResult =
                getReadOnlyConnection().search(searchRequest);

            LdapDAO.checkLdapResult(searchResult.getResultCode());
            for (SearchResultEntry next : searchResult.getSearchEntries())
            {
                final String firstName =
                    next.getAttributeValue(LDAP_FIRST_NAME).trim();
                final String lastName =
                    next.getAttributeValue(LDAP_LAST_NAME).trim();
                final String uid = next.getAttributeValue(LDAP_UID).trim();
                User<Principal> user = new User<Principal>(new HttpPrincipal(uid));

                // Only add Personal Details if it is relevant.
                if (StringUtil.hasLength(firstName)
                    && StringUtil.hasLength(lastName))
                {
                    user.details.add(new PersonalDetails(firstName, lastName));
                }

                users.add(user);
            }
        }
        catch (LDAPSearchException e)
        {
            if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT)
            {
                final String message = "Could not find users root";
                logger.debug(message, e);
                throw new IllegalStateException(message);
            }
        }

        return users;
    }

    /**
     * Move the pending user specified by userID from the
     * pending users tree to the active users tree.
     *
     * @param userID
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> approvePendingUser(final T userID)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        User<T> pendingUser = getPendingUser(userID);

        Set<HttpPrincipal> httpPrincipals = pendingUser.getIdentities(HttpPrincipal.class);
        if (httpPrincipals.isEmpty())
        {
            throw new RuntimeException("BUG: missing HttpPrincipal for " + userID.getName());
        }
        HttpPrincipal httpPrincipal = httpPrincipals.iterator().next();
        String uid = "uid=" + httpPrincipal.getName();
        String dn = uid + "," + config.getUserRequestsDN();

        try
        {
            ModifyDNRequest modifyDNRequest =
                new ModifyDNRequest(dn, uid, true, config.getUsersDN());

            LdapDAO.checkLdapResult(getReadWriteConnection().modifyDN(modifyDNRequest).getResultCode());
        }
        catch (LDAPException e)
        {
            logger.debug("Modify Exception", e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        try
        {
            return getUser(userID);
        }
        catch (UserNotFoundException e)
        {
            throw new RuntimeException(
                "BUG: approved user not found (" + userID.getName() + ")");
        }
    }

    /**
     * Update the user specified by User.
     *
     * @param userID
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User<T> modifyUser(final User<T> userID)
            throws UserNotFoundException, TransientException, AccessControlException
    {
        User existingUser = getUser(userID.getUserID());

        List<Modification> mods = new ArrayList<Modification>();
        for (UserDetails details : userID.details)
        {
            if (details.getClass() == PersonalDetails.class)
            {
                PersonalDetails pd = (PersonalDetails) details;
                addModification(mods, LDAP_FIRST_NAME, pd.getFirstName());
                addModification(mods, LDAP_LAST_NAME, pd.getLastName());
                addModification(mods, LDAP_ADDRESS, pd.address);
                addModification(mods, LDAP_CITY, pd.city);
                addModification(mods, LDAP_COUNTRY, pd.country);
                addModification(mods, LDAP_EMAIL, pd.email);
                addModification(mods, LDAP_INSTITUTE, pd.institute);
            }
            else if (details.getClass() == PosixDetails.class)
            {
                throw new UnsupportedOperationException(
                    "Support for users PosixDetails not available");
            }
        }

        try
        {
            ModifyRequest modifyRequest = new ModifyRequest(getUserDN(userID), mods);
            //modifyRequest.addControl(
            //    new ProxiedAuthorizationV2RequestControl(
            //        "dn:" + getSubjectDN().toNormalizedString()));
            LdapDAO.checkLdapResult(getReadWriteConnection().modify(modifyRequest).getResultCode());
        }
        catch (LDAPException e)
        {
            logger.debug("Modify Exception", e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        try
        {
            return getUser(userID.getUserID());
        }
        catch (UserNotFoundException e)
        {
            throw new RuntimeException(
                "BUG: modified user not found (" + userID.getUserID() + ")");
        }
    }

    /**
     * Update a user's password. The given user and authenticating user must match.
     *
     * @param userID
     * @param oldPassword   current password.
     * @param newPassword   new password.
     * @throws UserNotFoundException If the given user does not exist.
     * @throws TransientException   If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void setPassword(HttpPrincipal userID, String oldPassword, String newPassword)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        try
        {
            User user = new User(userID);
            DN userDN = getUserDN(user);

            //BindRequest bindRequest = new SimpleBindRequest(
            //        getUserDN(username, config.getUsersDN()), oldPassword);
            //LDAPConnection conn = this.getUnboundReadConnection();
            //conn.bind(bindRequest);

            LDAPConnection conn = this.getReadWriteConnection();

            PasswordModifyExtendedRequest passwordModifyRequest =
                new PasswordModifyExtendedRequest(
                    userDN.toNormalizedString(), new String(oldPassword), new String(newPassword));

            PasswordModifyExtendedResult passwordModifyResult = (PasswordModifyExtendedResult)
                    conn.processExtendedOperation(passwordModifyRequest);

            LdapDAO.checkLdapResult(passwordModifyResult.getResultCode());
        }
        catch (LDAPException e)
        {
            logger.debug("setPassword Exception: " + e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
    }

    /**
     * Delete the user specified by userID from the active user tree.
     *
     * @param userID The userID.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void deleteUser(final T userID)
            throws UserNotFoundException, TransientException,
                   AccessControlException
    {
        deleteUser(userID, config.getUsersDN(), true);
    }

    /**
     * Delete the user specified by userID from the pending user tree.
     *
     * @param userID The userID.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void deletePendingUser(final T userID)
        throws UserNotFoundException, TransientException,
        AccessControlException
    {
        deleteUser(userID, config.getUserRequestsDN(), false);
    }

    private void deleteUser(final T userID, final String usersDN, boolean markDelete)
        throws UserNotFoundException, AccessControlException, TransientException
    {
        getUser(userID, usersDN);
        try
        {
            DN userDN = getUserDN(userID.getName(), usersDN);
            if (markDelete)
            {
                List<Modification> modifs = new ArrayList<Modification>();
                modifs.add(new Modification(ModificationType.ADD, LDAP_NSACCOUNTLOCK, "true"));

                ModifyRequest modifyRequest = new ModifyRequest(userDN, modifs);
                //modifyRequest.addControl(
                //    new ProxiedAuthorizationV2RequestControl(
                //        "dn:" + getSubjectDN().toNormalizedString()));

                LDAPResult result = getReadWriteConnection().modify(modifyRequest);
                LdapDAO.checkLdapResult(result.getResultCode());
            }
            else // real delete
            {
                DeleteRequest delRequest = new DeleteRequest(userDN);
                //delRequest.addControl(
                //    new ProxiedAuthorizationV2RequestControl(
                //        "dn:" + getSubjectDN().toNormalizedString()));

                LDAPResult result = getReadWriteConnection().delete(delRequest);
                LdapDAO.checkLdapResult(result.getResultCode());
            }
        }
        catch (LDAPException e1)
        {
            logger.debug("Delete Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }

        // getUser does not yet support nsaccountlock
        if (!markDelete)
        {
            try
            {
                getUser(userID, usersDN);
                throw new RuntimeException(
                    "BUG: " + userID.getName() + " not deleted in " + usersDN);
            }
            catch (UserNotFoundException ignore) {}
        }
    }

    /**
     * Returns a member user identified by the X500Principal only. The
     * returned object has the fields required by the LdapGroupDAO.
     * Note that this method binds as a proxy user and not as the
     * subject.
     *
     * @param userDN
     * @return
     * @throws UserNotFoundException
     * @throws LDAPException
     */
    User<X500Principal> getX500User(DN userDN)
            throws UserNotFoundException, LDAPException, TransientException
    {
        Filter filter =
                Filter.createEqualityFilter(LDAP_ENTRYDN,
                    userDN.toNormalizedString());

        SearchRequest searchRequest =
                new SearchRequest(config.getUsersDN(), SearchScope.ONE,
                                  filter, firstLastAttribs);

        SearchResultEntry searchResult =
                getReadOnlyConnection().searchForEntry(searchRequest);

        if (searchResult == null)
        {
            String msg = "User not found " + userDN;
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
        String searchField = userLdapAttrib.get(user.getUserID().getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + user.getUserID().getClass());
        }

        // change the DN to be in the 'java' format
        Filter filter;
        if (user.getUserID() instanceof X500Principal)
        {
            X500Principal orderedPrincipal = AuthenticationUtil.getOrderedForm(
                (X500Principal) user.getUserID());
            filter = Filter.createEqualityFilter(searchField, orderedPrincipal.toString());
        }
        else
        {
            filter = Filter.createEqualityFilter(searchField, user.getUserID().getName());
        }
        logger.debug("search filter: " + filter);

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest = new SearchRequest(
                config.getUsersDN(), SearchScope.ONE, filter, LDAP_ENTRYDN);
            searchResult = getReadOnlyConnection().searchForEntry(searchRequest);
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

    protected DN getUserDN(final String userID, final String usersDN)
            throws LDAPException, TransientException
    {
        try
        {
            return new DN(LDAP_UID + "=" + userID + "," + usersDN);
        }
        catch (LDAPException e)
        {
            logger.debug("getUserDN Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        throw new IllegalArgumentException(userID + " not a valid user ID");
    }

    private void addAttribute(List<Attribute> attributes, final String name, final String value)
    {
        if (value != null && !value.isEmpty())
        {
            attributes.add(new Attribute(name, value));
        }
    }

    private void addModification(List<Modification> mods, final String name, final String value)
    {
        if (value != null && !value.isEmpty())
        {
            mods.add(new Modification(ModificationType.REPLACE, name, value));
        }
        else
        {
            mods.add(new Modification(ModificationType.REPLACE, name));
        }
    }

    /**
     * Checks the Ldap result code, and if the result is not SUCCESS,
     * throws an appropriate exception. This is the place to decide on
     * mapping between ldap errors and exception types
     *
     * @param code The code returned from an LDAP request.
     * @throws TransientException
     * @throws UserAlreadyExistsException
     */
    protected static void checkUserLDAPResult(final ResultCode code)
            throws TransientException, UserAlreadyExistsException
    {
        if (code == ResultCode.ENTRY_ALREADY_EXISTS)
        {
            throw new UserAlreadyExistsException("User already exists.");
        }
        else
        {
            LdapDAO.checkLdapResult(code);
        }
    }

    /**
     * Method to return a randomly generated user numeric ID. The default
     * implementation returns a value between 10000 and Integer.MAX_VALUE.
     * Services that support a different mechanism for generating numeric
     * IDs override this method.
     * @return
     */
    protected int genNextNumericId()
    {
        Random rand = new Random();
        return rand.nextInt(Integer.MAX_VALUE - 10000) + 10000;
    }
}
