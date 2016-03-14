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

import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.AC;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.client.GroupMemberships;
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
 */
public class LdapUserDAO extends LdapDAO
{
    public static final String EMAIL_ADDRESS_CONFLICT_MESSAGE =
            "email address ";

    private static final Logger logger = Logger.getLogger(LdapUserDAO.class);

    private final Profiler profiler = new Profiler(LdapUserDAO.class);

    // Map of identity type to LDAP attribute
    private final Map<Class<?>, String> userLdapAttrib = new HashMap<Class<?>, String>();

    // User cn and sn values for users without a HttpPrincipal
    protected static final String EXTERNAL_USER_CN = "$EXTERNAL-CN";
    protected static final String EXTERNAL_USER_SN = "$EXTERNAL-SN";

    // LDAP User attributes
    protected static final String LDAP_OBJECT_CLASS = "objectClass";
    protected static final String LDAP_INET_USER = "inetuser";
    protected static final String LDAP_INET_ORG_PERSON = "inetOrgPerson";
    protected static final String LDAP_CADC_ACCOUNT = "cadcaccount";
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
    protected static final String USER_ID = "id";

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
        LDAP_UID, LDAP_DISTINGUISHED_NAME, LDAP_ENTRYDN,
        LDAP_MEMBEROF // for group cache
    };

    public LdapUserDAO(LdapConnections connections)
    {
        super(connections);
        this.userLdapAttrib.put(HttpPrincipal.class, LDAP_COMMON_NAME);
        this.userLdapAttrib.put(X500Principal.class, LDAP_DISTINGUISHED_NAME);
        this.userLdapAttrib.put(NumericPrincipal.class, LDAP_UID);
        this.userLdapAttrib.put(DNPrincipal.class, LDAP_ENTRYDN);

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
     * @throws UserNotFoundException
     */
    public Boolean doLogin(final String username, final String password)
        throws TransientException, UserNotFoundException
    {
        try
        {
            HttpPrincipal httpPrincipal = new HttpPrincipal(username);
            User user = getUser(httpPrincipal);
            long id = user.getID().getUUID().getLeastSignificantBits();
            BindRequest bindRequest = new SimpleBindRequest(
                getUserDN(String.valueOf(id), config.getUsersDN()), new String(password));

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
        catch (UserNotFoundException e)
        {
            throw new AccessControlException("Invalid username");
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
    public void addUser(final UserRequest userRequest)
        throws TransientException, UserAlreadyExistsException
    {
        Principal userID = getSupportedPrincipal(userRequest.getUser());
        if (userID == null)
        {
            throw new IllegalArgumentException("UserRequest missing supported Principal type");
        }

        try
        {
            getUser(userID, config.getUsersDN());
            final String error = userID.getName() + " found in " + config.getUsersDN();
            throw new UserAlreadyExistsException(error);
        }
        catch (UserNotFoundException e1) {}

        addUser(userRequest, config.getUsersDN());
    }

    private String getEmailAddress(final UserRequest userRequest)
    {
        if (userRequest.getUser().personalDetails == null)
        {
            String error = userRequest.getUser().getHttpPrincipal().getName() + " missing required PersonalDetails";
            throw new IllegalArgumentException(error);
        }

        if (!StringUtil.hasText(userRequest.getUser().personalDetails.email))
        {
            String error = userRequest.getUser().getHttpPrincipal().getName() + " missing required email address";
            throw new IllegalArgumentException(error);
        }

        return userRequest.getUser().personalDetails.email;
    }

    private void checkUsers(final UserRequest userRequest, final String usersDN)
        throws TransientException, UserAlreadyExistsException
    {
        // check current users
        try
        {
            Principal userID = getSupportedPrincipal(userRequest.getUser());
            if (userID == null)
            {
                throw new IllegalArgumentException("UserRequest missing supported Principal type");
            }

            getUser(userID, usersDN);
            final String error = "user " + userID.getName() + " found in " + usersDN;
            throw new UserAlreadyExistsException(error);
        }
        catch (UserNotFoundException ok) { }

        // check if email address is already in use
        try
        {
            String emailAddress = getEmailAddress(userRequest);
            Principal userID = getSupportedPrincipal(userRequest.getUser());
            if (userID instanceof HttpPrincipal)
            {
                getUserByEmailAddress(emailAddress, usersDN);
            }
        }
        catch (UserNotFoundException ok) { }
    }

    /**
     *Add the specified user to the pending user tree.
     *
     * @param userRequest                   The user to add.
     * @throws TransientException           If an temporary, unexpected problem occurred.
     * @throws UserAlreadyExistsException   If the user already exists.
     */
    public void addPendingUser(final UserRequest userRequest)
            throws TransientException, UserAlreadyExistsException
    {
        // check current users
        checkUsers(userRequest, config.getUsersDN());

        // check pending users
        checkUsers(userRequest, config.getUserRequestsDN());

        addUser(userRequest, config.getUserRequestsDN());
    }

    private void addUser(final UserRequest userRequest, final String usersDN)
        throws TransientException, UserAlreadyExistsException
    {
        final User user = userRequest.getUser();
        final Principal userID = getSupportedPrincipal(user);
        if (userID == null)
        {
            throw new IllegalArgumentException("UserRequest missing supported Principal type");
        }

        final Class userType = userID.getClass();
        final String searchField = userLdapAttrib.get(userType);
        if (searchField == null)
        {
            throw new IllegalArgumentException("Unsupported principal type " + userType);
        }

        String numericID = String.valueOf(genNextNumericId());

        try
        {
            List<Attribute> attributes = new ArrayList<Attribute>();
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_ORG_PERSON);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_USER);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_CADC_ACCOUNT);
            addAttribute(attributes, LDAP_UID, numericID);
            addAttribute(attributes, LADP_USER_PASSWORD, new String(userRequest.getPassword()));

            if (user.getHttpPrincipal() == null)
            {
                addAttribute(attributes, LDAP_COMMON_NAME, EXTERNAL_USER_CN);
                addAttribute(attributes, LDAP_LAST_NAME, EXTERNAL_USER_SN);
            }
            else
            {
                if (user.personalDetails == null)
                {
                    final String error = "User " + user.getHttpPrincipal().getName() +
                        " missing required PersonalDetails";
                    throw new IllegalArgumentException(error);
                }
                 if (userID.getName().startsWith("$"))
                 {
                     final String error = "Username " + user.getHttpPrincipal().getName() +
                         " cannot start with a $";
                     throw new IllegalArgumentException(error);
                 }
                addAttribute(attributes, LDAP_COMMON_NAME, userID.getName());
                addAttribute(attributes, LDAP_FIRST_NAME, user.personalDetails.getFirstName());
                addAttribute(attributes, LDAP_LAST_NAME, user.personalDetails.getLastName());
                addAttribute(attributes, LDAP_ADDRESS, user.personalDetails.address);
                addAttribute(attributes, LDAP_CITY, user.personalDetails.city);
                addAttribute(attributes, LDAP_COUNTRY, user.personalDetails.country);
                addAttribute(attributes, LDAP_EMAIL, user.personalDetails.email);
                addAttribute(attributes, LDAP_INSTITUTE, user.personalDetails.institute);
            }

            for (Principal princ : user.getIdentities())
            {
                if (princ instanceof X500Principal)
                {
                    addAttribute(attributes, LDAP_DISTINGUISHED_NAME, princ.getName());
                }
            }

            if (user.posixDetails != null)
            {
                throw new UnsupportedOperationException("Support for users PosixDetails not available");
            }

            DN userDN = getUserDN(numericID, usersDN);
            AddRequest addRequest = new AddRequest(userDN, attributes);
            logger.info("adding " + userID.getName() + " to " + usersDN);
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
     * Get the user specified by the userID.
     *
     * @param userID The userID.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found in the main tree.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User getUser(final Principal userID)
            throws UserNotFoundException, TransientException,
                   AccessControlException
    {
        return getUser(userID, config.getUsersDN());
    }

    /**
     * Get the user specified by the email address exists.
     *
     * @param emailAddress The user's email address.
     *
     * @return User instance.
     *
     * @throws UserNotFoundException  when the user is not found in the main tree.
     * @throws TransientException If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws UserAlreadyExistsException A user with the same email address already exists
     */
    public User getUserByEmailAddress(final String emailAddress)
            throws UserNotFoundException, TransientException,
            AccessControlException, UserAlreadyExistsException
    {
        return getUserByEmailAddress(emailAddress, config.getUsersDN());
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
    public User getPendingUser(final Principal userID)
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
    private User getUser(final Principal userID, final String usersDN)
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
            logger.debug("getUser search filter: " + filter);

            SearchRequest searchRequest =
                    new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);

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

        User user = new User();
        String username = searchResult.getAttributeValue(userLdapAttrib.get(HttpPrincipal.class));
        logger.debug("username: " + username);
        if (username != null)
        {
            user.getIdentities().add(new HttpPrincipal(username));
        }

        String uid = searchResult.getAttributeValue(userLdapAttrib.get(NumericPrincipal.class));
        logger.debug("uid: " + uid);
        if (uid == null)
        {
            // If the numeric ID does not return it means the user
            // does not have permission
            throw new AccessControlException("Permission denied");
        }

        InternalID internalID = getInternalID(uid);
        setField(user, internalID, USER_ID);
        user.getIdentities().add(new NumericPrincipal(internalID.getUUID()));

        String x500str = searchResult.getAttributeValue(userLdapAttrib.get(X500Principal.class));
        logger.debug("x500principal: " + x500str);
        if (x500str != null)
        {
            user.getIdentities().add(new X500Principal(x500str));
        }

        String firstName = searchResult.getAttributeValue(LDAP_FIRST_NAME);
        String lastName = searchResult.getAttributeValue(LDAP_LAST_NAME);
        if (StringUtil.hasLength(firstName) && StringUtil.hasLength(lastName))
        {
            user.personalDetails = new PersonalDetails(firstName, lastName);
            user.personalDetails.address = searchResult.getAttributeValue(LDAP_ADDRESS);
            user.personalDetails.city = searchResult.getAttributeValue(LDAP_CITY);
            user.personalDetails.country = searchResult.getAttributeValue(LDAP_COUNTRY);
            user.personalDetails.email = searchResult.getAttributeValue(LDAP_EMAIL);
            user.personalDetails.institute = searchResult.getAttributeValue(LDAP_INSTITUTE);
        }

        logger.info("got " + userID.getName() + " from " + usersDN);
        return user;
    }

    /**
     * Get the user specified by the email address exists.
     *
     * @param emailAddress  The user's email address.
     * @param usersDN The LDAP tree to search.
     * @return User ID
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     * @throws UserAlreadyExistsException A user with the same email address already exists
     */
    private User getUserByEmailAddress(final String emailAddress, final String usersDN)
        throws UserNotFoundException, TransientException,
               AccessControlException, UserAlreadyExistsException
    {
        SearchResultEntry searchResult = null;
        Filter filter = null;
        try
        {
            filter = Filter.createEqualityFilter("email", emailAddress);
            logger.debug("search filter: " + filter);

            SearchRequest searchRequest =
                    new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);

            searchResult = getReadOnlyConnection().searchForEntry(searchRequest);
        }
        catch (LDAPSearchException e)
        {
            if (e.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED)
            {
                String msg = EMAIL_ADDRESS_CONFLICT_MESSAGE + emailAddress + " already in use";
                logger.debug(msg);
                throw new UserAlreadyExistsException(msg);
            }
            else
            {
                LdapDAO.checkLdapResult(e.getResultCode());
            }
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
            catch (LDAPSearchException e)
            {
                if (e.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED)
                {
                    String msg = EMAIL_ADDRESS_CONFLICT_MESSAGE + emailAddress + " already in use";
                    logger.debug(msg);
                    throw new UserAlreadyExistsException(msg);
                }
                else
                {
                    LdapDAO.checkLdapResult(e.getResultCode());
                }
            }
            catch (LDAPException e)
            {
                LdapDAO.checkLdapResult(e.getResultCode());
            }

            if (searchResult == null)
            {
                String msg = "User with email address " + emailAddress + " not found";
                logger.debug(msg);
                throw new UserNotFoundException(msg);
            }
            throw new AccessControlException("Permission denied");
        }

        String userIDString = searchResult.getAttributeValue(LDAP_COMMON_NAME);
        HttpPrincipal userID = new HttpPrincipal(userIDString);
        User user = new User();
        user.getIdentities().add(userID);

        String numericID = searchResult.getAttributeValue(userLdapAttrib.get(NumericPrincipal.class));
        logger.debug("Numeric id: " + numericID);
        if (numericID == null)
        {
            // If the numeric ID does not return it means the user does not have permission
            throw new AccessControlException("Permission denied");
        }

        // Set the User's private InternalID field
        InternalID internalID = getInternalID(numericID);
        setField(user, internalID, USER_ID);
        user.getIdentities().add(new NumericPrincipal(internalID.getUUID()));

        String x500str = searchResult.getAttributeValue(userLdapAttrib.get(X500Principal.class));
        logger.debug("x500principal: " + x500str);

        if (x500str != null)
            user.getIdentities().add(new X500Principal(x500str));

        String firstName = searchResult.getAttributeValue(LDAP_FIRST_NAME);
        String lastName = searchResult.getAttributeValue(LDAP_LAST_NAME);
        if (StringUtil.hasLength(firstName) && StringUtil.hasLength(lastName))
        {
            user.personalDetails = new PersonalDetails(firstName, lastName);
            user.personalDetails.address = searchResult.getAttributeValue(LDAP_ADDRESS);
            user.personalDetails.city = searchResult.getAttributeValue(LDAP_CITY);
            user.personalDetails.country = searchResult.getAttributeValue(LDAP_COUNTRY);
            user.personalDetails.email = searchResult.getAttributeValue(LDAP_EMAIL);
            user.personalDetails.institute = searchResult.getAttributeValue(LDAP_INSTITUTE);
        }

        return user;
    }

    public User getAugmentedUser(final Principal userID)
        throws UserNotFoundException, TransientException
    {
        String searchField = userLdapAttrib.get(userID.getClass());
        profiler.checkpoint("getAugmentedUser.getSearchField");
        if (searchField == null)
        {
            throw new IllegalArgumentException("Unsupported principal type " + userID.getClass());
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

            User user = new User();
            user.getIdentities().add(new HttpPrincipal(
                searchResult.getAttributeValue(LDAP_UID)));

            String numericID = searchResult.getAttributeValue(LDAP_UID);
            logger.debug("numericID is " + numericID);

            InternalID internalID = getInternalID(numericID);
            setField(user, internalID, USER_ID);
            user.getIdentities().add(new NumericPrincipal(internalID.getUUID()));

            String dn = searchResult.getAttributeValue(LDAP_DISTINGUISHED_NAME);
            if (dn != null)
            {
                user.getIdentities().add(new X500Principal(dn));
            }
            user.getIdentities().add(new DNPrincipal(searchResult.getAttributeValue(LDAP_ENTRYDN)));

            // cache memberOf values in the user
            GroupMemberships gms = new GroupMemberships(userID);
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
    public Collection<User> getUsers()
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
    public Collection<User> getPendingUsers()
        throws AccessControlException, TransientException
    {
        return getUsers(config.getUserRequestsDN());
    }

    private Collection<User> getUsers(final String usersDN)
        throws AccessControlException, TransientException
    {
        final Collection<User> users = new ArrayList<User>();

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
                    next.getAttributeValue(LDAP_FIRST_NAME);
                final String lastName =
                    next.getAttributeValue(LDAP_LAST_NAME).trim();
                final String uid = next.getAttributeValue(LDAP_UID);

                User user = new User();
                user.getIdentities().add(new HttpPrincipal(uid));

                // Only add Personal Details if it is relevant.
                if (StringUtil.hasLength(firstName) &&
                    StringUtil.hasLength(lastName))
                {
                    user.personalDetails = new PersonalDetails(firstName.trim(), lastName.trim());
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
    public User approvePendingUser(final Principal userID)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        User pendingUser = getPendingUser(userID);
        if (pendingUser.getHttpPrincipal() == null)
        {
            throw new RuntimeException("BUG: missing HttpPrincipal for " + userID.getName());
        }
        String uid = "uid=" + pendingUser.getID().getUUID().getLeastSignificantBits();
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
     * @param user
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User modifyUser(final User user)
            throws UserNotFoundException, TransientException, AccessControlException
    {
        // Will we always have a HttpPrincipal?
        User existingUser = getUser(user.getHttpPrincipal());

        List<Modification> mods = new ArrayList<Modification>();

        if (user.personalDetails != null)
        {
            addModification(mods, LDAP_FIRST_NAME, user.personalDetails.getFirstName());
            addModification(mods, LDAP_LAST_NAME, user.personalDetails.getLastName());
            addModification(mods, LDAP_ADDRESS, user.personalDetails.address);
            addModification(mods, LDAP_CITY, user.personalDetails.city);
            addModification(mods, LDAP_COUNTRY, user.personalDetails.country);
            addModification(mods, LDAP_EMAIL, user.personalDetails.email);
            addModification(mods, LDAP_INSTITUTE, user.personalDetails.institute);
        }

        if (user.posixDetails != null)
        {
            throw new UnsupportedOperationException(
                "Support for users PosixDetails not available");
        }

        // set the x500 DNs if there
        Set<X500Principal> x500Principals = user.getIdentities(X500Principal.class);
        if (x500Principals != null && !x500Principals.isEmpty())
        {
            Iterator<X500Principal> i = x500Principals.iterator();
            X500Principal next = null;
            while (i.hasNext())
            {
                next = i.next();
                addModification(mods, LDAP_DISTINGUISHED_NAME, next.getName());
            }
        }

        try
        {
            ModifyRequest modifyRequest = new ModifyRequest(getUserDN(user), mods);
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
            User ret = getUser(user.getHttpPrincipal());
            logger.info("updated " + user.getHttpPrincipal().getName());
            return ret;
        }
        catch (UserNotFoundException e)
        {
            throw new RuntimeException(
                "BUG: modified user not found (" + user.getHttpPrincipal().getName() + ")");
        }
    }

    protected void updatePassword(HttpPrincipal userID, String oldPassword, String newPassword)
            throws UserNotFoundException, TransientException, AccessControlException
    {
        try
        {
            User user = new User();
            user.getIdentities().add(userID);
            DN userDN = getUserDN(user);

            //BindRequest bindRequest = new SimpleBindRequest(
            //        getUserDN(username, config.getUsersDN()), oldPassword);
            //LDAPConnection conn = this.getUnboundReadConnection();
            //conn.bind(bindRequest);

            LDAPConnection conn = this.getReadWriteConnection();
            PasswordModifyExtendedRequest passwordModifyRequest;
            if (oldPassword == null)
            {
                passwordModifyRequest =
                        new PasswordModifyExtendedRequest(userDN.toNormalizedString(),
                                null, new String(newPassword));
            }
            else
            {
                passwordModifyRequest =
                        new PasswordModifyExtendedRequest(userDN.toNormalizedString(),
                                new String(oldPassword), new String(newPassword));
            }

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
        updatePassword(userID, oldPassword, newPassword);
    }

    /**
     * Reset a user's password. The given user and authenticating user must match.
     *
     * @param userID
     * @param newPassword   new password.
     * @throws UserNotFoundException If the given user does not exist.
     * @throws TransientException   If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void resetPassword(HttpPrincipal userID, String newPassword)
        throws UserNotFoundException, TransientException, AccessControlException
    {
        updatePassword(userID, null, newPassword);
    }

    /**
     * Delete the user specified by userID from the active user tree.
     *
     * @param userID The userID.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void deleteUser(final Principal userID)
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
    public void deletePendingUser(final Principal userID)
        throws UserNotFoundException, TransientException,
        AccessControlException
    {
        deleteUser(userID, config.getUserRequestsDN(), false);
    }

    private void deleteUser(final Principal userID, final String usersDN, boolean markDelete)
        throws UserNotFoundException, AccessControlException, TransientException
    {
        User user2Delete = getUser(userID, usersDN);
        try
        {
            long id = user2Delete.getID().getUUID().getLeastSignificantBits();
            DN userDN = getUserDN(String.valueOf(id), usersDN);
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

                LDAPResult result = getReadWriteConnection().delete(delRequest);
                logger.info("delete result:" + delRequest);
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
    User getX500User(DN userDN)
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
        User user = new User();
        String distinguishedName = searchResult.getAttributeValue(userLdapAttrib.get(X500Principal.class));
        X500Principal x500Principal = new X500Principal(distinguishedName);
        String username = searchResult.getAttributeValue(userLdapAttrib.get(HttpPrincipal.class));
        if (username != null)
        {
            user.getIdentities().add(new HttpPrincipal(username));
        }
        String firstName = searchResult.getAttributeValue(LDAP_FIRST_NAME);
        String lastName = searchResult.getAttributeValue(LDAP_LAST_NAME);
        if (StringUtil.hasLength(firstName) && StringUtil.hasLength(lastName))
        {
            user.personalDetails = new PersonalDetails(firstName, lastName);
        }
        return user;
    }

    DN getUserDN(User user)
        throws UserNotFoundException, TransientException
    {
        Principal userID = user.getHttpPrincipal();
        String searchField = userLdapAttrib.get(userID.getClass());
        if (searchField == null)
        {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        // change the DN to be in the 'java' format
        Filter filter;
//        if (userID instanceof X500Principal)
//        {
//            X500Principal orderedPrincipal = AuthenticationUtil.getOrderedForm(
//                (X500Principal) userID);
//            filter = Filter.createEqualityFilter(searchField, orderedPrincipal.toString());
//        }
//        else
//        {
            filter = Filter.createEqualityFilter(searchField, userID.getName());
//        }
        logger.debug("search filter: " + filter);

        SearchResultEntry searchResult = null;
        try
        {
            SearchRequest searchRequest = new SearchRequest(
                config.getUsersDN(), SearchScope.ONE, filter, LDAP_ENTRYDN);
            searchResult = getReadOnlyConnection().searchForEntry(searchRequest);
            logger.info("getUserDN: got " + userID.getName() + " from " + config.getUsersDN());
        }
        catch (LDAPException e)
        {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        if (searchResult == null)
        {
            String msg = "User not found " + userID.getName() + " in " + config.getUsersDN();
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

//    protected Principal getUserIDPrincipal(Principal userID)
//    {
//        if (userID instanceof HttpPrincipal)
//        {
//            return new HttpPrincipal(userID.getName());
//        }
//        else if (userID instanceof X500Principal)
//        {
//            return new X500Principal(userID.getName());
//        }
//        else if (userID instanceof NumericPrincipal)
//        {
//            return new NumericPrincipal(UUID.fromString(userID.getName()));
//        }
//        else
//        {
//            throw new IllegalArgumentException("Unsupported principal type " + userID.getClass());
//        }
//    }

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

    /**
     * Get the first supported Principal out of the list of the User's Principals, or
     * null of if the User doesn't have a supported Principal.
     *
     * @param user  the User.
     * @return a Principal.
     */
    protected Principal getSupportedPrincipal(final User user)
    {
        // Look for a HttpPrincipal first.
        if (user.getHttpPrincipal() != null)
        {
            return user.getHttpPrincipal();
        }

        // X500Principal next
        Set<X500Principal> x500Principals = user.getIdentities(X500Principal.class);
        if (!x500Principals.isEmpty())
        {
            return x500Principals.iterator().next();
        }

        // Another supported Principal
//        for (Principal principal : user.getIdentities())
//        {
//            if (userLdapAttrib.get(principal.getClass()) != null)
//            {
//                return principal;
//            }
//        }
        return null;
    }

    protected InternalID getInternalID(String numericID)
    {
        UUID uuid = new UUID(0L, Long.parseLong(numericID));

        final String uriString = AC.USER_URI + uuid.toString();
        URI uri;
        try
        {
            uri = new URI(uriString);
        }
        catch (URISyntaxException e)
        {
            throw new RuntimeException("Invalid InternalID URI " + uriString);
        }
        return new InternalID(uri);
    }

    // set private field using reflection
    private void setField(Object object, Object value, String name)
    {
        try
        {
            Field field = object.getClass().getDeclaredField(name);
            field.setAccessible(true);
            field.set(object, value);
        }
        catch (NoSuchFieldException e)
        {
            final String error = object.getClass().getSimpleName() +
                " field " + name + "not found";
            throw new RuntimeException(error, e);
        }
        catch (IllegalAccessException e)
        {
            final String error = "unable to update " + name + " in " +
                object.getClass().getSimpleName();
            throw new RuntimeException(error, e);
        }
    }

}
