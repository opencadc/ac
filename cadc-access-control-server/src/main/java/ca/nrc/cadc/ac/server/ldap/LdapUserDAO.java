/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.Role;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.client.GroupMemberships;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.ObjectUtil;
import ca.nrc.cadc.util.StringUtil;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.opencadc.gms.GroupURI;
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
 * @author pdowler
 */
public class LdapUserDAO extends LdapDAO {
    public static final String EMAIL_ADDRESS_CONFLICT_MESSAGE =
            "email address ";

    private static final Logger logger = Logger.getLogger(LdapUserDAO.class);

    // Map of identity type to LDAP attribute
    private final Map<Class<?>, String> userLdapAttrib = new HashMap<>();

    // Many of the calls need to filter out LDAP accounts that are locked.
    // (return user accounts that are not locked.)
    private final Filter notFilter = Filter.createNOTFilter(Filter.createPresenceFilter(LDAP_NSACCOUNTLOCK));
    private final Filter notTrueFilter = Filter.createNOTFilter(Filter.createEqualityFilter(LDAP_NSACCOUNTLOCK, "true"));
    private final Filter notLockedFilter = Filter.createANDFilter(notFilter, notTrueFilter);

    // User cn and sn values for users without a HttpPrincipal
    protected static final String EXTERNAL_USER_CN = "$EXTERNAL-CN";
    protected static final String EXTERNAL_USER_SN = "$EXTERNAL-SN";

    // LDAP User attributes
    protected static final String LDAP_INET_ORG_PERSON = "inetOrgPerson";
    protected static final String LDAP_CADC_ACCOUNT = "cadcaccount";
    protected static final String LDAP_POSIX_ACCOUNT = "posixaccount";
    protected static final String LDAP_MEMBEROF = "memberOf";
    protected static final String LDAP_USER_NAME = "cn";
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
    protected static final String LDAP_HOME_DIRECTORY = "homeDirectory";
    protected static final String LDAP_LOGIN_SHELL = "loginShell";
    protected static final String LDAP_OIDCID = "oidcid";

    protected static final String USER_ID = "id";
    protected static final String NO_LOGIN = "/bin/nologin";

    private String[] userAttribs = new String[]
    {
            LDAP_FIRST_NAME, LDAP_LAST_NAME, LDAP_ADDRESS, LDAP_CITY,
            LDAP_COUNTRY, LDAP_EMAIL, LDAP_INSTITUTE, LDAP_HOME_DIRECTORY,
            LDAP_LOGIN_SHELL
    };
    private final String[] identityAttribs = new String[]
    {
            LDAP_UID, LDAP_UID_NUMBER, LDAP_GID_NUMBER,
            LDAP_DISTINGUISHED_NAME, LDAP_ENTRYDN, LDAP_USER_NAME, LDAP_OIDCID
    };

    public LdapUserDAO(LdapConnections connections) {
        super(connections);
        this.userLdapAttrib.put(HttpPrincipal.class, LDAP_USER_NAME);
        this.userLdapAttrib.put(X500Principal.class, LDAP_DISTINGUISHED_NAME);
        this.userLdapAttrib.put(PosixPrincipal.class, LDAP_UID_NUMBER);
        this.userLdapAttrib.put(NumericPrincipal.class, LDAP_UID);
        this.userLdapAttrib.put(OpenIdPrincipal.class, LDAP_OIDCID);
        this.userLdapAttrib.put(DNPrincipal.class, LDAP_ENTRYDN);

        // add the id attributes to user and member attributes
        String[] princs = userLdapAttrib.values().toArray(new String[0]);
        String[] tmp = new String[userAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(userAttribs, 0, tmp, princs.length,
                userAttribs.length);
        userAttribs = tmp;

        String[] firstLastAttribs = new String[]
                {
                        LDAP_FIRST_NAME, LDAP_LAST_NAME
                };
        tmp = new String[firstLastAttribs.length + princs.length];
        System.arraycopy(princs, 0, tmp, 0, princs.length);
        System.arraycopy(firstLastAttribs, 0, tmp, princs.length,
                firstLastAttribs.length);
    }

    /**
     * Verifies the username and password for an existing User.
     *
     * @param username username to verify.
     * @param password password to verify.
     * @return Boolean
     * @throws TransientException - If a temporary, unexpected problem occurred.
     */
    public Boolean doLogin(final String username, final String password)
            throws TransientException {
        try {
            HttpPrincipal httpPrincipal = new HttpPrincipal(username);
            User user = getUser(httpPrincipal);
            long uuid = uuid2long(user.getID().getUUID());
            BindRequest bindRequest = new SimpleBindRequest(
                    getUserDN(uuid, config.getUsersDN()), password);

            LDAPConnection conn = this.getUnboundReadConnection();
            BindResult bindResult = conn.bind(bindRequest);

            if (bindResult != null && bindResult.getResultCode() == ResultCode.SUCCESS) {
                return Boolean.TRUE;
            } else {
                throw new AccessControlException("Invalid username or password");
            }
        } catch (UserNotFoundException e) {
            throw new AccessControlException("Invalid username");
        } catch (LDAPException e) {
            logger.debug("doLogin Exception: " + e, e);

            if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS) {
                throw new AccessControlException("Invalid password");
            } else if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT) {
                throw new AccessControlException("Invalid username");
            } else if (e.getResultCode() == ResultCode.UNWILLING_TO_PERFORM) {
                throw new AccessControlException("Account inactivated");
            }

            throw new RuntimeException("Unexpected LDAP exception", e);
        }
    }

    /**
     * Add the specified user to the active user tree.
     *
     * @param user The user to add.
     * @return User instance.
     * @throws TransientException         If an temporary, unexpected problem occurred.
     * @throws UserAlreadyExistsException If the user already exists.
     */
    public User addUser(final User user)
            throws TransientException, UserAlreadyExistsException {
        Set<Principal> principals = user.getIdentities();
        if (principals.isEmpty()) {
            throw new IllegalArgumentException("addUser: No user identities");
        }

        List<Attribute> attributes = new ArrayList<>();
        String idForLogging = null;
        for (Principal princ : principals) {
            checkUsers(princ, null, config.getUsersDN()); // check identities not in used already
            if (princ instanceof OpenIdPrincipal) {
                idForLogging = toLdapValue((OpenIdPrincipal)princ);
                addAttribute(attributes, LDAP_OIDCID, idForLogging);
            } else if (princ instanceof X500Principal) {
                idForLogging = princ.getName();
                addAttribute(attributes, LDAP_DISTINGUISHED_NAME, princ.getName());
            }
        }

        if (idForLogging == null) {
            throw new IllegalArgumentException("addUser: No validated user identity (OpenId or X500) found");
        }

        try {
            int numericID = this.genNextNumericId();
            String password = UUID.randomUUID().toString();

            String homeDirectory = "/home/" + numericID;
            PosixDetails posixDetails = new PosixDetails(EXTERNAL_USER_CN, numericID, numericID, homeDirectory);
            posixDetails.loginShell = NO_LOGIN;
            user.posixDetails = posixDetails;

            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_ORG_PERSON);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_USER);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_CADC_ACCOUNT);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_POSIX_ACCOUNT);
            addAttribute(attributes, LDAP_UID, String.valueOf(numericID));
            addAttribute(attributes, LDAP_UID_NUMBER, String.valueOf(numericID));
            addAttribute(attributes, LDAP_GID_NUMBER, String.valueOf(numericID));
            addAttribute(attributes, LDAP_USER_NAME, EXTERNAL_USER_CN);
            addAttribute(attributes, LDAP_LAST_NAME, EXTERNAL_USER_SN);
            addAttribute(attributes, LADP_USER_PASSWORD, password);
            addAttribute(attributes, LDAP_HOME_DIRECTORY, user.posixDetails.getHomeDirectory());
            addAttribute(attributes, LDAP_LOGIN_SHELL, user.posixDetails.loginShell);

            // use the same ldapConnection to add the user and subsequently get the same user
            DN userDN = getUserDN(numericID, config.getUsersDN());
            AddRequest addRequest = new AddRequest(userDN, attributes);
            logger.debug("addUser: adding " + idForLogging + " to " + config.getUsersDN());
            LDAPConnection ldapRWConn = getReadWriteConnection();
            LDAPResult result = ldapRWConn.add(addRequest);
            LdapDAO.checkLdapResult(result.getResultCode());
            return getUser((Principal) principals.toArray()[0], ldapRWConn);
        } catch (LDAPException e) {
            logger.error("addUser Exception: " + e, e);
            LdapUserDAO.checkUserLDAPResult(e);
            throw new RuntimeException("Unexpected LDAP exception", e);
        } catch (UserNotFoundException e) {
            throw new RuntimeException("BUG: User not found after adding user", e);
        }
    }

    String toLdapValue(OpenIdPrincipal principal) {
        return principal.getIssuer().toExternalForm() + " " + principal.getName();
    }

    OpenIdPrincipal toOpenIdPrincipal(String value) {
        String[] parts = value.split(" ");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid OpenIdPrincipal value: " + value);
        }
        try {
            return new OpenIdPrincipal(new URL(parts[0]), parts[1]);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid OpenIdPrincipal value: " + value, e);
        }
    }
    private String getEmailAddress(final User user) {
        if (user.personalDetails == null) {
            String error = user.getHttpPrincipal().getName() + " missing required PersonalDetails";
            throw new IllegalArgumentException(error);
        }

        if (!StringUtil.hasText(user.personalDetails.email)) {
            String error = user.getHttpPrincipal().getName() + " missing required email address";
            throw new IllegalArgumentException(error);
        }
        return user.personalDetails.email;
    }

    protected void checkUsers(final Principal userID, final String email, final String usersDN)
            throws TransientException, UserAlreadyExistsException {
        // check current users
        try {
            getUser(userID, usersDN);
            final String error = "user " + userID.getName() + " found in " + usersDN;
            throw new UserAlreadyExistsException(error);
        } catch (UserNotFoundException ok) {
            // no-op
        }

        // check if email address is already in use
        if (email != null) {
            List<User> users = getUsersByEmailAddress(email, usersDN);
            if (!users.isEmpty()) {
                final String error = "email address " + email + " for user " + userID.getName() + " found in " + usersDN;
                throw new UserAlreadyExistsException(error);
            }
        }
    }

    /**
     * Add the specified user to the pending user tree.
     *
     * @param userRequest The user to add.
     * @return User instance.
     * @throws UserNotFoundException      when the user is not found in the main tree.
     * @throws TransientException         If an temporary, unexpected problem occurred.
     * @throws UserAlreadyExistsException If the user already exists.
     */
    public User addUserRequest(final UserRequest userRequest)
            throws UserNotFoundException, TransientException, UserAlreadyExistsException {
        final User user = userRequest.getUser();
        final HttpPrincipal userID = user.getHttpPrincipal();
        if (userID == null) {
            throw new IllegalArgumentException("User missing required HttpPrincipal type");
        }

        if (userID.getName().startsWith("$")) {
            final String error = "addUserRequest: username " + user.getHttpPrincipal().getName() +
                    " cannot start with a $";
            throw new IllegalArgumentException(error);
        }

        // email is required
        String email = getEmailAddress(user);

        // check current users
        checkUsers(userID, email, config.getUsersDN());

        // check user requests
        checkUsers(userID, email, config.getUserRequestsDN());

        try {
            int numericID = this.genNextNumericId();

            String homeDirectory = "/home/" + numericID;
            PosixDetails posixDetails = new PosixDetails(userID.getName(), numericID, numericID, homeDirectory);
            posixDetails.loginShell = NO_LOGIN;
            user.posixDetails = posixDetails;

            List<Attribute> attributes = new ArrayList<>();
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_ORG_PERSON);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_INET_USER);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_CADC_ACCOUNT);
            addAttribute(attributes, LDAP_OBJECT_CLASS, LDAP_POSIX_ACCOUNT);
            addAttribute(attributes, LDAP_UID, String.valueOf(numericID));
            addAttribute(attributes, LDAP_UID_NUMBER, String.valueOf(numericID));
            addAttribute(attributes, LDAP_GID_NUMBER, String.valueOf(numericID));
            addAttribute(attributes, LDAP_USER_NAME, userID.getName());
            addAttribute(attributes, LDAP_LAST_NAME, user.personalDetails.getLastName());
            addAttribute(attributes, LADP_USER_PASSWORD, new String(userRequest.getPassword()));
            addAttribute(attributes, LDAP_FIRST_NAME, user.personalDetails.getFirstName());
            addAttribute(attributes, LDAP_ADDRESS, user.personalDetails.address);
            addAttribute(attributes, LDAP_CITY, user.personalDetails.city);
            addAttribute(attributes, LDAP_COUNTRY, user.personalDetails.country);
            addAttribute(attributes, LDAP_EMAIL, email);
            addAttribute(attributes, LDAP_INSTITUTE, user.personalDetails.institute);
            addAttribute(attributes, LDAP_HOME_DIRECTORY, user.posixDetails.getHomeDirectory());
            addAttribute(attributes, LDAP_LOGIN_SHELL, user.posixDetails.loginShell);

            Set<Principal> principals = user.getIdentities();
            for (Principal princ : principals) {
                if (princ instanceof X500Principal) {
                    addAttribute(attributes, LDAP_DISTINGUISHED_NAME, princ.getName());
                }
                if (princ instanceof OpenIdPrincipal) {
                    addAttribute(attributes, LDAP_OIDCID, toLdapValue((OpenIdPrincipal) princ));
                }
            }

            DN userDN = getUserDN(numericID, config.getUserRequestsDN());
            AddRequest addRequest = new AddRequest(userDN, attributes);
            logger.debug("addUserRequest: adding " + userID.getName() + " to " + config.getUserRequestsDN());
            LDAPConnection ldapRWConn = getReadWriteConnection();
            LDAPResult result = ldapRWConn.add(addRequest);
            LdapDAO.checkLdapResult(result.getResultCode());
            return getUserRequest((Principal) principals.toArray()[0], ldapRWConn);
        } catch (LDAPException e) {
            logger.error("addUserRequest Exception: " + e, e);
            LdapUserDAO.checkUserLDAPResult(e);
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
            AccessControlException {
        return getUser(userID, config.getUsersDN());
    }

    /**
     * Get the user specified by the userID using the specified LDAPConnection.
     *
     * @param userID   The userID.
     * @param ldapConn The LDAPConnection instance to use.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found in the main tree.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User getUser(final Principal userID, final LDAPConnection ldapConn)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        return getUser(userID, config.getUsersDN(), ldapConn, false);
    }

    /**
     * Obtain a user who is awaiting approval.
     *
     * @param userID The user ID of the pending user.
     * @return A User instance awaiting approval.
     * @throws UserNotFoundException  when the user is not found in the user request tree.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User getUserRequest(final Principal userID)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        return getUser(userID, config.getUserRequestsDN());
    }

    /**
     * Obtain a user who is awaiting approval.
     *
     * @param userID   The user ID of the pending user.
     * @param ldapConn The LDAPConnection instance to use.
     * @return A User instance awaiting approval.
     * @throws UserNotFoundException  when the user is not found in the user request tree.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User getUserRequest(final Principal userID, final LDAPConnection ldapConn)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        return getUser(userID, config.getUserRequestsDN(), ldapConn, false);
    }

    /**
     * Return search result entry from Search Result supplied. If there's only one entry,
     * it is returned. If there are more than one, the first one that does NOT have $EXTERNAL-CN
     * as it's LDAP_USER_NAME is returned. Otherwise, an error is thrown.
     *
     * @param multiSearchResult - search result with potentially multiple users
     * @return SearchResultEntry
     */
    private SearchResultEntry getFirstUserEntry(SearchResult multiSearchResult) {
        SearchResultEntry ret = null;

        if (multiSearchResult == null) {
            return null;
        }

        if (multiSearchResult.getSearchEntries().size() == 1) {
            // Only one entry returned, send it back
            return multiSearchResult.getSearchEntries().get(0);
        }

        for (SearchResultEntry next : multiSearchResult.getSearchEntries()) {
            // Need to determine which is the 'right' user
            final String username = next.getAttributeValue(LDAP_USER_NAME);

            // 'Real' user will have an LDAP_USER_NAME that is NOT EXTERNAL_USER_CN
            if (EXTERNAL_USER_CN.equals(username)) {
                continue;
            }
            ret = next;
            break;
        }

        if (ret == null) {
            // multiple entries with EXTERNAL_USER_CN found,
            // with no 'real' user. throw an error
            // todo: get something to identify the user so it can be found in ldap manually
            SearchResultEntry sre = multiSearchResult.getSearchEntries().get(0);
            String x500str = sre.getAttributeValue(userLdapAttrib.get(X500Principal.class));

            throw new RuntimeException("multiple $EXTERNAL-CN users found for userid " + x500str);
        }
        return ret;
    }

    private User makeUserFromResult(SearchResultEntry userEntry) {
        User newUser = new User();

        if (userEntry == null) {
            return null;
        }

        String firstName = userEntry.getAttributeValue(LDAP_FIRST_NAME);
        String lastName = userEntry.getAttributeValue(LDAP_LAST_NAME);

        if (StringUtil.hasLength(firstName) && StringUtil.hasLength(lastName)) {
            newUser.personalDetails = new PersonalDetails(firstName, lastName);
            newUser.personalDetails.address = userEntry.getAttributeValue(LDAP_ADDRESS);
            newUser.personalDetails.city = userEntry.getAttributeValue(LDAP_CITY);
            newUser.personalDetails.country = userEntry.getAttributeValue(LDAP_COUNTRY);
            newUser.personalDetails.email = userEntry.getAttributeValue(LDAP_EMAIL);
            newUser.personalDetails.institute = userEntry.getAttributeValue(LDAP_INSTITUTE);
        }

        String uid = userEntry.getAttributeValue(userLdapAttrib.get(NumericPrincipal.class));
        logger.debug("makeUserFromResult: uid = " + uid);
        if (uid == null) {
            // If the numeric ID does not return it means the user
            // does not have permission
            throw new AccessControlException("Permission denied");
        }

        String username = userEntry.getAttributeValue(LDAP_USER_NAME);
        logger.debug("makeUserFromResult: username = " + username);
        String uidNumberString = null;
        if (username != null) {
            newUser.getIdentities().add(new HttpPrincipal(username));
            String homeDir = userEntry.getAttributeValue(LDAP_HOME_DIRECTORY);
            if (homeDir != null) {
                // uid, uidNumber and gidNumber hold the same value
                uidNumberString = userEntry.getAttributeValue(userLdapAttrib.get(PosixPrincipal.class));
                int uidNumber = Integer.parseInt(uidNumberString);
                newUser.posixDetails = new PosixDetails(username, uidNumber, uidNumber, homeDir);
                newUser.posixDetails.loginShell = userEntry.getAttributeValue(LDAP_LOGIN_SHELL);
            }
        }

        InternalID internalID = getInternalID(uid);
        ObjectUtil.setField(newUser, internalID, USER_ID);
        newUser.getIdentities().add(new NumericPrincipal(internalID.getUUID()));

        String x500str = userEntry.getAttributeValue(userLdapAttrib.get(X500Principal.class));
        logger.debug("makeUserFromResult: x500principal = " + x500str);
        if (x500str != null) {
            newUser.getIdentities().add(new X500Principal(x500str));
        }

        String[] oidc = userEntry.getAttributeValues(userLdapAttrib.get(OpenIdPrincipal.class));
        logger.debug("makeUserFromResult: OpenIdPrincipal = " + oidc);
        if (oidc != null) {
            for (String next : oidc) {
                newUser.getIdentities().add(toOpenIdPrincipal(next));
            }
        }

        logger.debug("makeUserFromResult: posixPrincipal = " + uidNumberString);
        if (uidNumberString != null) {
            newUser.getIdentities().add(new PosixPrincipal(Integer.parseInt(uidNumberString)));
        }

        return newUser;
    }

    private User getUserFromResultList(SearchResult multiSearchResult) {
        SearchResultEntry userEntry = getFirstUserEntry(multiSearchResult);
        return makeUserFromResult(userEntry);
    }

    // Replacement getUser that handles a list returned from ldap
    private User getUser(final Principal userID, final String usersDN)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        return getUser(userID, usersDN, getReadOnlyConnection(), false);
    }

    // Returns users that are locked (disabled or marked deleted)
    public User getLockedUser(final Principal userID)
            throws UserNotFoundException, TransientException {
        return getLockedUser(userID, config.getUsersDN());
    }

    // Returns users that are locked (disabled or marked deleted)
    private User getLockedUser(final Principal userID, final String usersDN)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        return getUser(userID, usersDN, getReadOnlyConnection(), true);
    }

    // Replacement getUser that handles a list returned from ldap
    private User getUser(final Principal userID, final String usersDN, final LDAPConnection ldapConn, Boolean getLocked)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        Profiler profiler = new Profiler(LdapUserDAO.class);

        String searchField = userLdapAttrib.get(userID.getClass());
        if (searchField == null) {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        try {
            String name;
            if (userID instanceof NumericPrincipal) {
                name = String.valueOf(uuid2long(UUID.fromString(userID.getName())));
            } else if (userID instanceof OpenIdPrincipal) {
                name = toLdapValue((OpenIdPrincipal) userID);
            } else {
                name = userID.getName();
            }

            Filter equalsFilter = Filter.createEqualityFilter(searchField, name);
            Filter filter;
            if (!getLocked) {
                filter = Filter.createANDFilter(this.notLockedFilter, equalsFilter);
            } else {
                filter = equalsFilter;
            }
            logger.debug("getUser: search filter = " + filter);

            SearchRequest searchRequest = new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);

            // Get all instances of the user from ldap.
            SearchResult multiSearchResult = ldapConn.search(searchRequest);
            profiler.checkpoint("getUser.search");

            if (multiSearchResult == null || multiSearchResult.getSearchEntries().isEmpty()) {
                String msg = "getUser: user " + userID + " not found in " + usersDN;
                logger.debug(msg);
                throw new UserNotFoundException(msg);
            } else if (multiSearchResult.getSearchEntries().size() > 1) {
                logger.info("getUser: multiple LDAP entries found for " + userID);
            }

            // Determine which is the 'real' user (not automatically generated
            // by vospace interaction, for example) and return that.
            User foundUser;
            foundUser = getUserFromResultList(multiSearchResult);
            if (foundUser == null) {
                throw new RuntimeException(
                        "BUG: user not found (" + userID.getName() + ")");
            }
            logger.debug("getUser: found " + userID.getName() + " in " + usersDN);
            return foundUser;

        } catch (LDAPException e) {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        throw new RuntimeException("BUG: user not found (" + userID.getName() + ")");
    }

    public List<User> getAllUsers(final Principal userID, final String usersDN)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        String searchField = userLdapAttrib.get(userID.getClass());
        List<User> userList = new ArrayList<>();
        if (searchField == null) {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + userID.getClass());
        }

        try {
            String name;
            if (userID instanceof NumericPrincipal) {
                name = String.valueOf(uuid2long(UUID.fromString(userID.getName())));
            } else if (userID instanceof OpenIdPrincipal) {
                name = toLdapValue((OpenIdPrincipal) userID);
            } else {
                name = userID.getName();
            }

            Filter equalsFilter = Filter.createEqualityFilter(searchField, name);
            Filter filter = Filter.createANDFilter(this.notLockedFilter, equalsFilter);
            logger.debug("getAllUsers: search filter = " + filter);

            SearchRequest searchRequest = new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);

            // Get the search, then loop through the entries & build users
            // for the list that will return.
            SearchResult multiSearchResult = getReadOnlyConnection().search(searchRequest);

            if (multiSearchResult == null || multiSearchResult.getSearchEntries().isEmpty()) {
                String msg = "getAllUsers: user " + userID + " not found in " + usersDN;
                logger.debug(msg);
                throw new UserNotFoundException(msg);
            } else if (multiSearchResult.getSearchEntries().size() > 1) {
                logger.info("getAllUsers: ,multiple LDAP entries found for " + userID);
            }

            for (SearchResultEntry next : multiSearchResult.getSearchEntries()) {
                userList.add(makeUserFromResult(next));
            }

        } catch (LDAPException e) {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        logger.debug("getAllUsers returning " + userList.size() + " entries for " + userID);
        return userList;
    }

    /**
     * Get the users specified by the email address exists.
     *
     * @param emailAddress The email address.
     * @return List of users.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public List<User> getUsersByEmailAddress(final String emailAddress)
            throws TransientException, AccessControlException {
        return getUsersByEmailAddress(emailAddress, config.getUsersDN());
    }

    /**
     * Get the users specified by the email address exists.
     *
     * @param emailAddress The email address.
     * @param usersDN      The LDAP tree to search.
     * @return List of users
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    private List<User> getUsersByEmailAddress(final String emailAddress, final String usersDN)
            throws TransientException, AccessControlException {
        SearchResult multiSearchResult = null;
        Filter filter;
        try {
            Filter equalsFilter = Filter.createEqualityFilter("email", emailAddress);
            filter = Filter.createANDFilter(this.notLockedFilter, equalsFilter);
            logger.debug("search filter: " + filter);

            SearchRequest searchRequest =
                    new SearchRequest(usersDN, SearchScope.ONE, filter, userAttribs);

            multiSearchResult = getReadOnlyConnection().search(searchRequest);

        } catch (LDAPException e) {
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        List<User> users = new ArrayList<>();
        if (multiSearchResult == null || multiSearchResult.getSearchEntries().isEmpty()) {
            logger.debug("getUsersByEmailAddress: user not found in " + usersDN);
            return users;
        }

        logger.debug("Found " + multiSearchResult.getSearchEntries().size() + " users with email: " + emailAddress);

        for (SearchResultEntry searchResult : multiSearchResult.getSearchEntries()) {
            String userIDString = searchResult.getAttributeValue(LDAP_USER_NAME);

            User user = new User();
            // don't add http identities for those with external dns
            if (!EXTERNAL_USER_CN.equals(userIDString)) {
                HttpPrincipal userID = new HttpPrincipal(userIDString);
                user.getIdentities().add(userID);
            }

            // Set the User's private InternalID field
            String numericID = searchResult.getAttributeValue(userLdapAttrib.get(NumericPrincipal.class));
            InternalID internalID = getInternalID(numericID);
            ObjectUtil.setField(user, internalID, USER_ID);
            user.getIdentities().add(new NumericPrincipal(internalID.getUUID()));

            String x500str = searchResult.getAttributeValue(userLdapAttrib.get(X500Principal.class));
            logger.debug("getUserByEmailAddress: x500principal = " + x500str);
            if (x500str != null)
                user.getIdentities().add(new X500Principal(x500str));

            String[] oidcid = searchResult.getAttributeValues(userLdapAttrib.get(OpenIdPrincipal.class));
            if (oidcid != null) {
                for (String next : oidcid) {
                    logger.debug("getUserByEmailAddress: OpenIdPrincipal = " + next);
                    user.getIdentities().add(toOpenIdPrincipal(next));
                }
            }

            String firstName = searchResult.getAttributeValue(LDAP_FIRST_NAME);
            String lastName = searchResult.getAttributeValue(LDAP_LAST_NAME);
            if (StringUtil.hasLength(firstName) && StringUtil.hasLength(lastName)) {
                user.personalDetails = new PersonalDetails(firstName, lastName);
                user.personalDetails.address = searchResult.getAttributeValue(LDAP_ADDRESS);
                user.personalDetails.city = searchResult.getAttributeValue(LDAP_CITY);
                user.personalDetails.country = searchResult.getAttributeValue(LDAP_COUNTRY);
                user.personalDetails.email = searchResult.getAttributeValue(LDAP_EMAIL);
                user.personalDetails.institute = searchResult.getAttributeValue(LDAP_INSTITUTE);
            }

            String uidNumberStr = searchResult.getAttributeValue(userLdapAttrib.get(PosixPrincipal.class));
            logger.debug("getUserByEmailAddress: posixprincipal = " + uidNumberStr);
            if (uidNumberStr != null) {
                user.getIdentities().add(new PosixPrincipal(Integer.parseInt(uidNumberStr)));
                String homeDir = searchResult.getAttributeValue(LDAP_HOME_DIRECTORY);
                if (homeDir != null) {
                    // numericID, uidNumber and gidNumber hold the same value
                    int uidNumber = Integer.parseInt(uidNumberStr);
                    user.posixDetails = new PosixDetails(userIDString, uidNumber, uidNumber, homeDir);
                    user.posixDetails.loginShell = searchResult.getAttributeValue(LDAP_LOGIN_SHELL);
                }
            }

            users.add(user);

        }

        return users;
    }

    public User getAugmentedUser(final Principal userID, final boolean primeGroupCache)
            throws UserNotFoundException, TransientException {
        Profiler profiler = new Profiler(LdapUserDAO.class);
        String searchField = userLdapAttrib.get(userID.getClass());
        if (searchField == null) {
            throw new IllegalArgumentException("getAugmentedUser: unsupported principal type " +
                    userID.getClass());
        }

        try {
            String name;
            if (userID instanceof NumericPrincipal) {
                name = String.valueOf(uuid2long(UUID.fromString(userID.getName())));
            } else if (userID instanceof OpenIdPrincipal) {
                name = toLdapValue((OpenIdPrincipal) userID);
            } else {
                name = userID.getName();
            }

            Filter equalsFilter = Filter.createEqualityFilter(searchField, name);
            Filter filter = Filter.createANDFilter(this.notLockedFilter, equalsFilter);

            profiler.checkpoint("getAugmentedUser.createFilter");
            logger.debug("getAugmentedUser: search filter = " + filter);

            String[] attrs = identityAttribs;
            if (primeGroupCache) {
                attrs = new String[identityAttribs.length + 1];
                System.arraycopy(identityAttribs, 0, attrs, 0, identityAttribs.length);
                attrs[identityAttribs.length] = LDAP_MEMBEROF;

            }
            String usersDN = config.getUsersDN();
            SearchRequest searchRequest = new SearchRequest(
                    usersDN, SearchScope.ONE, filter, attrs);

            profiler.checkpoint("getAugmentedUser.getReadOnlyConnection");
            SearchResult multiSearchResult = getReadOnlyConnection().search(searchRequest);
            profiler.checkpoint("getAugmentedUser.search");

            if (multiSearchResult == null || multiSearchResult.getSearchEntries().isEmpty()) {
                String msg = "getUser: user " + userID + " not found in " + usersDN;
                logger.debug(msg);
                throw new UserNotFoundException(msg);
            } else if (multiSearchResult.getSearchEntries().size() > 1) {
                logger.info("getAugmentedUser: multiple LDAP entries found for " + userID);
            }

            // Get entry from possible list of user instances from ldap
            SearchResultEntry userFromSearch = getFirstUserEntry(multiSearchResult);

            if (userFromSearch == null) {
                throw new RuntimeException(
                        "BUG: augmented user not found (" + userID.getName() + ")");
            }
            logger.debug("getAugmentedUser: found " + userID.getName() + " in " + usersDN);

            User user = new User();
            String username = userFromSearch.getAttributeValue(LDAP_USER_NAME);
            logger.debug("getAugmentedUser: username = " + username);
            // don't add http identities for those with external dns
            if (!EXTERNAL_USER_CN.equals(username)) {
                user.getIdentities().add(new HttpPrincipal(username));
            }

            String numericID = userFromSearch.getAttributeValue(LDAP_UID);
            logger.debug("getAugmentedUser: numericID = " + numericID);

            InternalID internalID = getInternalID(numericID);
            ObjectUtil.setField(user, internalID, USER_ID);
            user.getIdentities().add(new NumericPrincipal(internalID.getUUID()));

            String dn = userFromSearch.getAttributeValue(LDAP_DISTINGUISHED_NAME);
            if (dn != null) {
                user.getIdentities().add(new X500Principal(dn));
            }
            user.getIdentities().add(new DNPrincipal(userFromSearch.getAttributeValue(LDAP_ENTRYDN)));
            String[] openId = userFromSearch.getAttributeValues(LDAP_OIDCID);
            if (openId != null) {
                for (String next : openId) {
                    logger.debug("getAugmentedUser: OpenIdPrincipal = " + next);
                    user.getIdentities().add(toOpenIdPrincipal(next));
                }
            }

            String uidNumberString = userFromSearch.getAttributeValue(LDAP_UID_NUMBER);
            if (uidNumberString != null) {
                user.getIdentities().add(new PosixPrincipal(Integer.parseInt(uidNumberString)));
                // HACK by pdowler: add posix details to augment
                int uidNumber = Integer.parseInt(uidNumberString);
                // home dir hack because it's required but not used
                user.posixDetails = new PosixDetails(username, uidNumber, uidNumber, "/home/" + uidNumber);
            }

            // cache memberOf values in the user
            LocalAuthority localAuthority = new LocalAuthority();
            URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());

            if (primeGroupCache) {
                GroupMemberships gms = new GroupMemberships(gmsServiceURI.toString(), userID);
                user.appData = gms; // add even if empty
                String[] mems = userFromSearch.getAttributeValues(LDAP_MEMBEROF);
                if (mems != null && mems.length > 0) {
                    DN adminDN = new DN(config.getAdminGroupsDN());
                    DN groupsDN = new DN(config.getGroupsDN());
                    List<Group> memberOf = new ArrayList<>();
                    List<Group> adminOf = new ArrayList<>();
                    for (String m : mems) {
                        DN groupDN = new DN(m);
                        if (groupDN.isDescendantOf(groupsDN, false))
                            memberOf.add(createGroupFromDN(groupDN));
                        else if (groupDN.isDescendantOf(adminDN, false))
                            adminOf.add(createGroupFromDN(groupDN));
                    }
                    gms.add(adminOf, Role.ADMIN);
                    gms.add(memberOf, Role.MEMBER);
                }
            }
            profiler.checkpoint("getAugmentedUser.mapIdentities");
            logger.debug("getAugmentedUser: returning user " + userID.getName());
            return user;
        } catch (LDAPException e) {
            logger.debug("getAugmentedUser Exception: " + e, e);
            LdapDAO.checkLdapResult(e.getResultCode());
            throw new RuntimeException("BUG: checkLdapResult didn't throw an exception");
        } finally {
            profiler.checkpoint("Done getAugmentedUser");
        }
    }

    // some pretty horrible hacks to avoid querying LDAP for group details...
    private Group createGroupFromDN(DN groupDN) {
        LocalAuthority localAuthority = new LocalAuthority();
        URI gmsServiceURI = localAuthority.getServiceURI(Standards.GMS_GROUPS_01.toString());
        String cn = groupDN.getRDNString();
        String[] parts = cn.split("=");
        if (parts.length == 2 && parts[0].equals("cn")) {
            GroupURI groupID = new GroupURI(gmsServiceURI, parts[1]);
            return new Group(groupID);
        }
        throw new RuntimeException("BUG: failed to extract group name from " + groupDN);
    }

    /**
     * Get all users from the active tree.
     *
     * @return A Collection of User's.
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public Collection<User> getUsers()
            throws AccessControlException, TransientException {
        return getUsers(config.getUsersDN());
    }

    /**
     * Get all users from the pending tree.
     *
     * @return A Collection of User's.
     * @throws TransientException If an temporary, unexpected problem occurred.
     */
    public Collection<User> getUserRequests()
            throws AccessControlException, TransientException {
        return getUsers(config.getUserRequestsDN());
    }

    public Collection<User> getUsers(final String usersDN)
            throws AccessControlException, TransientException {
        final Collection<User> users = new ArrayList<>();

        Filter presenceFilter = Filter.createPresenceFilter(LDAP_UID);
        Filter filter = Filter.createANDFilter(this.notLockedFilter, presenceFilter);
        logger.debug("search filter: " + filter);

        final String[] attributes = new String[]
                {LDAP_USER_NAME, LDAP_FIRST_NAME, LDAP_LAST_NAME, LDAP_UID_NUMBER, LDAP_HOME_DIRECTORY};
        final SearchRequest searchRequest =
                new SearchRequest(usersDN, SearchScope.ONE, filter, attributes);

        try {
            final SearchResult searchResult =
                    getReadOnlyConnection().search(searchRequest);

            LdapDAO.checkLdapResult(searchResult.getResultCode());
            for (SearchResultEntry next : searchResult.getSearchEntries()) {
                final String firstName =
                        next.getAttributeValue(LDAP_FIRST_NAME);
                final String lastName =
                        next.getAttributeValue(LDAP_LAST_NAME).trim();
                final String username = next.getAttributeValue(LDAP_USER_NAME);

                User user = new User();
                // don't add users with no http identities
                if (!EXTERNAL_USER_CN.equals(username)) {
                    user.getIdentities().add(new HttpPrincipal(username));

                    if (StringUtil.hasLength(firstName) && StringUtil.hasLength(lastName)) {
                        user.personalDetails = new PersonalDetails(firstName.trim(), lastName.trim());
                    }

                    String homeDir = next.getAttributeValue(LDAP_HOME_DIRECTORY);
                    if (homeDir != null) {
                        // uid, uidNumber and gidNumber hold the same value
                        int uidNumber = Integer.parseInt(next.getAttributeValue(LDAP_UID_NUMBER));
                        user.posixDetails = new PosixDetails(username, uidNumber, uidNumber, homeDir);
                        user.posixDetails.loginShell = next.getAttributeValue(LDAP_LOGIN_SHELL);
                    }

                    users.add(user);
                }
            }
        } catch (LDAPSearchException e) {
            if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT) {
                final String message = "Could not find users root";
                logger.debug(message, e);
                throw new IllegalStateException(message);
            }
        }
        logger.debug("getUsers: found " + users.size() + " in " + usersDN);
        return users;
    }

    public SortedSet<String> getEmailsForAllUsers()
            throws AccessControlException, TransientException {

        Filter emailFilter = Filter.createPresenceFilter(LDAP_EMAIL);
        Filter filter = Filter.createANDFilter(this.notLockedFilter, emailFilter);
        logger.debug("search filter: " + filter);

        final SortedSet<String> emails = new TreeSet<>();
        final String[] attributes = new String[]{LDAP_EMAIL};
        final SearchRequest searchRequest = new SearchRequest(config.getUsersDN(), SearchScope.ONE, filter, attributes);

        try {
            final SearchResult searchResult = getReadOnlyConnection().search(searchRequest);

            LdapDAO.checkLdapResult(searchResult.getResultCode());
            for (SearchResultEntry next : searchResult.getSearchEntries()) {
                emails.add(next.getAttributeValue(LDAP_EMAIL));
            }
        } catch (LDAPSearchException e) {
            if (e.getResultCode() == ResultCode.NO_SUCH_OBJECT) {
                final String message = "Could not find users root";
                logger.debug(message, e);
                throw new IllegalStateException(message);
            }
        }
        logger.debug("getDistinctEmailAddressesForAllUsers: found " + emails.size()
                + " distinct emails in " + config.getUsersDN());

        return emails;
    }

    /**
     * Move the pending user specified by userID from the
     * pending users tree to the active users tree.
     *
     * @param userID - The user ID of the pending user.
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User approveUserRequest(final Principal userID)
            throws UserNotFoundException, TransientException, AccessControlException {
        // ensure that we use the same LDAP server
        LDAPConnection ldapRWConn = getReadWriteConnection();
        User userRequest = getUserRequest(userID, ldapRWConn);
        if (userRequest.getHttpPrincipal() == null) {
            throw new RuntimeException("BUG: missing HttpPrincipal for " + userID.getName());
        }
        String uid = "uid=" + uuid2long(userRequest.getID().getUUID());
        String dn = uid + "," + config.getUserRequestsDN();

        try {
            ModifyDNRequest modifyDNRequest =
                    new ModifyDNRequest(dn, uid, true, config.getUsersDN());

            LdapDAO.checkLdapResult(ldapRWConn.modifyDN(modifyDNRequest).getResultCode());
        } catch (LDAPException e) {
            logger.debug("Modify Exception", e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        try {
            User user = getUser(userID, ldapRWConn);
            logger.debug("approvedUserRequest: " + userID.getName());
            return user;
        } catch (UserNotFoundException e) {
            throw new RuntimeException(
                    "BUG: approved user not found (" + userID.getName() + ")");
        }
    }

    /**
     * Update the user specified by User.
     *
     * @param user Updated user
     * @return User instance.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public User modifyUser(final User user)
            throws UserNotFoundException, TransientException, AccessControlException {

        List<Modification> mods = new ArrayList<>();

        if (user.personalDetails != null) {
            addModification(mods, LDAP_FIRST_NAME, user.personalDetails.getFirstName());
            addModification(mods, LDAP_LAST_NAME, user.personalDetails.getLastName());
            addModification(mods, LDAP_ADDRESS, user.personalDetails.address);
            addModification(mods, LDAP_CITY, user.personalDetails.city);
            addModification(mods, LDAP_COUNTRY, user.personalDetails.country);
            addModification(mods, LDAP_EMAIL, user.personalDetails.email);
            addModification(mods, LDAP_INSTITUTE, user.personalDetails.institute);
        }

        if (user.posixDetails != null) {
            addModification(mods, LDAP_USER_NAME, user.posixDetails.getUsername());
            addModification(mods, LDAP_UID_NUMBER, Integer.toString(user.posixDetails.getUid()));
            addModification(mods, LDAP_GID_NUMBER, Integer.toString(user.posixDetails.getGid()));
            addModification(mods, LDAP_HOME_DIRECTORY, user.posixDetails.getHomeDirectory());
            addModification(mods, LDAP_LOGIN_SHELL, user.posixDetails.loginShell);
        }

        // set the x500 DNs if there
        Set<X500Principal> x500Principals = user.getIdentities(X500Principal.class);
        if (x500Principals != null && !x500Principals.isEmpty()) {
            for (X500Principal x500Principal : x500Principals) {
                addModification(mods, LDAP_DISTINGUISHED_NAME, x500Principal.getName());
            }
        }
        Set<OpenIdPrincipal> openIdPrincipals = user.getIdentities(OpenIdPrincipal.class);
        if (openIdPrincipals != null && !openIdPrincipals.isEmpty()) {
            for (OpenIdPrincipal openIdPrincipal : openIdPrincipals) {
                addModification(mods, LDAP_OIDCID, toLdapValue(openIdPrincipal));
            }
        }

        LDAPConnection ldapRWConn = getReadWriteConnection();
        try {
            ModifyRequest modifyRequest = new ModifyRequest(getUserDN(user, ldapRWConn, false), mods);
            LdapDAO.checkLdapResult(ldapRWConn.modify(modifyRequest).getResultCode());
        } catch (LDAPException e) {
            logger.debug("Modify Exception", e);
            LdapDAO.checkLdapResult(e.getResultCode());
        }
        try {
            User ret = getUser(user.getHttpPrincipal(), ldapRWConn);
            logger.debug("ModifiedUser: " + user.getHttpPrincipal().getName());
            return ret;
        } catch (UserNotFoundException e) {
            throw new RuntimeException(
                    "BUG: modified user not found (" + user.getHttpPrincipal().getName() + ")");
        }
    }

    protected void updatePassword(HttpPrincipal userID, String oldPassword, String newPassword)
            throws UserNotFoundException, TransientException, AccessControlException {
        try {
            // ensure that we access the same LDAP server
            LDAPConnection ldapRWConn = this.getReadWriteConnection();
            User user = new User();
            user.getIdentities().add(userID);
            DN userDN = getUserDN(user, ldapRWConn, false);

            PasswordModifyExtendedRequest passwordModifyRequest;
            if (oldPassword == null) {
                passwordModifyRequest =
                        new PasswordModifyExtendedRequest(userDN.toNormalizedString(),
                                null, newPassword);
            } else {
                passwordModifyRequest =
                        new PasswordModifyExtendedRequest(userDN.toNormalizedString(),
                                oldPassword, newPassword);
            }

            PasswordModifyExtendedResult passwordModifyResult = (PasswordModifyExtendedResult)
                    ldapRWConn.processExtendedOperation(passwordModifyRequest);

            LdapDAO.checkLdapResult(passwordModifyResult.getResultCode());
            logger.debug("updatedPassword for " + userID.getName());
        } catch (LDAPException e) {
            logger.debug("setPassword Exception: " + e);
            LdapDAO.checkLdapResult(e);
        }
    }

    /**
     * Update a user's password. The given user and authenticating user must match.
     *
     * @param userID ID of user to update password for
     * @param oldPassword current password.
     * @param newPassword new password.
     * @throws UserNotFoundException  If the given user does not exist.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void setPassword(HttpPrincipal userID, String oldPassword, String newPassword)
            throws UserNotFoundException, TransientException, AccessControlException {
        updatePassword(userID, oldPassword, newPassword);
    }

    /**
     * Reset a user's password. The given user and authenticating user must match.
     *
     * @param userID ID of user to reset password for
     * @param newPassword new password.
     * @throws UserNotFoundException  If the given user does not exist.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void resetPassword(HttpPrincipal userID, String newPassword)
            throws UserNotFoundException, TransientException, AccessControlException {
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
    public void deleteUser(final Principal userID, boolean markDelete)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        deleteUser(userID, config.getUsersDN(), markDelete);
    }

    /**
     * Delete the user specified by userID from the active user tree.
     *
     * @param userID The userID.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void unlockUser(final Principal userID)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        unlockUser(userID, config.getUsersDN());
    }


    /**
     * Delete the user specified by userID from the pending user tree.
     *
     * @param userID The userID.
     * @throws UserNotFoundException  when the user is not found.
     * @throws TransientException     If an temporary, unexpected problem occurred.
     * @throws AccessControlException If the operation is not permitted.
     */
    public void deleteUserRequest(final Principal userID)
            throws UserNotFoundException, TransientException,
            AccessControlException {
        deleteUser(userID, config.getUserRequestsDN(), false);
    }

    private void deleteUser(final Principal userID, final String usersDN, boolean markDelete)
            throws UserNotFoundException, AccessControlException, TransientException {
        User user2Delete = getUser(userID, usersDN);
        LDAPConnection ldapRWConn = getReadWriteConnection();
        try {
            long uuid = uuid2long(user2Delete.getID().getUUID());
            DN userDN = getUserDN(uuid, usersDN);
            if (markDelete) {
                List<Modification> modifs = new ArrayList<>();
                modifs.add(new Modification(ModificationType.ADD, LDAP_NSACCOUNTLOCK, "true"));

                ModifyRequest modifyRequest = new ModifyRequest(userDN, modifs);

                LDAPResult result = ldapRWConn.modify(modifyRequest);
                LdapDAO.checkLdapResult(result.getResultCode());
            } else // real delete
            {
                DeleteRequest delRequest = new DeleteRequest(userDN);

                LDAPResult result = ldapRWConn.delete(delRequest);
                logger.info("delete result:" + delRequest);
                LdapDAO.checkLdapResult(result.getResultCode());
            }
            logger.debug("deleted " + userID.getName() + " from " + usersDN);
        } catch (LDAPException e1) {
            logger.debug("Delete Exception: " + e1, e1);
            LdapDAO.checkLdapResult(e1.getResultCode());
        }

        // getUser does not yet support nsaccountlock
        if (!markDelete) {
            try {
                getUser(userID, usersDN, ldapRWConn, false);
                throw new RuntimeException(
                        "BUG: " + userID.getName() + " not deleted in " + usersDN);
            } catch (UserNotFoundException ignore) {
            }
        }
    }

    private void unlockUser(final Principal userID, final String usersDN)
            throws UserNotFoundException, AccessControlException, TransientException {
        User user2Unlock = getLockedUser(userID, usersDN);
        LDAPConnection ldapRWConn = getReadWriteConnection();
        try {
            long uuid = uuid2long(user2Unlock.getID().getUUID());
            DN userDN = getUserDN(uuid, usersDN);

            List<Modification> modifs = new ArrayList<>();
            modifs.add(new Modification(ModificationType.DELETE, LDAP_NSACCOUNTLOCK));

            ModifyRequest modifyRequest = new ModifyRequest(userDN, modifs);

            LDAPResult result = ldapRWConn.modify(modifyRequest);
            LdapDAO.checkLdapResult(result.getResultCode());

            logger.debug("unlocked " + userID.getName());
        } catch (LDAPException e1) {
            logger.debug("UnlockUser Exception: " + e1, e1);

            // If there is no LDAP_NSACCOUNTLOCK attribute, the user is not locked
            // and for this function it's not an error
            LdapDAO.checkLdapResult(e1.getResultCode(), true, e1.getMessage());
        }
    }

    private Principal getPreferredPrincipal(User user) {
        Principal ret = null;
        Principal next;
        for (Principal principal : user.getIdentities()) {
            next = principal;
            if (next instanceof NumericPrincipal) {
                return next;
            }
            ret = next;
        }
        return ret;
    }

    DN getUserDN(User user, final LDAPConnection ldapConn, boolean isPending)
            throws UserNotFoundException, TransientException, LDAPException {
        Principal p = getPreferredPrincipal(user);
        if (p == null) {
            throw new UserNotFoundException("No identities");
        }

        String configUserDN;
        if (isPending) {
            configUserDN = config.getUserRequestsDN();
        } else {
            configUserDN = config.getUsersDN();
        }

        // DN can be formulated if it is the numeric id
        if (p instanceof NumericPrincipal)
            return this.getUserDN(uuid2long(UUID.fromString(p.getName())), configUserDN);

        // Otherwise we need to search for the numeric id
        String searchField = userLdapAttrib.get(p.getClass());
        if (searchField == null) {
            throw new IllegalArgumentException(
                    "Unsupported principal type " + p.getClass());
        }

        Filter filter = Filter.createEqualityFilter(searchField, p.getName());
        logger.debug("search filter: " + filter);

        SearchResultEntry searchResult = null;
        try {
            SearchRequest searchRequest = new SearchRequest(
                    configUserDN, SearchScope.ONE, filter, LDAP_ENTRYDN);
            searchResult = ldapConn.searchForEntry(searchRequest);
            logger.debug("getUserDN: got " + p.getName() + " from " + configUserDN);
        } catch (LDAPException e) {
            LdapDAO.checkLdapResult(e.getResultCode());
        }

        if (searchResult == null) {
            String msg = "User not found " + p.getName() + " in " + configUserDN;
            logger.debug(msg);
            throw new UserNotFoundException(msg);
        }
        return searchResult.getAttributeValueAsDN(LDAP_ENTRYDN);
    }

    protected DN getUserDN(long numericID, String usersDN)
            throws LDAPException, TransientException {
        return new DN(LDAP_UID + "=" + numericID + "," + usersDN);
    }

    private void addAttribute(List<Attribute> attributes, final String name, final String value) {
        if (value != null && !value.isEmpty()) {
            attributes.add(new Attribute(name, value));
        }
    }

    private void addModification(List<Modification> mods, final String name, final String value) {
        if (value != null && !value.isEmpty()) {
            mods.add(new Modification(ModificationType.REPLACE, name, value));
        } else {
            mods.add(new Modification(ModificationType.REPLACE, name));
        }
    }

    protected static void checkUserLDAPResult(LDAPException e)
            throws TransientException, UserAlreadyExistsException {
        if (e.getResultCode() == ResultCode.ENTRY_ALREADY_EXISTS) {
            throw new UserAlreadyExistsException("User already exists.");
        } else {
            LdapDAO.checkLdapResult(e);
        }
    }

    protected long uuid2long(UUID uuid) {
        return uuid.getLeastSignificantBits();
    }

    protected InternalID getInternalID(String numericID) {
        UUID uuid = new UUID(0L, Long.parseLong(numericID));
        LocalAuthority localAuthority = new LocalAuthority();
        URI umsServiceURI = localAuthority.getServiceURI(Standards.UMS_REQS_01.toString());
        String uriString = umsServiceURI.toString() + "?" + uuid;
        URI uri;
        try {
            uri = new URI(uriString);
        } catch (URISyntaxException e) {
            throw new RuntimeException("Invalid InternalID URI " + uriString);
        }
        return new InternalID(uri);
    }

}
