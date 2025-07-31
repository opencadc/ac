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

package ca.nrc.cadc.ac.client;

import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserAlreadyExistsException;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.ac.xml.UserReader;
import ca.nrc.cadc.ac.xml.UserWriter;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.net.HttpDownload;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.HttpUpload;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessControlException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;


/**
 * Client class for performing user searching and user actions
 * with the access control web service.
 */
public class UserClient {
    private static final Logger log = Logger.getLogger(UserClient.class);

    private URI serviceID;

    /**
     * Constructor.
     *
     * @param serviceID The URI of the supporting access control web service
     *                  obtained from the registry.
     */
    public UserClient(URI serviceID)
            throws IllegalArgumentException {
        if (serviceID == null) {
            throw new IllegalArgumentException("Service URI cannot be null.");
        }
        if (serviceID.getFragment() != null) {
            throw new IllegalArgumentException("invalid serviceURI (fragment not allowed): " + serviceID);
        }
        this.serviceID = serviceID;
    }

    /**
     * This method takes a subject with at least one valid principal,
     * uses the ac user web service to get all the other
     * associated principals which are then added to the subject.
     *
     * @param subject The Subject to pull Princials for.
     * @throws MalformedURLException
     */
    public void augmentSubject(Subject subject) throws MalformedURLException {
        Principal principal = this.getPrincipal(subject);
        if (principal != null) {

            String userID = principal.getName();
            AuthMethod authMethod;
            if ((principal instanceof OpenIdPrincipal) || (principal instanceof AuthorizationToken)) {
                authMethod = AuthMethod.TOKEN;
            } else {
                authMethod = AuthMethod.CERT;
            }
            String userPath;
            if (authMethod == AuthMethod.TOKEN) {
                userPath = "/" + NetUtil.encode(userID)
                        + "?iss=" + NetUtil.encode(((OpenIdPrincipal) principal).getIssuer().toExternalForm());
            } else {
                userPath = "/" + NetUtil.encode(userID)
                        + "?idType=" + NetUtil.encode(this.getIdType(principal));
            }
            URL usersURL = getRegistryClient()
                        .getServiceURL(this.serviceID, Standards.UMS_USERS_01, AuthMethod.CERT);
            if (usersURL == null) {
                throw new IllegalArgumentException("No service endpoint for uri " + Standards.UMS_USERS_01 + " and authMethod " + authMethod);
            }

            URL getUserURL = new URL(usersURL.toExternalForm() + userPath);
            log.debug("augmentSubject request to " + getUserURL);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            HttpGet download = new HttpGet(getUserURL, out);
            download.run();

            int responseCode = download.getResponseCode();
            if (responseCode == 404) {
                return;
            }
            if (responseCode != 200) {
                String message = "Error calling /ac to augment subject";
                if (download.getThrowable() != null) {
                    throw new IllegalStateException(message, download
                            .getThrowable());
                }
                throw new IllegalStateException(message);
            }

            subject.getPrincipals().clear();
            subject.getPrincipals().addAll(this.getPrincipals(out));
        }
    }

    /**
     * Obtain all of the users as userID - name in JSON format.
     *
     * @return List of HTTP Principal users.
     * @throws IOException Any errors in reading.
     */
    public List<User> getDisplayUsers() throws IOException {

        AuthMethod am = getAuthMethod();
        URL usersURL = getRegistryClient()
                .getServiceURL(this.serviceID, Standards.UMS_USERS_01, am);
        final List<User> webUsers = new ArrayList<User>();
        HttpDownload httpDownload =
                new HttpDownload(usersURL,
                        new JsonUserListInputStreamWrapper(webUsers));
        httpDownload.setRequestProperty("Accept", "application/json");
        httpDownload.run();

        final Throwable error = httpDownload.getThrowable();

        if (error != null) {
            final String errMessage = error.getMessage();
            final int responseCode = httpDownload.getResponseCode();
            log.debug("getDisplayUsers response " + responseCode + ": "
                    + errMessage);
            if ((responseCode == 401) || (responseCode == 403)
                    || (responseCode == -1)) {
                throw new AccessControlException(errMessage);
            } else if (responseCode == 400) {
                throw new IllegalArgumentException(errMessage);
            } else {
                throw new IOException("HttpResponse (" + responseCode + ") - "
                        + errMessage);
            }
        }

        log.debug("Content-Length: " + httpDownload.getContentLength());
        log.debug("Content-Type: " + httpDownload.getContentType());

        return webUsers;
    }

    /**
     * Create an auto-approved user directly in the user tree (not
     * the userRequest tree) from the principal.
     *
     * @param principal Their x500 Principal
     * @throws UserAlreadyExistsException
     * @throws WriterException
     * @throws IOException
     * @throws URISyntaxException
     * @throws ReaderException
     */
    public User createUser(Principal principal)
            throws UserAlreadyExistsException, IOException, WriterException,
            ReaderException, URISyntaxException {
        if (principal == null) {
            throw new IllegalArgumentException("principal required");
        }

        User user = new User();
        user.getIdentities().add(principal);
        UserWriter userWriter = new UserWriter();
        StringBuilder userXML = new StringBuilder();
        userWriter.write(user, userXML);

        AuthMethod am = getAuthMethod();

        URL createUserURL = getRegistryClient()
                .getServiceURL(this.serviceID, Standards.UMS_USERS_01, am);

        if (createUserURL == null) {
            throw new IllegalArgumentException("No service endpoint for uri " + Standards.UMS_REQS_01);
        }
        log.debug("createUser request to " + createUserURL.toString());

        ByteArrayInputStream in = new ByteArrayInputStream(userXML.toString()
                .getBytes());
        HttpUpload put = new HttpUpload(in, createUserURL);

        put.run();
        int responseCode = put.getResponseCode();

        if (responseCode == 200 || responseCode == 201) {
            UserReader userReader = new UserReader();
            return userReader.read(put.getResponseBody());
        }

        String message = "";
        if (put.getThrowable() != null) {
            log.debug("error calling createX509User", put.getThrowable());
            message = put.getThrowable().getMessage();
        }

        if (responseCode == 400) {
            throw new IllegalArgumentException(message);
        }
        if (responseCode == 409) {  // conflict
            throw new UserAlreadyExistsException(message);
        }
        if (responseCode == 403) {
            throw new AccessControlException(message);
        }
        throw new IllegalStateException(message);
    }

    /**
     * Given a pricipal return the user object.
     *
     * @param principal The principal to lookup.
     * @throws URISyntaxException
     * @throws IOException
     * @throws ReaderException
     * @throws UserNotFoundException
     */
    public User getUser(Principal principal)
            throws ReaderException, IOException, URISyntaxException,
            UserNotFoundException {
        String id = NetUtil.encode(principal.getName());
        String path = "/" + id + "?idType=" + AuthenticationUtil
                .getPrincipalType(principal);
        AuthMethod am = getAuthMethod();

        URL usersURL = getRegistryClient()
                .getServiceURL(this.serviceID, Standards.UMS_USERS_01, am);
        URL getUserURL = new URL(usersURL.toExternalForm() + path);
        log.debug("getUser request to " + getUserURL.toString());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpDownload get = new HttpDownload(getUserURL, out);

        get.run();
        int responseCode = get.getResponseCode();

        if (responseCode == 200) {
            UserReader userReader = new UserReader();
            return userReader.read(out.toString());
        }

        String message = "";
        if (get.getThrowable() != null) {
            log.debug("error calling get user", get.getThrowable());
            message = get.getThrowable().getMessage();
        }

        if (responseCode == 400) {
            throw new IllegalArgumentException(message);
        }
        if (responseCode == 404) {
            throw new UserNotFoundException(message);
        }
        if (responseCode == 403) {
            throw new AccessControlException(message);
        }
        throw new IllegalStateException(message);
    }

    protected Principal getPrincipal(final Subject subject) {
        if (subject == null || subject.getPrincipals() == null || subject
                .getPrincipals().isEmpty()) {
            return null;
        }

        if (subject.getPrincipals().size() == 1) {
            return subject.getPrincipals().iterator().next();
        }

        // in the case that there is more than one principal in the
        // subject, favor OpenID principals, then x500 principals, then numeric principals,
        // then http principals.
        Set<OpenIdPrincipal> openIdPrincipals = subject
                .getPrincipals(OpenIdPrincipal.class);
        if (openIdPrincipals.size() > 0) {
            return openIdPrincipals.iterator().next();
        }

        Set<X500Principal> x500Principals = subject
                .getPrincipals(X500Principal.class);
        if (x500Principals.size() > 0) {
            return x500Principals.iterator().next();
        }

        Set<NumericPrincipal> numericPrincipals = subject
                .getPrincipals(NumericPrincipal.class);
        if (numericPrincipals.size() > 0) {
            return numericPrincipals.iterator().next();
        }

        Set<HttpPrincipal> httpPrincipals = subject
                .getPrincipals(HttpPrincipal.class);
        if (httpPrincipals.size() > 0) {
            return httpPrincipals.iterator().next();
        }

        // just return the first one
        return subject.getPrincipals().iterator().next();
    }

    protected Set<Principal> getPrincipals(ByteArrayOutputStream out) {
        try {
            String userXML = new String(out.toByteArray(), "UTF-8");
            log.debug("userXML Input to getPrincipals(): " + userXML);

            User user = new UserReader().read(userXML);

            // PROTO: include minimal posiz info in PosixPrincipal
            if (user.posixDetails != null) {
                for (PosixPrincipal pp : user.getIdentities(PosixPrincipal.class)) {
                    if (pp.getUidNumber() == user.posixDetails.getUid()) {
                        pp.defaultGroup = user.posixDetails.getGid();
                        pp.username = user.posixDetails.getUsername();
                    }
                }
            }
            return user.getIdentities();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected String getIdType(Principal principal) {
        String idTypeStr = AuthenticationUtil.getPrincipalType(principal);
        if (idTypeStr == null) {
            final String msg = "Subject has unsupported principal "
                    + principal.getClass();
            throw new IllegalArgumentException(msg);
        }

        return idTypeStr;
    }

    protected RegistryClient getRegistryClient() {
        return new RegistryClient();
    }

    /**
     * Used for tests to override.
     *
     * @param url          The URL to download from.
     * @param outputStream The OutputStream to write to.
     * @return HttpDownload instance used.
     * @throws IOException Any errors.
     */
    protected HttpDownload download(final URL url,
                                    final OutputStream outputStream)
            throws IOException {
        final HttpDownload get = new HttpDownload(url, outputStream);
        get.run();

        return get;
    }

    /**
     * Override for tests to write to a different output.
     *
     * @return OutputStream instance.
     */
    protected OutputStream getOutputStream() {
        return new ByteArrayOutputStream();
    }

    /**
     * Obtain the current User for the given Subject.
     *
     * <p>This requires that a Subject is in the current context.
     *
     * @return User instance.
     * @throws IOException           Any reader/writer errors.
     * @throws UserNotFoundException If there is no such user.
     */
    public User whoAmI() throws IOException, UserNotFoundException {
        AuthMethod am = getAuthMethod();
        final URL whoAmIURL = getRegistryClient()
                .getServiceURL(this.serviceID, Standards.UMS_WHOAMI_01, am);
        if (whoAmIURL == null) {
            throw new IllegalArgumentException("No service endpoint for uri "
                    + Standards.UMS_WHOAMI_01);
        }

        log.debug("getUser request to " + whoAmIURL.toString());

        OutputStream out = getOutputStream();
        final HttpDownload get = download(whoAmIURL, out);

        final int responseCode = get.getResponseCode();
        if (responseCode == 200) {
            final UserReader userReader = new UserReader();

            try {
                return userReader.read(out.toString());
            } catch (URISyntaxException | ReaderException e) {
                throw new IllegalStateException(e);
            }
        }

        String message = "";
        if (get.getThrowable() != null) {
            log.debug("error calling get user", get.getThrowable());
            message = get.getThrowable().getMessage();
        }

        if (responseCode == 400) {
            throw new IllegalArgumentException(message);
        }
        if (responseCode == 404) {
            throw new UserNotFoundException(message);
        }
        if (responseCode == 403) {
            throw new AccessControlException(message);
        }
        throw new IllegalStateException(message);
    }

    private AuthMethod getAuthMethod() throws AccessControlException {
        Subject subject = AuthenticationUtil.getCurrentSubject();
        AuthMethod am = AuthenticationUtil.getAuthMethodFromCredentials(subject);
        if (am == null || am.equals(AuthMethod.ANON)) {
            throw new AccessControlException("Anonymous access not supported.");
        }
        return am;
    }

}
