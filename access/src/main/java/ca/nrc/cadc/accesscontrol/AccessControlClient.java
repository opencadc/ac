package ca.nrc.cadc.accesscontrol;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;

import org.apache.log4j.Logger;


/**
 * Client to access a registered AC Web Service.
 */
public class AccessControlClient {
    private static final String CADC_TOKEN_HEADER_KEY = "X-CADC-DelegationToken";
    private static final String CADC_PASSWORD_FIELD = "password";
    private final RegistryClient registryClient;
    private final URI groupManagementServiceURI;
    private static final Logger log = Logger.getLogger(AccessControlClient.class);

    public AccessControlClient(final URI serviceURI) throws IllegalArgumentException {
        this(serviceURI, new RegistryClient());
    }

    AccessControlClient(URI serviceURI, RegistryClient registryClient) {
        this.registryClient = registryClient;
        this.groupManagementServiceURI = serviceURI;
    }


    /**
     * Obtain the Login URL.
     *
     * @return URL for login
     */
    private URL lookupLoginURL() {
        return this.registryClient.getServiceURL(this.groupManagementServiceURI, Standards.UMS_LOGIN_01,
                                                 AuthMethod.ANON);
    }

    public String login(final String username, char[] password) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Map<String, Object> payload = new HashMap<>();

        payload.put("username", username);
        payload.put("password", new String(password));

        final int statusCode = post(lookupLoginURL(), payload, out);
        switch (statusCode) {
            case 200: {
                return out.toString();
            }

            case 400: {
                throw new IllegalArgumentException(out.toString());
            }

            case 401: {
                throw new NotAuthenticatedException("Login denied");
            }

            default: {
                throw new IllegalArgumentException(String.format("Unable to login '%s'.\nServer error code: %d.",
                                                                 username, statusCode));
            }
        }
    }

    private URL lookupPasswordResetURL() {
        return this.registryClient.getServiceURL(this.groupManagementServiceURI, Standards.UMS_RESETPASS_01,
                                                 AuthMethod.TOKEN);
    }

    /**
     * Reset the password for the currently authenticated user.
     *
     * @param newPassword   The new password value.
     * @param token         The secure pre-authorized token.
     */
    public void resetPassword(final char[] newPassword, final char[] token) {
        final Map<String, Object> payload = new HashMap<>();
        payload.put(CADC_PASSWORD_FIELD, new String(newPassword));

        final Map<String, String> headers = new HashMap<>();
        headers.put(CADC_TOKEN_HEADER_KEY, new String(token));

        Subject subject = AuthenticationUtil.getAnonSubject();

        try {

            Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
                final HttpPost thePost = postNoRedirect(lookupPasswordResetURL(), payload, headers);
                int statusCode = thePost.getResponseCode();
                StringBuilder logStr = new StringBuilder();
                logStr.append("Unable to reset password");
                StringBuilder throwStr = new StringBuilder();
                throwStr.append("Unable to reset password");

                // Gets added after specific message
                StringBuilder reasonPart = new StringBuilder();
                if (statusCode != 200) {
                    reasonPart.append(" - ");
                    reasonPart.append(thePost.getResponseCode());
                    reasonPart.append(": ");
                    reasonPart.append(thePost.getThrowable().toString());
                }
                String msg = "";

                switch (statusCode) {
                    case 200: {
                        break;
                    }
                    case 400: {
                        throwStr.append(": ");
                        throwStr.append(thePost.getThrowable().getMessage());
                        logStr.append(msg);
                        logStr.append(reasonPart);
                        log.error(logStr.toString());
                        throw new IllegalArgumentException(throwStr.toString());
                    }
                    case 403:
                    case 401: {
                        msg = ": Login denied";
                        throwStr.append(msg);
                        logStr.append(msg);
                        logStr.append(reasonPart);
                        log.error(logStr.toString());
                        throw new NotAuthenticatedException(throwStr.toString());
                    }
                    case 404: {
                        msg = ": Service unavailable";
                        throwStr.append(msg);
                        logStr.append(msg);
                        logStr.append(reasonPart);
                        log.error(logStr.toString());
                        throw new ResourceNotFoundException(throwStr.toString());
                    }
                    case -1: {
                        throwStr.append(": Bad request");
                        logStr.append(": Call not completed");
                        logStr.append(reasonPart);
                        log.error(logStr.toString());
                        throw new IllegalStateException(throwStr.toString());
                    }
                    case 500: {
                        msg = ": Server error";
                        throwStr.append(msg);
                        logStr.append(msg);
                        logStr.append(reasonPart);
                        log.error(logStr.toString());
                        throw new IllegalStateException(throwStr.toString());
                    }
                    default: {
                        msg = ": Unknown error";
                        throwStr.append(msg);
                        logStr.append(msg);
                        logStr.append(reasonPart);
                        log.error(logStr.toString());
                        throw new IllegalStateException(throwStr.toString());
                    }
                }

                return null;
            });
        } catch (PrivilegedActionException pea) {
            final Exception cause = pea.getException();

            // This is to make sure the right errors are propagated out
            if (cause == null) {
                log.error("Bug: Unknown error.", cause);
            } else if (cause instanceof SecurityException) {
                throw ((SecurityException) cause);
            } else if (cause instanceof IllegalArgumentException) {
                throw ((IllegalArgumentException) cause);
            } else {
                throw new RuntimeException(cause);
            }
        }

    }

    /**
     * Submit login data to the service.
     *
     * @param url     The URL endpoint.
     * @param payload The payload information.
     * @param out     The response stream.
     * @return Response status code.
     */
    int post(final URL url, final Map<String, Object> payload, final OutputStream out) {
        log.debug("Logging into " + url);
        final Map<String, String> headers = Collections.emptyMap();
        return post(url, payload, headers, out);
    }

    /**
     * Submit login data to the service with extra headers
     *
     * @param url     The URL endpoint.
     * @param payload The payload information.
     * @param headers Extra headers set to the request.
     * @param out     The response stream.
     * @return Response status code.
     */
    int post(final URL url, final Map<String, Object> payload, final Map<String, String> headers,
             final OutputStream out) {
        final HttpPost post = new HttpPost(url, payload, out);
        for (final Map.Entry<String, String> entry : headers.entrySet()) {
            post.setRequestProperty(entry.getKey(), entry.getValue());
        }

        post.run();
        if (post.getThrowable() != null) {
            post.getThrowable().printStackTrace();
        }
        return post.getResponseCode();
    }

    /**
     * POST to the provided URL, do not follow redirects
     *
     * @param url       The URL to rePOST to.
     * @param payload   The payload of the request.
     * @param headers   Any headers to be set.
     * @return          The HttpPost object AFTER the POST is executed.  Never null.
     */
    HttpPost postNoRedirect(final URL url, final Map<String, Object> payload, final Map<String, String> headers) {
        final HttpPost post = new HttpPost(url, payload, false);
        for (final Map.Entry<String, String> entry : headers.entrySet()) {
            post.setRequestProperty(entry.getKey(), entry.getValue());
        }

        post.run();
        return post;
    }

    public String getCurrentHttpPrincipalUsername(Subject subject) {
        final AuthMethod authMethod = AuthenticationUtil.getAuthMethod(subject);
        String username;

        if ((authMethod != null) && (authMethod != AuthMethod.ANON)) {
            final Set<HttpPrincipal> curPrincipals = subject.getPrincipals(HttpPrincipal.class);
            final HttpPrincipal[] principalArray = new HttpPrincipal[curPrincipals.size()];
            username = ((HttpPrincipal[]) curPrincipals.toArray(principalArray))[0].getName();
        } else {
            username = null;
        }

        return username;
    }
}
