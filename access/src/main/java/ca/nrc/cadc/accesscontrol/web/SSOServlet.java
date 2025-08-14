/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2012.                         (c) 2012.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author jenkinsd
 * 4/19/12 - 9:27 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.accesscontrol.web;


import ca.nrc.cadc.auth.InvalidSignedTokenException;
import ca.nrc.cadc.auth.SignedToken;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.util.*;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.accesscontrol.AccessControlUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.date.DateUtil;
import ca.nrc.cadc.util.ArrayUtil;
import org.apache.log4j.Logger;

import ca.nrc.cadc.util.StringUtil;


public abstract class SSOServlet extends HttpServlet {
    private static final Logger LOGGER = Logger.getLogger(SSOServlet.class);
    private static final String URL_CHAR_ENCODING = "UTF-8";

    // Request parameters.
    static final String TARGET_PARAMETER_NAME = "target";
    static final String SCOPE_PARAMETER_NAME = "scope";
    static final String USERNAME_PARAMETER_NAME = "username";
    private static final String PASSWORD_PARAMETER_NAME = "password";

    // Indicates a logout action.
    static final String LOGOUT_PARAMETER_NAME = "logout";

    // Configured domain SSO Agents.
    private final Set<String> agentServers = new HashSet<>();

    // SSOCookieAgentImpl manager.
    final SSOCookieManager cookieManager;


    SSOServlet() {
        this(new SSOCookieManager());
    }

    SSOServlet(final SSOCookieManager cookieManager) {
        this.cookieManager = cookieManager;
    }


    @Override
    public final void init(final ServletConfig config) throws ServletException {
        final AccessControlUtil accessControlUtil = new AccessControlUtil();
        agentServers.addAll(accessControlUtil.getSSOServers());

        if (agentServers.isEmpty()) {
            
            throw new ServletException(
                "SSO Servers not found. Looked for $HOME/config/access.properties file" + 
                "If your deployment still uses 'AccessControl.properties', please rename it to 'access.properties'."
            );

        }

        LOGGER.info("SSO Servers: " + Arrays.toString(agentServers.toArray(new String[0])));

        doInit(config);
    }

    /**
     * Parse the given cookie value into a known Principal.
     *
     * @param cookieValue The cookie value to parse.
     * @return A valid principal.  Never null.
     * @throws InvalidSignedTokenException If the given cookie cannot
     *                                     be parsed (invalid).
     */
    SignedToken parseCookie(final String cookieValue) throws InvalidSignedTokenException {
        return cookieManager.parse(cookieValue);
    }

    /**
     * Obtain the currently authenticated principal.
     *
     * @param request The current request.
     * @return The Principal found, or null.
     * @throws InvalidSignedTokenException If the given cookie cannot
     *                                     be parsed (invalid).
     */
    Principal getCurrentPrincipal(final HttpServletRequest request) throws InvalidSignedTokenException {
        if (request.getCookies() != null) {
            for (final Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(SSOCookieManager.DEFAULT_SSO_COOKIE_NAME)) {
                    final SignedToken token = parseCookie(cookie.getValue());
                    final Principal p = token.getUser();

                    // A valid cookie was found.
                    if (p != null) {
                        return p;
                    }
                }
            }
        }

        return null;
    }


    /**
     * The Login form is submitted.
     *
     * @param request  The HTTP Request.
     * @param response The HTTP Response.
     * @throws ServletException If anything went wrong pertaining to this
     *                          servlet.
     * @throws IOException      If anything unexpected happened.
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        final Map<String, String> parameterMap = new HashMap<>();

        parameterMap.put(TARGET_PARAMETER_NAME, request.getParameter(TARGET_PARAMETER_NAME));
        parameterMap.put(SCOPE_PARAMETER_NAME, request.getParameter(SCOPE_PARAMETER_NAME));
        parameterMap.put(USERNAME_PARAMETER_NAME, request.getParameter(USERNAME_PARAMETER_NAME));
        parameterMap.put(PASSWORD_PARAMETER_NAME, request.getParameter(PASSWORD_PARAMETER_NAME));

        handleRequest(parameterMap, new LoginLogInfo(request), response.getWriter(), response);
    }

    /**
     * Handle an SSO request that will then send the user to the SSOCookieAgentImpl agents.
     *
     * @param parameters A mapping of parameters.
     * @param logInfo    The LogInfo instance.
     * @param writer     The writer for the URL output.
     * @param response   The HTTP Response.
     * @throws ServletException Any servlet errors
     * @throws IOException      Any other errors
     */
    void handleRequest(final Map<String, String> parameters, final LoginLogInfo logInfo, final Writer writer,
                       final HttpServletResponse response) throws ServletException, IOException {

        // The URL the client is trying to access, or where they previously
        // were when they clicked 'Login'.
        String targetURL = parameters.get(TARGET_PARAMETER_NAME);
        String scope = parameters.get(SCOPE_PARAMETER_NAME);
        String username = parameters.get(USERNAME_PARAMETER_NAME);
        String password = parameters.get(PASSWORD_PARAMETER_NAME);

        final char[] cookieValue = authorizeCookie(username, password);

        long start = System.currentTimeMillis();

        logInfo.setUser(username);
        logInfo.setTargetURL(targetURL);

        try {
            LOGGER.info(logInfo.start());

            if (!ArrayUtil.isEmpty(cookieValue)) {
                LOGGER.debug("authorized");
                if (StringUtil.hasText(scope)) {
                    //this is a scoped cookie
                    try {
                        final Calendar expiryDate = new GregorianCalendar(DateUtil.UTC);
                        expiryDate.add(Calendar.HOUR, 24);

                        SignedToken token = new SignedToken(new HttpPrincipal(username), new URI(scope),
                                                            expiryDate.getTime(), null);
                        response.setStatus(HttpServletResponse.SC_OK);
                        try {
                            writer.write(SignedToken.format(token));
                            return;
                        } catch (InvalidKeyException e) {
                            throw new RuntimeException("BUG: invalid key to sign scoped cookies");
                        }
                    } catch (URISyntaxException e) {
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        return;
                    }
                }

                final StringBuilder ssoURL = new StringBuilder();

                ssoURL.append("/access/sso");

                if (parameters.containsKey(LOGOUT_PARAMETER_NAME)) {
                    ssoURL.append("/logout");
                }

                ssoURL.append("?");
                ssoURL.append(AccessConstants.COOKIE_VALUE_REQUEST_PARAMETER_NAME);
                ssoURL.append("=");
                ssoURL.append(encodeURLParameter(String.valueOf(cookieValue)));

                // Successful authentication.
                if (StringUtil.hasText(targetURL)) {
                    ssoURL.append("&referer=").append(encodeURLParameter(targetURL));
                }

                if (!agentServers.isEmpty()) {
                    ssoURL.append("&sites=");

                    for (final String agentServer : agentServers) {
                        ssoURL.append(encodeURLParameter(agentServer));
                        ssoURL.append(",");
                    }

                    ssoURL.deleteCharAt(ssoURL.lastIndexOf(","));
                }

                logInfo.setSuccess(true);
                logInfo.setMessage("Current URL being passed on: " + ssoURL);
                response.setStatus(HttpServletResponse.SC_OK);
                LOGGER.info("redirect url to be sent back: " + ssoURL);
                writer.write(ssoURL.toString());
            } else {
                logInfo.setSuccess(false);
                logInfo.setMessage("not authorized");
                LOGGER.debug("not authorized");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                try {
                    writer.write("Your session has expired, or your username and "
                                 + "password cannot be found.  Please go Back and "
                                 + "try again.");
                } finally {
                    writer.flush();
                    writer.close();
                }
            }
        } finally {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            LOGGER.info(logInfo.end());
        }
    }

    /**
     * Authorize a cookie for the given username/password.  In the case of a
     * Login this will generate a cookie to allow Single Sign on, and in the
     * case of a Logout, it will issue an expired cookie.
     *
     * @param username The username from the web.
     * @param password The password submitted.
     * @return SSOCookieAgentImpl char array value.
     * @throws ServletException If anything went wrong pertaining to this
     *                          servlet.
     * @throws IOException      If anything unexpected happened.
     */
    protected abstract char[] authorizeCookie(final String username, final String password) throws ServletException, IOException;

    /**
     * Do the init work for the implementors.  This ensures the main init() gets
     * called appropriately.
     *
     * @param servletConfig The ServletConfig instance.
     * @throws ServletException If any Servlet issues arise.
     */
    protected abstract void doInit(final ServletConfig servletConfig) throws ServletException;

    /**
     * Load the HTML login page.
     *
     * @param response The HttpServletResponse instance.
     * @param writer   The Response's writer.
     * @param context  Context of the page: "canfar" for Canfar or
     *                 "en" or "fr" for CADC pages.
     * @throws IOException For IO errors (Any weirdness)
     */
    void loadLoginPage(final HttpServletResponse response, final Writer writer, final String context)
            throws IOException {
        URL loginPageURL;
        if (context.equals("fr")) {
            loginPageURL = new URL("http://localhost/fr/connexion.html");
        } else {
            loginPageURL =
                    new URL("http://localhost/" + context + "/login.html");
        }

        final HttpURLConnection urlConnection =
                (HttpURLConnection) loginPageURL.openConnection();

        urlConnection.setDoInput(true);

        response.setContentType("text/html");

        final char[] buffer = new char[1024];
        int bytesRead;

        try (final Reader reader = new InputStreamReader(
                urlConnection.getInputStream())) {
            while ((bytesRead = reader.read(buffer)) > 0) {
                writer.write(buffer, 0, bytesRead);
            }
        } finally {
            writer.flush();
            writer.close();
        }
    }

    String encodeURLParameter(final String param) throws IOException {
        return URLEncoder.encode(param, URL_CHAR_ENCODING);
    }
}
