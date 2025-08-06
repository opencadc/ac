/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2019.                         (c) 2019.
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
 * 4/20/12 - 2:31 PM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */


package ca.nrc.cadc.accesscontrol.web;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.accesscontrol.AccessControlUtil;
import ca.nrc.cadc.auth.InvalidSignedTokenException;
import org.apache.log4j.Logger;

import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.util.StringUtil;


/**
 * Handling of cookies directly from the web.  This will make use of the
 * base SSOCookieManager to parse out the string value when needed.
 */
public class SSOCookieAgentImpl extends SSOServlet implements SSOCookieAgent, AccessConstants {
    private static final Logger LOGGER = Logger.getLogger(SSOCookieAgentImpl.class);

    private static final Collection<String> AGENT_SERVERS = new ArrayList<>();

    // Google Chrome requires that Secure be set if SameSite is set to None.  This Cookie depends on the site being
    // access over https.
    // jenkinsd 2021.10.20
    private static final String SET_COOKIE_TEMPLATE =
            "%s=\"%s\"; Secure; SameSite=None; HttpOnly; Domain=%s; Max-Age=%d; Path=%s";

    private String SSOURI;
    private final CreateURL createURL = new CreateURL();

    /**
     * Empty constructor.  Needs to be public as it's a servlet.
     */
    public SSOCookieAgentImpl() {
    }

    /**
     * Useful for testing.
     *
     * @param cookieManager A testable cookie manager
     * @param agentServers  Agent servers to use.
     * @param SSOURI        The URI for the SSO agents.
     */
    SSOCookieAgentImpl(final SSOCookieManager cookieManager, final Collection<String> agentServers,
                       final String SSOURI) {
        super(cookieManager);

        AGENT_SERVERS.clear();
        AGENT_SERVERS.addAll(agentServers);

        this.SSOURI = SSOURI;
    }


    /**
     * Do the init work for the implementors.  This ensures the main init() gets
     * called appropriately.
     *
     * @param servletConfig The ServletConfig instance.
     * @throws javax.servlet.ServletException If any Servlet issues arise.
     */
    @Override
    protected void doInit(final ServletConfig servletConfig) throws ServletException {
        final AccessControlUtil accessControlUtil = new AccessControlUtil();

        AGENT_SERVERS.clear();
        AGENT_SERVERS.addAll(accessControlUtil.getSSOServers());

        if (AGENT_SERVERS.isEmpty()) {
            throw new ServletException("No SSO servers found.  Please ensure "
                                       + "the ${HOME}/config/AccessControl."
                                       + "properties file exists and the "
                                       + "SSO_SERVERS property is set.");
        }

        SSOURI = servletConfig.getInitParameter("SSOURI");
    }


    /**
     * The Login form is submitted.
     *
     * @param request  The HTTP Request.
     * @param response The HTTP Response.
     * @throws IOException If anything unexpected happened.
     */
    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        String targetURL = request.getParameter("targetURL");
        final String cookieValue = request.getParameter(COOKIE_VALUE_REQUEST_PARAMETER_NAME);

        targetURL = createURL.getTargetUrl(targetURL, request);
        final StringBuilder ssoURL = new StringBuilder(createURL.createToken(SSOURI, cookieValue, targetURL, AGENT_SERVERS));
        LOGGER.info("Starting URL : " + ssoURL);

        response.getWriter().write(ssoURL.toString());
        response.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * Check if this is a logout request.
     *
     * @param request The HTTP Servlet Request instance.
     * @return True if logout request, False otherwise.
     */
    boolean isLogout(final HttpServletRequest request) {
        return request.getRequestURI().contains("/logout");
    }

    /**
     * Do a check of a user's token (Session ID), check it for validity, and
     * issue a cookie.
     *
     * @param request  The HTTP Servlet Request.
     * @param response The HTTP Servlet Response.
     * @throws IOException For any other errors.
     */
    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        LOGGER.debug("start doGet");
        final boolean isLogout = isLogout(request);
        final String cookieValue = request.getParameter(COOKIE_VALUE_REQUEST_PARAMETER_NAME);
        final String referer = request.getParameter("referer");
        final String sites = request.getParameter("sites");
        final StringBuilder redirect = new StringBuilder((createURL.createRedirectUrl(SSOURI, cookieValue, referer,
                                                                                      sites, isLogout)));
        LOGGER.debug("cookieValue=" + cookieValue);
        LOGGER.debug("referer=" + referer);
        LOGGER.info("sites=" + sites);

        if ((StringUtil.hasText(cookieValue) && validateToken(cookieValue)) || isLogout) {
            issueCookie(cookieValue, request, response);

            LOGGER.info("Redirecting to: " + redirect);
            response.setStatus(HttpServletResponse.SC_SEE_OTHER);
            response.setHeader("Location", redirect.toString());
        } else {
            LOGGER.info("Unauthorized for " + redirect);
            returnUnauthorized(response);
        }
    }

    /**
     * Return to the client as unauthorized.
     *
     * @param response The HTTP Response.
     * @throws IOException For anything that goes wrong.
     */
    private void returnUnauthorized(final HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired session.");
    }

    int getCookieLifetimeSeconds() {
        return new AccessControlUtil().getCookieLifetimeSeconds();
    }

    /**
     * Issue the caller a new cookie.
     *
     * @param sessionIDToken The Token as provided by the SSO Login
     *                       Access Control.
     * @param request        The HTTP Request.
     * @param response       The HTTP Response.
     * @throws java.io.IOException For all other errors.
     */
    @Override
    public void issueCookie(final String sessionIDToken, final HttpServletRequest request,
                            final HttpServletResponse response) throws IOException {
        final String setCookieHeaderName = "set-cookie";

        final String setCookieValue =
                String.format(SET_COOKIE_TEMPLATE,
                              SSOCookieManager.DEFAULT_SSO_COOKIE_NAME,
                              String.valueOf(sessionIDToken.toCharArray()),
                              NetUtil.getDomainName(request.getServerName()),
                              isLogout(request) ? 0 : getCookieLifetimeSeconds(), "/");

        // Check if set-cookie exists already.
        if (response.getHeaderNames().stream().anyMatch(headerName -> headerName.equalsIgnoreCase(
                setCookieHeaderName))) {
            response.addHeader(setCookieHeaderName, setCookieValue);
        } else {
            response.setHeader(setCookieHeaderName, setCookieValue);
        }
    }

    /**
     * Authorize a cookie for the given username/password.  In the case of a
     * Login this will generate a cookie to allow Single Sign on, and in the
     * case of a Logout, it will issue an expired cookie.
     *
     * @param username The username from the web.
     * @param password The password submitted.
     * @return Cookie char array value.
     */
    @Override
    protected char[] authorizeCookie(final String username, final String password) {
        // Do nothing as it does not apply.
        return null;
    }

    /**
     * Validate that the given token exists and is currently active for a
     * session.
     *
     * @param cookieValue The Token to validate.
     */
    @Override
    public boolean validateToken(final String cookieValue) throws IOException {
        try {
            return (parseCookie(cookieValue) != null);
        } catch (InvalidSignedTokenException e) {
            return false;
        }
    }
}
