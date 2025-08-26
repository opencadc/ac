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
 * 4/19/12 - 9:26 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.auth.InvalidSignedTokenException;
import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.util.StringUtil;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;


public class SSOLogoutServlet extends SSOServlet {
    static final String LOGOUT_PREFIX_VALUE = "LOGOUT-";

    public SSOLogoutServlet() {
        super();
    }

    public SSOLogoutServlet(final SSOCookieManager cookieManager) {
        super(cookieManager);
    }


    /**
     * Do the init work for the implementors.  This ensures the main init() gets
     * called appropriately.
     *
     * @param servletConfig The ServletConfig instance.
     */
    @Override
    protected void doInit(final ServletConfig servletConfig) {
        // Do nothing.
    }

    /**
     * A logout is requested.
     *
     * @param request  The HTTP Request.
     * @param response The HTTP Response.
     * @throws ServletException If anything went wrong pertaining to this
     *                          servlet.
     * @throws IOException      If anything unexpected happened.
     */
    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            final Principal currentPrincipal = getCurrentPrincipal(request);
            final Map<String, String> parameterMap = new HashMap<>();

            final String requestedTarget = request.getParameter(TARGET_PARAMETER_NAME);
            final String refererFromRequest = request.getHeader("referer");

            parameterMap.put(TARGET_PARAMETER_NAME, StringUtil.hasText(requestedTarget)
                                                    ? requestedTarget : refererFromRequest);
            parameterMap.put(SCOPE_PARAMETER_NAME, request.getParameter(SCOPE_PARAMETER_NAME));

            if (currentPrincipal != null) {
                parameterMap.put(USERNAME_PARAMETER_NAME, currentPrincipal.getName());
            }

            parameterMap.put(LOGOUT_PARAMETER_NAME, "true");

            final Writer writer = new StringWriter();
            handleRequest(parameterMap, new LoginLogInfo(request), writer, response);

            response.sendRedirect(writer.toString());
        } catch (InvalidSignedTokenException e) {
            // Unauthorized or empty cookie.
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
        cookieManager.setOffsetExpiryHours(-1);
        return getLogoutCookieValue();
    }

    char[] getLogoutCookieValue() {
        return (LOGOUT_PREFIX_VALUE + System.currentTimeMillis()).toCharArray();
    }
}
