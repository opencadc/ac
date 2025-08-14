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
 * 3/26/12 - 2:49 PM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */
package ca.nrc.cadc.accesscontrol.web;


import java.io.*;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.*;
import org.apache.log4j.Logger;

import ca.nrc.cadc.util.ArrayUtil;
import ca.nrc.cadc.util.StringUtil;



/**
 * Servlet to handle authentication of a CADC user.
 */
public class SSOLoginServlet extends SSOServlet
{
    private static final Logger LOGGER = Logger
            .getLogger(SSOLoginServlet.class);

    // New canonical name per containerized convention
    public static final String AC_PROPERTIES_FILE = "access.properties"; 

    private LoginAuthenticator loginAuthenticator;


    /**
     * Empty, default constructor.
     */
    public SSOLoginServlet()
    {
        super();
    }

    /**
     * Testable constructor.
     *
     * @param loginAuthenticator        Testable loginauthenticator instance.
     * @param cookieManager             Testable cookie manager.
     */
    public SSOLoginServlet(final LoginAuthenticator loginAuthenticator,
                           final SSOCookieManager cookieManager)
    {
        super(cookieManager);
        this.loginAuthenticator = loginAuthenticator;
    }


    /**
     * Read in the configured domains.
     *
     * @param servletConfig The ServletConfig instance.
     */
    @Override
    public void doInit(final ServletConfig servletConfig)
    {
        loginAuthenticator = new LoginAuthenticator();
    }

    /**
     * Serve up the Login page.
     *
     * @param request  The HTTP Request.
     * @param response The HTTP Response
     * @throws ServletException Any error pertaining to this Servlet.
     * @throws IOException      All other errors.
     */
    @Override
    protected void doGet(final HttpServletRequest request,
                         final HttpServletResponse response)
            throws ServletException, IOException
    {
        Subject subject = AuthenticationUtil.getSubject(request);
        LOGGER.debug(subject);

        try
        {
            Subject.doAs(subject, (PrivilegedExceptionAction<Object>) () -> {
                final Writer writer = response.getWriter();
                final String path = request.getPathInfo();

                LOGGER.debug("doGet on path: " + path);

                if (isUserLoggedIn())
                {
                    final String targetURL = request
                            .getParameter("target");
                    response.sendRedirect(!StringUtil.hasText(targetURL)
                                          ? "/en" : targetURL);
                }
                else
                {
                    if (request.getRequestURL().toString()
                            .contains("canfar"))
                    {
                        loadLoginPage(response, writer, "canfar");
                    }
                    else
                    {
                        // CADC site - determine the language
                        String language = request
                                .getHeader("Content-Language");
                        if (language == null)
                        {
                            // default
                            language = "en";
                        }
                        loadLoginPage(response, writer, language);
                    }
                }

                return null;
            });
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Check whether the currently requested User is authenticated.
     *
     * @return True if logged in, false otherwise.
     */
    protected boolean isUserLoggedIn()
    {
        AccessControlContext context = AccessController.getContext();
        Subject subject = Subject.getSubject(context);

        return !((subject == null) || (subject.getPrincipals() == null)
                 || subject.getPrincipals().isEmpty());
    }

    /**
     * Authenticate the user to proceed.  If the user is authenticated, then
     * pass the generated token to the next domain's cookie agent to issue
     * a cookie.
     *
     * @param username The username.
     * @param password The password entered.
     * @return Cookie value to pass to the agents.
     * @throws IOException      If anything unexpected happened.
     */
    @Override
    public char[] authorizeCookie(final String username, final String password)
            throws IOException
    {
        LOGGER.debug("username: " + username);
        char[] passwordChar = null;

        if (password != null)
        {
            passwordChar = password.toCharArray();
        }

        if (StringUtil.hasText(username) && !ArrayUtil.isEmpty(passwordChar))
        {
        	String token = authenticate(username, password);
        	if (StringUtil.hasText(token))
        	{
        		return token.toCharArray();
        	}
        	else
        	{
        		return null;
        	}
        }
        else
        {
        	throw new IllegalArgumentException("Missing either username or password");
        }
    }

    /**
     * Perform a username/password check for the given user.
     *
     * @param username The username.
     * @param password The submitted password.
     * @return True if they exist, False otherwise.
     */
    protected String authenticate(final String username, final String password)
            throws IOException
    {
        return loginAuthenticator.authenticate(username, password);
    }
}
