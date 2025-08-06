/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2013.                         (c) 2013.
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
 * 3/14/13 - 10:41 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */


package ca.nrc.cadc.accesscontrol.web;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Used to define a contract for SSO SSOCookieAgentImpl Agents.
 */
public interface SSOCookieAgent
{
    /**
     * Issue the caller a new cookie.
     *
     * @param sessionIDToken        The Token as provided by the SSO Login
     *                              Access Control.
     * @param request               The HTTP Request.
     * @param response              The HTTP Response.
     * @throws javax.servlet.ServletException     For any Servlet errors.
     * @throws java.io.IOException          For all other errors.
     */
    void issueCookie(final String sessionIDToken,
                     final HttpServletRequest request,
                     final HttpServletResponse response)
            throws ServletException, IOException;

    /**
     * Validate that the given token exists and is currently active for a
     * session.
     *
     * @param cookieValue The Token to validate.
     */
    boolean validateToken(final String cookieValue) throws IOException;
}
