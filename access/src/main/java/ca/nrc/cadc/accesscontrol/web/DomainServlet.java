/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2019.                         (c) 2019.
 * Government of Canada                 Gouvernement du Canada
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
 * @author dhawann
 * 08/01/19 - 10:07 AM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */


package ca.nrc.cadc.accesscontrol.web;

import java.io.IOException;
import java.util.*;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.accesscontrol.AccessControlUtil;
import org.apache.log4j.Logger;

import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.util.StringUtil;



public class DomainServlet extends HttpServlet implements AccessConstants {

    private static final Logger LOGGER = Logger.getLogger(DomainServlet.class);

    private Collection<String> agent_Servers = new  ArrayList<String>();

    private CreateURL createURL = new CreateURL();

    private String URI;

    public DomainServlet() {

    }

    /*
    *
    *  Used for testing only
    *
    */
    public DomainServlet(Collection<String> AgentServers, String URI){
        agent_Servers.clear();
        agent_Servers.addAll(AgentServers);
        this.URI = URI;
    }

    @Override
    public final void init(final ServletConfig config)  throws ServletException {

        agent_Servers.clear();

        final AccessControlUtil accessControlUtil = new AccessControlUtil();

        agent_Servers.addAll(accessControlUtil.getCookieDomains());

        LOGGER.info("Cookie Domains : " + accessControlUtil.getCookieDomains());

        if (agent_Servers.isEmpty()) {
            throw new ServletException("No Cookie domains found.  Please ensure "
                + "the ${HOME}/config/AccessControl."
                + "properties file exists and the "
                + "COOKIE_DOMAINS property is set.");
        }

        URI = config.getInitParameter("ConsentURI");
    }

    /**
     *
     * Creates the Initial token URL.
     *
     */
    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        final String cookieValue = request.getParameter(COOKIE_VALUE_REQUEST_PARAMETER_NAME);
        final String referer= request.getParameter("referer");
        final String sites= request.getParameter("sites");

        StringBuilder redirect = new StringBuilder(createURL.createRedirectUrl(URI,cookieValue,referer,sites, false));
        if(StringUtil.hasText(cookieValue)) {
            addCookie(cookieValue, response, NetUtil.getDomainName(request.getServerName()));
            response.setStatus(HttpServletResponse.SC_SEE_OTHER);
            response.setHeader("Location", redirect.toString());
        }
    }


    /**
     *
     * Creates the Redirect URL which domain hops on each of the agent servers.
     *
     */
    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        final String cookieValue = request.getParameter(COOKIE_VALUE_REQUEST_PARAMETER_NAME);
         String targetURL = request.getParameter("targetURL");

         targetURL  = createURL.getTargetUrl(targetURL,request);

        StringBuilder consentURL = new StringBuilder(createURL.createToken(URI, cookieValue,targetURL,agent_Servers));

        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(consentURL.toString());

    }

    private void addCookie(String cookieValue, HttpServletResponse response, String domainName) {

        Cookie cookie = new Cookie(CONSENT_COOKIE_REQUEST_PARAMETER_NAME, cookieValue);
        cookie.setMaxAge(60 * 60 * 24 * 365 * 68);      // 68 years.
        cookie.setDomain(domainName);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

}
