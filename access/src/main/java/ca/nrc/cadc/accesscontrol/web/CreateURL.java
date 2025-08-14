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

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URL;
import java.util.Collection;


import org.apache.log4j.Logger;

import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.util.StringUtil;


public class CreateURL implements AccessConstants {

    private static final Logger LOGGER =Logger.getLogger(CreateURL.class);

    /**
     * Creates the redirecting url.
     */
    public  String createRedirectUrl(String endpoint, String cookieValue, String referer, String sites, boolean isLogout) throws IOException{

        StringBuilder redirect = new StringBuilder();

        if (StringUtil.hasText(sites)) {
            final StringBuilder newSites = new StringBuilder();
            final String[] domains = sites.split(",", 2);
            redirect.append("https://");
            redirect.append(domains[0].trim());

            LOGGER.info("Stripped off " + domains[0].trim() + "\n");

            if (domains.length > 1) {
                LOGGER.info(" and am left with " + domains[1].trim() + "\n");
                newSites.append("&sites=");
                newSites.append(encodeURLParameter(domains[1].trim()));
            }


            if (StringUtil.hasText(referer)) {
                newSites.append("&referer=");
                newSites.append(encodeURLParameter(referer));
            }
            redirect.append(endpoint);

            if (isLogout) {
                redirect.append("/logout");
            }

            redirect.append("?");
            redirect.append(COOKIE_VALUE_REQUEST_PARAMETER_NAME);
            redirect.append("=");
            redirect.append(encodeURLParameter(cookieValue));
            redirect.append(newSites.toString());
        } else if (StringUtil.hasText(referer)) {
            redirect.append(decodeURLParameter(referer).trim());
        } else {
            redirect.append("/");
        }
        return redirect.toString();

    }

    /*
     * Creates the token url.
     *
     */
    public String createToken(String endpoint, String cookieValue, String targetURL, Collection<String> agentServers) throws IOException {

        StringBuilder pathURL = new StringBuilder(endpoint);
        pathURL.append("?");
        pathURL.append(COOKIE_VALUE_REQUEST_PARAMETER_NAME);
        pathURL.append("=");
        pathURL.append(encodeURLParameter(cookieValue));
        pathURL.append("&referer=");
        pathURL.append(encodeURLParameter(targetURL));

        pathURL.append("&sites=");

        if(!agentServers.isEmpty()){

            for (final String agentServer : agentServers){

                pathURL.append(encodeURLParameter(agentServer));
                pathURL.append(",");
            }

            pathURL.deleteCharAt(pathURL.lastIndexOf(","));
        }


        return pathURL.toString();

    }

    String encodeURLParameter(final String param) throws IOException {
        return NetUtil.encode(param);
    }

    String decodeURLParameter(final String encodedParam) throws IOException {
        return NetUtil.decode(encodedParam);
    }

    public String getTargetUrl(String targetUrl, HttpServletRequest request) throws IOException{

        if (!StringUtil.hasText(targetUrl)) {

            final int requestServerPort = request.getServerPort();
            final int port = ((request.getScheme().equals("http") && (requestServerPort == 80))
                || (request.getScheme().equals("https") && (requestServerPort == 443)))
                ? -1 : requestServerPort;

            final URL serverURL = new URL(request.getScheme(), request.getServerName(), port, "/");

            targetUrl = serverURL.toExternalForm();
        }
        return targetUrl;
    }

}
