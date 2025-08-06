/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2015.                            (c) 2015.
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
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.log.ServletLogInfo;
import javax.servlet.http.HttpServletRequest;

/**
 * An extension of ServletLogInfo for the access web service.
 *
 */
public class LoginLogInfo extends ServletLogInfo
{
    public String target;


    /**
     * Servlet request constructor that automatically
     * determines the path.
     *
     * @param request       The HTTP Request.
     */
    public LoginLogInfo(final HttpServletRequest request)
    {
        super(request);
    }


    public void setUser(String username)
    {
        user = username;
    }

    public void setTargetURL(final String targetURL)
    {
        this.target = targetURL;
    }
}
