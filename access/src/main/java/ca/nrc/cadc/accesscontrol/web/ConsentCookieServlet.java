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
import java.io.PrintWriter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;


public class ConsentCookieServlet extends HttpServlet implements AccessConstants {

    public ConsentCookieServlet() {
    }


    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        PrintWriter out = response.getWriter();
        String cookieName = CONSENT_COOKIE_REQUEST_PARAMETER_NAME;
        Cookie[] cookies = null;

        cookies = request.getCookies();

        if(cookies!=null && containsCookie(cookies,cookieName)) {
            out.write("exists");
        }
        else {
            out.write("does not exist");
        }

        out.close();

    }

    private boolean containsCookie(Cookie[] cookies, String cookieName) {

        for(int i=0;i<cookies.length;i++) {
            String getCookieFromArray = cookies[i].getName() ;
            if(getCookieFromArray.equals(cookieName)){
                return true;
            }
        }
        return false;
    }


}
