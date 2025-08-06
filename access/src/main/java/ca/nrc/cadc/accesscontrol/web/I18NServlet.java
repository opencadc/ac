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
 * 4/12/12 - 2:04 PM
 *
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */
package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.util.StringUtil;
import org.json.JSONException;
import org.json.JSONWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.Enumeration;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Stack;


public class I18NServlet extends HttpServlet
{
    /**
     * Only GET is supported.
     *
     * @param request               The HTTP Request.
     * @param response              The HTTP Response.
     * @throws ServletException     For Servlet errors.
     * @throws IOException          All other Exceptions.
     */
    @Override
    protected void doGet(final HttpServletRequest request,
                         final HttpServletResponse response)
            throws ServletException, IOException
    {
        final String resourceName = getResourceName(request);
        final Locale locale = request.getLocale();
        final ResourceBundle localeBundle =
                ResourceBundle.getBundle(resourceName + "Resources", locale);
        final Writer writer = response.getWriter();

        try
        {
            writeJSON(writer, localeBundle);
        }
        catch (JSONException e)
        {
            throw new IOException("Unable to write JSON to client.", e);
        }
    }


    /**
     * Write out the JSON for this Resource Bundle to the client.
     * @param writer                    The Writer to write out to.
     * @param localeResourceBundle      The ResourceBundle for this locale.
     * @throws JSONException            For all JSON errors.
     * @throws IOException              Any other Exceptions.
     */
    protected void writeJSON(final Writer writer,
                             final ResourceBundle localeResourceBundle)
            throws JSONException, IOException
    {
        final JSONWriter jsonWriter = new JSONWriter(writer);

        jsonWriter.object();

        final String resourceBundleLocaleString =
                localeResourceBundle.getLocale().getLanguage();
        final String localeString =
                StringUtil.hasText(resourceBundleLocaleString)
                ? resourceBundleLocaleString
                : Locale.getDefault().getLanguage();

        jsonWriter.key("locale").value(localeString.toUpperCase());

        for (final Enumeration<String> enumeration =
                     localeResourceBundle.getKeys();
             enumeration.hasMoreElements();)
        {
            final String nextKey = enumeration.nextElement();
            final String nextValue = localeResourceBundle.getString(nextKey);

            jsonWriter.key(nextKey).value(nextValue);
        }

        jsonWriter.endObject();
    }

    /**
     * Obtain the resource being asked for.
     *
     * @param request       The HTTP Request whose path to check.
     * @return              String for this resource.
     */
    protected String getResourceName(final HttpServletRequest request)
    {
        final String path = request.getPathInfo();
        final Stack<String> stack = new Stack<>();

        for (final String pathItem : path.split("/"))
        {
            if (StringUtil.hasText(pathItem))
            {
                stack.push(pathItem);
            }
        }

        return stack.pop();
    }
}
