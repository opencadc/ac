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

import ca.nrc.cadc.accesscontrol.AbstractAccessControlWebTest;

import org.junit.Test;
import static org.junit.Assert.*;
import static org.easymock.EasyMock.*;

import javax.servlet.http.HttpServletRequest;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ListResourceBundle;
import java.util.Locale;
import java.util.ResourceBundle;


public class I18NServletTest extends AbstractAccessControlWebTest<I18NServlet>
{
    private HttpServletRequest mockRequest =
            createMock(HttpServletRequest.class);


    @Test
    public void writeJSON() throws Exception
    {
        setTestSubject(new I18NServlet());
        final Writer writer = new StringWriter();
        final ResourceBundle resourceBundle = new ListResourceBundle()
        {
            @Override
            protected Object[][] getContents()
            {
                return new Object[][]
                        {
                                {"LABEL1", "BON"},
                                {"LABEL2", "MAUVAIS"},
                                {"LABEL3", "PETIT"},
                                {"LABEL4", "GRAND"}
                        };
            }

            /**
             * Returns the locale of this resource bundle. This method can be used after a
             * call to getBundle() to determine whether the resource bundle returned really
             * corresponds to the requested locale or is a fallback.
             *
             * @return the locale of this resource bundle
             */
            @Override
            public Locale getLocale()
            {
                return Locale.FRENCH;
            }
        };

        getTestSubject().writeJSON(writer, resourceBundle);

        final String jsonOutput = writer.toString();
        assertEquals("JSON String should match.",
                     "{\"locale\":\"FR\",\"LABEL4\":\"GRAND\",\"LABEL3\":\"PETIT\",\"LABEL2\":\"MAUVAIS\",\"LABEL1\":\"BON\"}",
                     jsonOutput);
    }

    @Test
    public void getResourceName() throws Exception
    {
        setTestSubject(new I18NServlet());
        expect(getMockRequest().getPathInfo()).andReturn("/a/b/c/").once();

        replay(getMockRequest());

        final String resourceName1 = getTestSubject().getResourceName(
                getMockRequest());

        assertEquals("Should be c", "c", resourceName1);

        verify(getMockRequest());


        //
        // TEST 2

        reset(getMockRequest());
        expect(getMockRequest().getPathInfo()).andReturn("/a/b/c/d").once();

        replay(getMockRequest());

        final String resourceName2 = getTestSubject().getResourceName(
                getMockRequest());

        assertEquals("Should be d", "d", resourceName2);

        verify(getMockRequest());
    }


    public HttpServletRequest getMockRequest()
    {
        return mockRequest;
    }
}
