package ca.nrc.cadc.ac.server.web;


import javax.servlet.http.HttpServletRequest;

import ca.nrc.cadc.ac.server.web.UserServlet;
import org.junit.Test;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;


public class UserServletTest
{
    @Test
    public void getAcceptedContentTypeJSON() throws Exception
    {
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final UserServlet testSubject = new UserServlet();

        expect(mockRequest.getHeader("Accept")).
                andReturn("application/json").once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "application/json",
                     testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }

    @Test
    public void getAcceptedContentTypeDefault() throws Exception
    {
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final UserServlet testSubject = new UserServlet();

        expect(mockRequest.getHeader("Accept")).andReturn(null).once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "text/xml",
                     testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }
}
