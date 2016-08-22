package ca.nrc.cadc.ac.server.web;


import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;


public class UserRequestServletTest
{
    @Test
    public void getAcceptedContentTypeJSON() throws Exception
    {
        final HttpServletRequest mockRequest =
                createMock(HttpServletRequest.class);
        final UserRequestServlet testSubject = new UserRequestServlet();

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
        final UserRequestServlet testSubject = new UserRequestServlet();

        expect(mockRequest.getHeader("Accept")).andReturn(null).once();

        replay(mockRequest);

        assertEquals("Wrong content type.", "text/xml",
                     testSubject.getAcceptedContentType(mockRequest));

        verify(mockRequest);
    }
}
