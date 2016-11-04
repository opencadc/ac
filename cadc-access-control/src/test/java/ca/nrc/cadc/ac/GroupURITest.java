package ca.nrc.cadc.ac;

import java.net.URISyntaxException;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.util.Log4jInit;

public class GroupURITest
{
    private static Logger log = Logger.getLogger(GroupURITest.class);

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @Test
    public void testMalformed()
    {
        try
        {
            // wrong scheme
            assertIllegalArgument("iko://cadc.nrc.ca/gms?gname", "scheme");

            // fragment instead of query
            assertIllegalArgument("ivo://cadc.nrc.ca/gms#gname", "fragment");

            // no authority
            assertIllegalArgument("ivo://gms?gname", "authority");

            // extended path in group
            assertIllegalArgument("ivo://cadc.nrc.ca/gms/path?gname", "path");
        }
        catch (Throwable t)
        {
            log.error("Test Failed", t);
            Assert.fail();
        }
    }

    @Test
    public void testCorrect()
    {
        try
        {
            GroupURI g = new GroupURI("ivo://my.authority/gms?name");
            Assert.assertEquals("ivo", g.getURI().getScheme());
            Assert.assertEquals("my.authority", g.getAuthority());
            Assert.assertEquals("/gms", g.getURI().getPath());
            Assert.assertEquals("name", g.getName());
            Assert.assertEquals("ivo://my.authority/gms", g.getServiceID().toString());
        }
        catch (Throwable t)
        {
            log.error("Test Failed", t);
        }
    }

    private void assertIllegalArgument(String uri, String message) throws URISyntaxException
    {
        try
        {
            new GroupURI(uri);
            Assert.fail("Expected Illegal argument for URI " + uri);
        }
        catch (IllegalArgumentException e)
        {
            // expected
            log.debug("Checking if message '" + e.getMessage() + "' contains '" + message + "'");
            Assert.assertTrue(e.getMessage().toLowerCase().contains(message));
        }
    }
}
