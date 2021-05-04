
package org.opencadc.gms;

import java.net.URISyntaxException;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.util.Log4jInit;
import java.net.URI;

public class GroupURITest {

    private static Logger log = Logger.getLogger(GroupURITest.class);

    static {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.DEBUG);
    }

    @Test
    public void testEquals() {
        GroupURI uri1 = new GroupURI(URI.create("ivo://example.org/gms?name"));
        GroupURI uri2 = new GroupURI(URI.create("ivo://example.org/gms?name"));
        Assert.assertTrue(uri1.equals(uri2));

        uri1 = new GroupURI(URI.create("ivo://example.org/gms?name"));
        uri2 = new GroupURI(URI.create("ivo://example.org/gms#name")); // backwards compat only
        Assert.assertTrue(uri1.equals(uri2));
    }

    @Test
    public void testMalformed() {
        try {
            // no scheme
            assertIllegalArgument("example.org/gms?gname", "scheme");

            // wrong scheme
            assertIllegalArgument("gms://example.org/gms?gname", "scheme");

            // no authority
            assertIllegalArgument("ivo://gms?gname", "authority");

            // no path
            assertIllegalArgument("ivo://example.org/gname", "name");
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testCorrect1() {
        try {
            GroupURI g = new GroupURI("ivo://my.authority/gms?name");
            Assert.assertEquals("ivo", g.getURI().getScheme());
            Assert.assertEquals("/gms", g.getURI().getPath());
            Assert.assertEquals("name", g.getName());
            Assert.assertEquals("ivo://my.authority/gms", g.getServiceID().toASCIIString());
            Assert.assertEquals("ivo://my.authority/gms?name", g.getURI().toASCIIString());
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testCorrect2() {
        try {
            GroupURI g = new GroupURI("ivo://my.authority/gms#name");
            Assert.assertEquals("ivo", g.getURI().getScheme());
            Assert.assertEquals("/gms", g.getURI().getPath());
            Assert.assertEquals("name", g.getName());
            Assert.assertEquals("ivo://my.authority/gms", g.getServiceID().toASCIIString());
            Assert.assertEquals("ivo://my.authority/gms?name", g.getURI().toASCIIString());
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    private void assertIllegalArgument(String uri, String message) throws URISyntaxException {
        try {
            new GroupURI(uri);
            Assert.fail("expected IllegalArgumentException, got: " + uri);
        } catch (IllegalArgumentException e) {
            // expected
            log.debug("Checking if message '" + e.getMessage() + "' contains '" + message + "'");
            Assert.assertTrue(e.getMessage().toLowerCase().contains(message));
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }
}
