package org.opencadc.gms;

import ca.nrc.cadc.util.Log4jInit;
import java.net.URI;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

public class GroupURITest {

    private static Logger log = Logger.getLogger(GroupURITest.class);

    static {
        Log4jInit.setLevel("org.opencadc.gms", Level.INFO);
    }

    @Test
    public void testEquals() {
        GroupURI uri1 = new GroupURI(URI.create("ivo://example.org/gms?name"));
        GroupURI uri2 = new GroupURI(URI.create("ivo://example.org/gms?name"));
        Assert.assertTrue(uri1.equals(uri2));
    }

    @Test
    public void testMalformed() {

        try {

            assertIllegalArgument(URI.create("ivo://example.org/gms?first.last@idp.com"));
            assertIllegalArgument(URI.create("ivo://example.org/gms"), "first.last@idp.com");

            // no scheme
            assertIllegalArgument(URI.create("example.org/gms?gname"));
            assertIllegalArgument(URI.create("example.org/gms"), "gname");

            // wrong scheme
            assertIllegalArgument(URI.create("gms://example.org/gms?gname"));
            assertIllegalArgument(URI.create("gms://example.org/gms"), "gname");

            // no authority
            assertIllegalArgument(URI.create("ivo://gms?gname"));
            assertIllegalArgument(URI.create("ivo://gms"), "gname");

            // no path
            assertIllegalArgument(URI.create("ivo://example.org?gname"));
            assertIllegalArgument(URI.create("ivo://example.org"), "gname");

            // no group name
            assertIllegalArgument(URI.create("ivo://example.org/gms"));
            assertIllegalArgument(URI.create("ivo://example.org/gms"), null);
            assertIllegalArgument(URI.create("ivo://example.org/gms"), "");
            assertIllegalArgument(URI.create("ivo://example.org/gms"), " ");

            // fragment not allowed
            assertIllegalArgument(URI.create("ivo://my.authority/gms#name"));
            assertIllegalArgument(URI.create("ivo://my.authority/gms#name"), null);
            assertIllegalArgument(URI.create("ivo://my.authority/gms?name#name"));
            assertIllegalArgument(URI.create("ivo://my.authority/gms?name#name"));

        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    @Test
    public void testSimpleGroupName() {
        try {
            GroupURI g = new GroupURI(URI.create("ivo://my.authority/gms?name"));
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
    public void testHierarchicalGroupName() {
        try {
            String name = "hierachical/group/structure";
            GroupURI g = new GroupURI(URI.create("ivo://my.authority/gms?" + name));
            Assert.assertEquals("ivo", g.getURI().getScheme());
            Assert.assertEquals("/gms", g.getURI().getPath());
            Assert.assertEquals(name, g.getName());
            Assert.assertEquals("ivo://my.authority/gms", g.getServiceID().toASCIIString());
            Assert.assertEquals("ivo://my.authority/gms?" + name, g.getURI().toASCIIString());
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    private void assertIllegalArgument(URI uri) {
        try {
            GroupURI gu = new GroupURI(uri);
            Assert.fail("expected IllegalArgumentException, got: " + gu);
        } catch (IllegalArgumentException e) {
            log.info("caught expected: " + e);
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }

    private void assertIllegalArgument(URI resourceID, String name) {
        try {
            GroupURI gu = new GroupURI(resourceID, name);
            Assert.fail("expected IllegalArgumentException, got: " + gu);
        } catch (IllegalArgumentException e) {
            log.info("caught expected: " + e);
        } catch (Exception unexpected) {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
    }
}
