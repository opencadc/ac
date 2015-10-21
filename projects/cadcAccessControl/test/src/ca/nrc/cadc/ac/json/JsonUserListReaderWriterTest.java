package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.io.*;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.*;

/**
 * JsonUserListReaderWriterTest TODO describe class
 */
public class JsonUserListReaderWriterTest
{
    private static Logger log = Logger
            .getLogger(JsonUserListReaderWriterTest.class);

    @Test
    public void testReaderExceptions()
            throws Exception
    {
        try
        {
            String s = null;
            JsonUserListReader reader = new JsonUserListReader();
            List<User<Principal>> u = reader.read(s);
            fail("null String should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
        }

        try
        {
            InputStream in = null;
            JsonUserListReader reader = new JsonUserListReader();
            List<User<Principal>> u = reader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e)
        {
        }

        try
        {
            Reader r = null;
            JsonUserListReader reader = new JsonUserListReader();
            List<User<Principal>> u = reader.read(r);
            fail("null Reader should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    /**
     * Test the JSON Output writer.
     * <p/>
     * TODO - Warning!  The JSONAssert testing library fails parsing of the
     * todo - JSON, so this test was changed to use String compare instead.
     *
     * @throws Exception
     */
    @Test
    public void testWriter() throws Exception
    {
        final JsonUserListWriter testSubject = new JsonUserListWriter();

        final Collection<User<HttpPrincipal>> users =
                new ArrayList<User<HttpPrincipal>>();
        final Writer writer = new StringWriter();

        for (int i = 0; i < 4; i++)
        {
            users.add(new User<HttpPrincipal>(
                    new HttpPrincipal(Integer.toString(i))));
        }

        testSubject.write(users, writer);

        final JSONObject expected =
                new JSONObject("{\"users\":{\"user\":[{\"userID\":" +
                               "{\"identity\":{\"$\":\"0\",\"@type\":\"HTTP\"}}}," +
                               "{\"userID\":{\"identity\":{\"$\":\"1\",\"@type\":\"HTTP\"}}}," +
                               "{\"userID\":{\"identity\":{\"$\":\"2\",\"@type\":\"HTTP\"}}}," +
                               "{\"userID\":{\"identity\":{\"$\":\"3\",\"@type\":\"HTTP\"}}}]}}");
        final JSONObject result = new JSONObject(writer.toString());

        JSONAssert.assertEquals(expected, result, true);

        JsonUserListReader reader = new JsonUserListReader();
        final InputStream in =
                new ByteArrayInputStream(expected.toString().getBytes());
        final Collection<User<Principal>> readBackIn = reader.read(in);

        assertEquals("Size is wrong.", 4, readBackIn.size());
    }

    @Test
    public void testWriterExceptions()
            throws Exception
    {
        try
        {
            JsonUserWriter writer = new JsonUserWriter();
            writer.write(null, new StringBuilder());
            fail("null User should throw WriterException");
        }
        catch (WriterException e)
        {
        }
    }

    @Test
    public void testReadWrite()
            throws Exception
    {
        User<Principal> expected = new User<Principal>(new HttpPrincipal("foo"));
        expected.getIdentities().add(new NumericPrincipal(123));
        expected.details.add(new PersonalDetails("firstname", "lastname"));
        expected.details.add(new PosixDetails(123l, 456l, "foo"));

        StringBuilder json = new StringBuilder();
        JsonUserWriter writer = new JsonUserWriter();
        writer.write(expected, json);
        assertFalse(json.toString().isEmpty());

        JsonUserReader reader = new JsonUserReader();
        User<Principal> actual = reader.read(json.toString());
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

}
