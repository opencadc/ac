package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import org.json.JSONObject;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.io.*;
import java.security.Principal;
import java.util.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import static org.junit.Assert.*;


/**
 * JsonUserListReaderWriterTest TODO describe class
 */
public class JsonUserListReaderWriterTest
{
    private static final Logger log = Logger.getLogger(JsonUserListReaderWriterTest.class);
    
    static
    {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }
    
    @Test
    public void testReaderExceptions()
            throws Exception
    {
        try
        {
            JsonUserListReader reader = new JsonUserListReader();
            reader.read((String) null);
            fail("null String should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            // Good
        }

        try
        {
            JsonUserListReader reader = new JsonUserListReader();
            reader.read((InputStream) null);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e)
        {
            // Good
        }

        try
        {
            JsonUserListReader reader = new JsonUserListReader();
            reader.read((Reader) null);
            fail("null Reader should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            // Good
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

        final List<User<HttpPrincipal>> users =
                new ArrayList<User<HttpPrincipal>>();
        final Writer writer = new StringWriter();

        for (int i = 0; i < 4; i++)
        {
            final User<HttpPrincipal> user = new User<HttpPrincipal>(
                    new HttpPrincipal("u"+Integer.toString(i)));

            user.details.add(new PersonalDetails("f"+Integer.toString(i),
                                                 "NUMBER_"));

            if ((i % 2) == 0)
            {
                user.details.add(new PosixDetails(88l + i, 88l + i, "/tmp"));
            }

            users.add(user);
        }

        testSubject.write(users, writer);

        final JSONObject expected =
                new JSONObject("{\"users\":{\"$\":[" +
                               "{\"details\":{\"$\":[{\"firstName\":{\"$\":\"f0\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"},{\"uid\":{\"$\":88},\"gid\":{\"$\":88},\"homeDirectory\":{\"$\":\"/tmp\"},\"@type\":\"posixDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u0\",\"@type\":\"HTTP\"}}}," +
                               "{\"details\":{\"$\":[{\"firstName\":{\"$\":\"f1\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u1\",\"@type\":\"HTTP\"}}}," +
                               "{\"details\":{\"$\":[{\"uid\":{\"$\":90},\"gid\":{\"$\":90},\"homeDirectory\":{\"$\":\"/tmp\"},\"@type\":\"posixDetails\"},{\"firstName\":{\"$\":\"f2\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u2\",\"@type\":\"HTTP\"}}}," +
                               "{\"details\":{\"$\":[{\"firstName\":{\"$\":\"f3\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u3\",\"@type\":\"HTTP\"}}}]}}");
        
        String json = writer.toString();
        log.debug("user list:\n" + json);
        final JSONObject result = new JSONObject(json);

        JSONAssert.assertEquals(expected, result, false);

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
            // Good
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
