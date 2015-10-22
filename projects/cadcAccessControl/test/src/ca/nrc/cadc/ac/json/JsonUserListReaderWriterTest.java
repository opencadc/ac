package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import org.json.JSONObject;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.io.*;
import java.security.Principal;
import java.util.*;

import static org.junit.Assert.*;


/**
 * JsonUserListReaderWriterTest TODO describe class
 */
public class JsonUserListReaderWriterTest
{
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
                    new HttpPrincipal(Integer.toString(i)));

            user.details.add(new PersonalDetails(Integer.toString(i),
                                                 "NUMBER_"));

            if ((i % 2) == 0)
            {
                user.details.add(new PosixDetails(88l + i, 88l + i, "/tmp"));
            }

            users.add(user);
        }

        testSubject.write(users, writer);

        final JSONObject expected =
                new JSONObject("{\"users\":{\"user\":[" +
                               "{\"details\":{\"userDetails\":[{\"firstName\":{\"$\":\"0\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"},{\"uid\":{\"$\":\"88\"},\"gid\":{\"$\":\"88\"},\"homeDirectory\":{\"$\":\"/tmp\"},\"@type\":\"posixDetails\"}]},\"userID\":{\"identity\":{\"$\":\"0\",\"@type\":\"HTTP\"}}}," +
                               "{\"details\":{\"userDetails\":{\"firstName\":{\"$\":\"1\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}},\"userID\":{\"identity\":{\"$\":\"1\",\"@type\":\"HTTP\"}}}," +
                               "{\"details\":{\"userDetails\":[{\"uid\":{\"$\":\"90\"},\"gid\":{\"$\":\"90\"},\"homeDirectory\":{\"$\":\"/tmp\"},\"@type\":\"posixDetails\"},{\"firstName\":{\"$\":\"2\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"2\",\"@type\":\"HTTP\"}}}," +
                               "{\"details\":{\"userDetails\":{\"firstName\":{\"$\":\"3\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}},\"userID\":{\"identity\":{\"$\":\"3\",\"@type\":\"HTTP\"}}}]}}");
        final JSONObject result = new JSONObject(writer.toString());

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
