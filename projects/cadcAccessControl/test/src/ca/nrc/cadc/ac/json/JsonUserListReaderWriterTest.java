package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.Principal;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * JsonUserListReaderWriterTest TODO describe class
 */
public class JsonUserListReaderWriterTest
{
    private static Logger log = Logger.getLogger(JsonUserListReaderWriterTest.class);

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
        catch (IllegalArgumentException e) {}

        try
        {
            InputStream in = null;
            JsonUserListReader reader = new JsonUserListReader();
            List<User<Principal>> u = reader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e) {}

        try
        {
            Reader r = null;
            JsonUserListReader reader = new JsonUserListReader();
            List<User<Principal>> u = reader.read(r);
            fail("null Reader should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e) {}
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
        catch (WriterException e) {}
    }

    @Test
    public void testReadWrite()
        throws Exception
    {
        User<Principal> expected = new User<Principal>(new HttpPrincipal("foo"));
        expected.getIdentities().add(new NumericPrincipal(123l));
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
