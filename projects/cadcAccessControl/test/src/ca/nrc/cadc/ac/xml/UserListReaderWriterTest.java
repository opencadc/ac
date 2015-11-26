package ca.nrc.cadc.ac.xml;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import org.apache.log4j.Logger;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class UserListReaderWriterTest
{
    private static Logger log = Logger.getLogger(UserListReaderWriterTest.class);

    @Test
    public void testReaderExceptions()
        throws Exception
    {
        try
        {
            String s = null;
            UserListReader UserListReader = new UserListReader();
            List<User<Principal>> u = UserListReader.read(s);
            fail("null String should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e) {}

        try
        {
            InputStream in = null;
            UserListReader userListReader = new UserListReader();
            List<User<Principal>> u = userListReader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e) {}

        try
        {
            Reader r = null;
            UserListReader userListReader = new UserListReader();
            List<User<Principal>> u = userListReader.read(r);
            fail("null element should throw ReaderException");
        }
        catch (IllegalArgumentException e) {}
    }

    @Test
    public void testWriterExceptions()
        throws Exception
    {
        try
        {
            UserListWriter userListWriter = new UserListWriter();
            userListWriter.write(null, new StringBuilder());
            fail("null User should throw WriterException");
        }
        catch (WriterException e) {}
    }

    @Test
    public void testMinimalReadWrite()
        throws Exception
    {
        List<User<Principal>> expected = new ArrayList<User<Principal>>();
        expected.add(new User<Principal>(new HttpPrincipal("foo")));
        expected.add(new User<Principal>(new X500Principal("cn=foo,o=bar")));

        StringBuilder xml = new StringBuilder();
        UserListWriter userListWriter = new UserListWriter();
        userListWriter.write(expected, xml);
        assertFalse(xml.toString().isEmpty());

        UserListReader userListReader = new UserListReader();
        List<User<Principal>> actual = userListReader.read(xml.toString());
        assertNotNull(actual);
        assertEquals(expected.size(), actual.size());
        assertEquals(expected.get(0), actual.get(0));
        assertEquals(expected.get(1), actual.get(1));
    }

}