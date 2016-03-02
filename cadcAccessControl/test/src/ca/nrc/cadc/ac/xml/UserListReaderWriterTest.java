package ca.nrc.cadc.ac.xml;

import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.TestUtil;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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
            List<User> u = UserListReader.read(s);
            fail("null String should throw IllegalArgumentException");
        }
        catch (IllegalArgumentException e) {}

        try
        {
            InputStream in = null;
            UserListReader userListReader = new UserListReader();
            List<User> u = userListReader.read(in);
            fail("null InputStream should throw IOException");
        }
        catch (IOException e) {}

        try
        {
            Reader r = null;
            UserListReader userListReader = new UserListReader();
            List<User> u = userListReader.read(r);
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
        List<User> expected = new ArrayList<User>();

        User user1 = new User();
        TestUtil.setInternalID(user1, new InternalID(UUID.randomUUID(), "foo"));
        expected.add(user1);

        User user2 = new User();
        TestUtil.setInternalID(user2, new InternalID(UUID.randomUUID(), "bar"));
        expected.add(user2);

        StringBuilder xml = new StringBuilder();
        UserListWriter userListWriter = new UserListWriter();
        userListWriter.write(expected, xml);
        assertFalse(xml.toString().isEmpty());

        UserListReader userListReader = new UserListReader();
        List<User> actual = userListReader.read(xml.toString());
        assertNotNull(actual);
        assertEquals(expected.size(), actual.size());
        assertEquals(expected.get(0), actual.get(0));
        assertEquals(expected.get(1), actual.get(1));
    }

}