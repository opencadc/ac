package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.TestUtil;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.ac.xml.AbstractReaderWriter;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.util.PropertiesReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URI;
import java.util.UUID;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;


/**
 * JsonUserListReaderWriterTest TODO describe class
 */
public class JsonUserListReaderWriterTest {
    private static final Logger log = Logger.getLogger(JsonUserListReaderWriterTest.class);

    static {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
    }

    @BeforeClass
    public static void setupClass() {
        System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");
    }

    @AfterClass
    public static void teardownClass() {
        System.clearProperty(PropertiesReader.class.getName() + ".dir");
    }

    @Test
    public void testReaderExceptions()
            throws Exception {
        try {
            JsonUserListReader reader = new JsonUserListReader();
            reader.read((String) null);
            fail("null String should throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            // Good
        }

        try {
            JsonUserListReader reader = new JsonUserListReader();
            reader.read((InputStream) null);
            fail("null InputStream should throw IOException");
        } catch (IOException e) {
            // Good
        }

        try {
            JsonUserListReader reader = new JsonUserListReader();
            reader.read((Reader) null);
            fail("null Reader should throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
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
//    @Test
//    public void testWriter() throws Exception
//    {
//        final JsonUserListWriter testSubject = new JsonUserListWriter();
//
//        final List<User> users = new ArrayList<User>();
//        final Writer writer = new StringWriter();
//
//        for (int i = 0; i < 4; i++)
//        {
//            final User user = new User(
//                    new HttpPrincipal("u"+Integer.toString(i)));
//
//            user.details.add(new PersonalDetails("f"+Integer.toString(i),
//                                                 "NUMBER_"));
//
//            if ((i % 2) == 0)
//            {
//                user.details.add(new PosixDetails(88l + i, 88l + i, "/tmp"));
//            }
//
//            users.add(user);
//        }
//
//        testSubject.write(users, writer);
//
//        final JSONObject expected =
//                new JSONObject("{\"users\":{\"$\":[" +
//                               "{\"details\":{\"$\":[{\"firstName\":{\"$\":\"f0\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"},{\"uid\":{\"$\":88},\"gid\":{\"$\":88},\"homeDirectory\":{\"$\":\"/tmp\"},\"@type\":\"posixDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u0\",\"@type\":\"HTTP\"}}}," +
//                               "{\"details\":{\"$\":[{\"firstName\":{\"$\":\"f1\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u1\",\"@type\":\"HTTP\"}}}," +
//                               "{\"details\":{\"$\":[{\"uid\":{\"$\":90},\"gid\":{\"$\":90},\"homeDirectory\":{\"$\":\"/tmp\"},\"@type\":\"posixDetails\"},{\"firstName\":{\"$\":\"f2\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u2\",\"@type\":\"HTTP\"}}}," +
//                               "{\"details\":{\"$\":[{\"firstName\":{\"$\":\"f3\"},\"lastName\":{\"$\":\"NUMBER_\"},\"@type\":\"personalDetails\"}]},\"userID\":{\"identity\":{\"$\":\"u3\",\"@type\":\"HTTP\"}}}]}}");
//
//        String json = writer.toString();
//        log.debug("user list:\n" + json);
//        final JSONObject result = new JSONObject(json);
//
//        JSONAssert.assertEquals(expected, result, false);
//
//        JsonUserListReader reader = new JsonUserListReader();
//
//        final InputStream in =
//                new ByteArrayInputStream(expected.toString().getBytes());
//        final Collection<User<Principal>> readBackIn = reader.read(in);
//
//        assertEquals("Size is wrong.", 4, readBackIn.size());
//    }
    @Test
    public void testWriterExceptions()
            throws Exception {
        try {
            JsonUserWriter writer = new JsonUserWriter();
            writer.write(null, new StringBuilder());
            fail("null User should throw WriterException");
        } catch (WriterException e) {
            // Good
        }
    }

    @Test
    public void testReadWrite()
            throws Exception {
        User expected = new User();
        UUID uuid = UUID.randomUUID();
        URI uri = new URI("ivo://cadc.nrc.ca/user?" + UUID.randomUUID());
        TestUtil.setField(expected, new InternalID(uri), AbstractReaderWriter.ID);

        expected.getIdentities().add(new NumericPrincipal(uuid));
        expected.personalDetails = new PersonalDetails("firstname", "lastname");
        expected.personalDetails.address = "address";
        expected.personalDetails.city = "city";
        expected.personalDetails.country = "country";
        expected.personalDetails.email = "foo@bar.com";
        expected.personalDetails.institute = "institute";
        expected.posixDetails = new PosixDetails("bar", 123, 456, "/dev/null");

        StringBuilder json = new StringBuilder();
        JsonUserWriter writer = new JsonUserWriter();
        writer.write(expected, json);
        assertFalse(json.toString().isEmpty());

        JsonUserReader reader = new JsonUserReader();
        User actual = reader.read(json.toString());
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

}
