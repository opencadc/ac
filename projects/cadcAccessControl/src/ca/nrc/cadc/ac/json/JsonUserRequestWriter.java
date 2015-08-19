package ca.nrc.cadc.ac.json;

import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.ac.xml.UserRequestWriter;
import ca.nrc.cadc.util.StringBuilderWriter;
import ca.nrc.cadc.xml.JsonOutputter;
import org.jdom2.Document;
import org.jdom2.Element;

import java.io.IOException;
import java.io.Writer;
import java.security.Principal;

/**
 * Class to write a JSON representation of a UserRequest object.
 */
public class JsonUserRequestWriter extends UserRequestWriter
{
    /**
     * Write a UserRequest to a StringBuilder.
     *
     * @param userRequest UserRequest to write.
     * @param builder StringBuilder to write to.
     * @throws java.io.IOException if the writer fails to write.
     * @throws WriterException
     */
    public void write(UserRequest<? extends Principal> userRequest, StringBuilder builder)
        throws IOException, WriterException
    {
        write(userRequest, new StringBuilderWriter(builder));
    }

    /**
     * Write a UserRequest to a Writer.
     *
     * @param userRequest UserRequest to write.
     * @param writer Writer to write to.
     * @throws IOException if the writer fails to write.
     * @throws WriterException
     */
    public static void write(UserRequest<? extends Principal> userRequest, Writer writer)
        throws IOException, WriterException
    {
        if (userRequest == null)
        {
            throw new WriterException("null UserRequest");
        }

        Element children = UserRequestWriter.getUserRequestElement(userRequest);
        Element userRequestElement = new Element("userRequest");
        userRequestElement.addContent(children);
        Document document = new Document();
        document.setRootElement(userRequestElement);

        JsonOutputter jsonOutputter = new JsonOutputter();
        jsonOutputter.getListElementNames().add("identities");
        jsonOutputter.getListElementNames().add("details");

        jsonOutputter.output(document, writer);
    }

}
