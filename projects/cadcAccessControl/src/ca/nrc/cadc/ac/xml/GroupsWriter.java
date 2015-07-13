package ca.nrc.cadc.ac.xml;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.util.StringBuilderWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.Collection;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class GroupsWriter
{
    /**
     * Write a List of Group's to a StringBuilder.
     * @param groups List of Group's to write.
     * @param builder
     * @throws java.io.IOException
     * @throws WriterException
     */
    public static void write(Collection<Group> groups, StringBuilder builder)
        throws IOException, WriterException
    {
        write(groups, new StringBuilderWriter(builder));
    }

    /**
     * Write a List of Group's to an OutputStream.
     * 
     * @param groups List of Group's to write.
     * @param out OutputStream to write to.
     * @throws IOException if the writer fails to write.
     * @throws WriterException
     */
    public static void write(Collection<Group> groups, OutputStream out)
        throws IOException, WriterException
    {
        OutputStreamWriter outWriter;
        try
        {
        outWriter = new OutputStreamWriter(out, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
        throw new RuntimeException("UTF-8 encoding not supported", e);
        }
        write(groups, new BufferedWriter(outWriter));
    }

    /**
     * Write a List of Group's to a Writer.
     * 
     * @param groups List of Group's to write.
     * @param writer  Writer to write to.
     * @throws IOException if the writer fails to write.
     * @throws WriterException
     */
    public static void write(Collection<Group> groups, Writer writer)
        throws IOException, WriterException
    {
        if (groups == null)
        {
        throw new WriterException("null groups");
        }

        write(getGroupsElement(groups), writer);
    }

    /**
     * 
     * @param groups List of Group's to write.
     * @return Element of list of Group's.
     * @throws WriterException
     */
    public static Element getGroupsElement(Collection<Group> groups)
        throws WriterException
    {
        Element groupsElement = new Element("groups");

        for (Group group : groups)
        {
            groupsElement.addContent(GroupWriter.getGroupElement(group));
        }

        return groupsElement;
    }

    /**
     * Write to root Element to a writer.
     * 
     * @param root Root Element to write.
     * @param writer Writer to write to.
     * @throws IOException if the writer fails to write.
     */
    private static void write(Element root, Writer writer)
        throws IOException
    {
        XMLOutputter outputter = new XMLOutputter();
        outputter.setFormat(Format.getPrettyFormat());
        outputter.output(new Document(root), writer);
    }
    
}