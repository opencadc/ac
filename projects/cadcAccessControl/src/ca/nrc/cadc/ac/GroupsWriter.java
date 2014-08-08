package ca.nrc.cadc.ac;

import ca.nrc.cadc.util.StringBuilderWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.List;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class GroupsWriter
{
  public static void write(List<Group> groups, StringBuilder builder)
    throws IOException, WriterException
  {
    write(groups, new StringBuilderWriter(builder));
  }

  public static void write(List<Group> groups, OutputStream out)
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

  public static void write(List<Group> groups, Writer writer)
    throws IOException, WriterException
  {
    if (groups == null)
    {
      throw new WriterException("null groups");
    }

    write(getGroupsElement(groups), writer);
  }

  public static Element getGroupsElement(List<Group> groups)
    throws WriterException
  {
    Element groupsElement = new Element("groups");

    for (Group group : groups)
    {
      groupsElement.addContent(GroupWriter.getGroupElement(group));
    }

    return groupsElement;
  }

  private static void write(Element root, Writer writer)
    throws IOException
  {
    XMLOutputter outputter = new XMLOutputter();
    outputter.setFormat(Format.getPrettyFormat());
    outputter.output(new Document(root), writer);
  }
}