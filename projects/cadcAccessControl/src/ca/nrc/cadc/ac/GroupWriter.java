/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *  $Revision: 4 $
 *
 ************************************************************************
 */
package ca.nrc.cadc.ac;

import ca.nrc.cadc.date.DateUtil;
import ca.nrc.cadc.util.StringBuilderWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.Principal;
import java.text.DateFormat;
import java.util.Set;
import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class GroupWriter
{
    /**
     * Write a Group to a StringBuilder.
     * @param group
     * @param builder
     * @throws java.io.IOException
     * @throws ca.nrc.cadc.ac.WriterException
     */
    public static void write(Group group, StringBuilder builder)
        throws IOException, WriterException
    {
        write(group, new StringBuilderWriter(builder));
    }

    /**
     * Write a Group to an OutputStream.
     * 
     * @param group Group to write.
     * @param out OutputStream to write to.
     * @throws IOException if the writer fails to write.
     * @throws ca.nrc.cadc.ac.WriterException
     */
    public static void write(Group group, OutputStream out)
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
        write(group, new BufferedWriter(outWriter));
    }

    /**
     * Write a Group to a Writer.
     * 
     * @param group Group to write.
     * @param writer  Writer to write to.
     * @throws IOException if the writer fails to write.
     * @throws ca.nrc.cadc.ac.WriterException
     */
    public static void write(Group group, Writer writer)
        throws IOException, WriterException
    {
        if (group == null)
        {
            throw new WriterException("null group");
        }

        write(getGroupElement(group), writer);
    }

    /**
     * 
     * @param group
     * @return 
     * @throws ca.nrc.cadc.ac.WriterException 
     */
    public static Element getGroupElement(Group group)
        throws WriterException
    {
        return getGroupElement(group, true);
    }

    public static Element getGroupElement(Group group, boolean deepCopy)
        throws WriterException
    {
        // Create the root group element.
        Element groupElement = new Element("group");
        String groupURI = AC.GROUP_URI + group.getID();
        groupElement.setAttribute(new Attribute("uri", groupURI));

        // Group owner
        if (group.getOwner() != null)
        {
            Element ownerElement = new Element("owner");
            Element userElement = UserWriter.getUserElement(group.getOwner());
            ownerElement.addContent(userElement);
            groupElement.addContent(ownerElement);
        }

        if (deepCopy)
        {
            // Group description
            if (group.description != null)
            {
                Element descriptionElement = new Element("description");
                descriptionElement.setText(group.description);
                groupElement.addContent(descriptionElement);
            }

            // Group publicRead
            Element publicReadElement = new Element("publicRead");
            publicReadElement.setText(String.valueOf(group.publicRead));
            groupElement.addContent(publicReadElement);

            // lastModified
            if (group.lastModified != null)
            {
                Element lastModifiedElement = new Element("lastModified");
                DateFormat df = DateUtil.getDateFormat(DateUtil.IVOA_DATE_FORMAT, DateUtil.UTC);
                lastModifiedElement.setText(df.format(group.lastModified));
                groupElement.addContent(lastModifiedElement);
            }

            // Group properties
            if (!group.getProperties().isEmpty())
            {
                Element propertiesElement = new Element("properties");
                for (GroupProperty property : group.getProperties())
                {
                    propertiesElement.addContent(GroupPropertyWriter.write(property));
                }
                groupElement.addContent(propertiesElement);
            }

            // Group groupMembers.
            if ((group.getGroupMembers() != null) && (!group.getGroupMembers().isEmpty()))
            {
                Element groupMembersElement = new Element("groupMembers");
                for (Group groupMember : group.getGroupMembers())
                {
                    groupMembersElement.addContent(getGroupElement(groupMember, false));
                }
                groupElement.addContent(groupMembersElement);
            }

            // Group groupRead.
            if (group.groupRead != null)
            {
                Element groupReadElement = new Element("groupRead");
                groupReadElement.addContent(getGroupElement(group.groupRead, false));
                groupElement.addContent(groupReadElement);
            }

            // Group groupWrite.
            if (group.groupWrite != null)
            {
                Element groupWriteElement = new Element("groupWrite");
                groupWriteElement.addContent(getGroupElement(group.groupWrite, false));
                groupElement.addContent(groupWriteElement);
            }

            // Group userMembers
            if ((group.getUserMembers() != null) && (!group.getUserMembers().isEmpty()))
            {
                Element userMembersElement = new Element("userMembers");
                for (User<? extends Principal> userMember : group.getUserMembers())
                {
                    userMembersElement.addContent(UserWriter.getUserElement(userMember));
                }
                groupElement.addContent(userMembersElement);
            }
        }

        return groupElement;
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
