/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2011.                            (c) 2011.
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
*  $Revision: 5 $
*
************************************************************************
*/

package ca.nrc.cadc.ac.xml;

import ca.nrc.cadc.ac.AC;
import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.IdentityType;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserDetails;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.date.DateUtil;
import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.Writer;
import java.security.Principal;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.List;
import java.util.Set;

/**
 * AbstractXML TODO describe class
 */
public abstract class AbstractXML
{
    /**
     * Write to root Element to a writer.
     *
     * @param root Root Element to write.
     * @param writer Writer to write to.
     * @throws IOException if the writer fails to write.
     */
    protected void write(Element root, Writer writer)
        throws IOException
    {
        XMLOutputter outputter = new XMLOutputter();
        outputter.setFormat(Format.getPrettyFormat());
        outputter.output(new Document(root), writer);
    }

    /**
     * Get a UserRequest object from a JDOM element.
     *
     * @param element The UserRequest JDOM element.
     * @return A UserRequest object.
     * @throws ReaderException
     */
    protected final Group getGroup(Element element)
        throws ReaderException
    {
        String uri = element.getAttributeValue("uri");
        if (uri == null)
        {
            String error = "group missing required uri attribute";
            throw new ReaderException(error);
        }

        // Group groupID
        int index = uri.indexOf(AC.GROUP_URI);
        if (index == -1)
        {
            String error = "group uri attribute malformed: " + uri;
            throw new ReaderException(error);
        }
        String groupID = uri.substring(AC.GROUP_URI.length());

        // Group owner
        User<? extends Principal> user = null;
        Element ownerElement = element.getChild("owner");
        if (ownerElement != null)
        {
            // Owner user
            Element userElement = ownerElement.getChild("user");
            if (userElement == null)
            {
                String error = "owner missing required user element";
                throw new ReaderException(error);
            }
            user = getUser(userElement);
        }

        Group group = new Group(groupID, user);

        // description
        Element descriptionElement = element.getChild("description");
        if (descriptionElement != null)
        {
            group.description = descriptionElement.getText();
        }

        // lastModified
        Element lastModifiedElement = element.getChild("lastModified");
        if (lastModifiedElement != null)
        {
            try
            {
                DateFormat df = DateUtil.getDateFormat(DateUtil.IVOA_DATE_FORMAT, DateUtil.UTC);
                group.lastModified = df.parse(lastModifiedElement.getText());
            }
            catch (ParseException e)
            {
                String error = "Unable to parse group lastModified because " + e.getMessage();

                throw new ReaderException(error);
            }
        }

        // properties
        Element propertiesElement = element.getChild("properties");
        if (propertiesElement != null)
        {
            List<Element> propertyElements = propertiesElement.getChildren("property");
            for (Element propertyElement : propertyElements)
            {
                group.getProperties().add(getGroupProperty(propertyElement));
            }
        }

        // groupMembers
        Element groupMembersElement = element.getChild("groupMembers");
        if (groupMembersElement != null)
        {
            List<Element> groupElements = groupMembersElement.getChildren("group");
            for (Element groupMember : groupElements)
            {
                group.getGroupMembers().add(getGroup(groupMember));
            }
        }

        // userMembers
        Element userMembersElement = element.getChild("userMembers");
        if (userMembersElement != null)
        {
            List<Element> userElements = userMembersElement.getChildren("user");
            for (Element userMember : userElements)
            {
                group.getUserMembers().add(getUser(userMember));
            }
        }

        // groupAdmins
        Element groupAdminsElement = element.getChild("groupAdmins");
        if (groupAdminsElement != null)
        {
            List<Element> groupElements = groupAdminsElement.getChildren("group");
            for (Element groupMember : groupElements)
            {
                group.getGroupAdmins().add(getGroup(groupMember));
            }
        }

        // userAdmins
        Element userAdminsElement = element.getChild("userAdmins");
        if (userAdminsElement != null)
        {
            List<Element> userElements = userAdminsElement.getChildren("user");
            for (Element userMember : userElements)
            {
                group.getUserAdmins().add(getUser(userMember));
            }
        }

        return group;
    }

    /**
     * Get a JDOM element from a Group object.
     *
     * @param group The UserRequest.
     * @return A JDOM Group representation.
     * @throws WriterException
     */
    protected final Element getElement(Group group)
        throws WriterException
    {
        return getElement(group, true);
    }

    /**
     * Get a JDOM element from a Group object.
     *
     * @param group The UserRequest.
     * @param deepCopy Return all Group elements.
     * @return A JDOM Group representation.
     * @throws WriterException
     */
    protected final Element getElement(Group group, boolean deepCopy)
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
            Element userElement = getElement(group.getOwner());
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
                    propertiesElement.addContent(getElement(property));
                }
                groupElement.addContent(propertiesElement);
            }

            // Group groupMembers.
            if ((group.getGroupMembers() != null) && (!group.getGroupMembers().isEmpty()))
            {
                Element groupMembersElement = new Element("groupMembers");
                for (Group groupMember : group.getGroupMembers())
                {
                    groupMembersElement.addContent(getElement(groupMember, false));
                }
                groupElement.addContent(groupMembersElement);
            }

            // Group userMembers
            if ((group.getUserMembers() != null) && (!group.getUserMembers().isEmpty()))
            {
                Element userMembersElement = new Element("userMembers");
                for (User<? extends Principal> userMember : group.getUserMembers())
                {
                    userMembersElement.addContent(getElement(userMember));
                }
                groupElement.addContent(userMembersElement);
            }

            // Group groupAdmins.
            if ((group.getGroupAdmins() != null) && (!group.getGroupAdmins().isEmpty()))
            {
                Element groupAdminsElement = new Element("groupAdmins");
                for (Group groupMember : group.getGroupAdmins())
                {
                    groupAdminsElement.addContent(getElement(groupMember, false));
                }
                groupElement.addContent(groupAdminsElement);
            }

            // Group userAdmins
            if ((group.getUserAdmins() != null) && (!group.getUserAdmins().isEmpty()))
            {
                Element userAdminsElement = new Element("userAdmins");
                for (User<? extends Principal> userMember : group.getUserAdmins())
                {
                    userAdminsElement.addContent(getElement(userMember));
                }
                groupElement.addContent(userAdminsElement);
            }
        }

        return groupElement;
    }

    /**
     * Get a UserRequest object from a JDOM element.
     *
     * @param element The UserRequest JDOM element.
     * @return A UserRequest object.
     * @throws ReaderException
     */
    protected final UserRequest<Principal> getUserRequest(Element element)
        throws ReaderException
    {
        // user element of the UserRequest element
        Element userElement = element.getChild("user");
        if (userElement == null)
        {
            String error = "user element not found in userRequest element";
            throw new ReaderException(error);
        }
        User<Principal> user = getUser(userElement);

        // password element of the userRequest element
        Element passwordElement = element.getChild("password");
        if (passwordElement == null)
        {
            String error = "password element not found in userRequest element";
            throw new ReaderException(error);
        }
        String password = passwordElement.getText();

        return new UserRequest<Principal>(user, password.toCharArray());
    }

    /**
     * Get a JDOM element from a UserRequest object.
     *
     * @param userRequest The UserRequest.
     * @return A JDOM UserRequest representation.
     * @throws WriterException
     */
    protected final Element getElement(UserRequest<? extends Principal> userRequest)
        throws WriterException
    {
        // Create the userRequest Element.
        Element userRequestElement = new Element("userRequest");

        // user element
        Element userElement = getElement(userRequest.getUser());
        userRequestElement.addContent(userElement);

        // password element
        Element passwordElement = new Element("password");
        passwordElement.setText(String.valueOf(userRequest.getPassword()));
        userRequestElement.addContent(passwordElement);

        return userRequestElement;
    }

    /**
     * Get a User object from a JDOM element.
     *
     * @param element The User JDOM element.
     * @return A User object.
     * @throws ReaderException
     */
    protected final User<Principal> getUser(Element element)
        throws ReaderException
    {
        // userID element of the User element
        Element userIDElement = element.getChild("userID");
        if (userIDElement == null)
        {
            String error = "userID element not found in user element";
            throw new ReaderException(error);
        }

        // identity element of the userID element
        Element userIDIdentityElement = userIDElement.getChild("identity");
        if (userIDIdentityElement == null)
        {
            String error = "identity element not found in userID element";
            throw new ReaderException(error);
        }

        Principal userID = getPrincipal(userIDIdentityElement);
        User<Principal> user = new User<Principal>(userID);

        // identities
        Element identitiesElement = element.getChild("identities");
        if (identitiesElement != null)
        {
            List<Element> identityElements = identitiesElement.getChildren("identity");
            for (Element identityElement : identityElements)
            {
                user.getIdentities().add(getPrincipal(identityElement));
            }

        }

        // details
        Element detailsElement = element.getChild("details");
        if (detailsElement != null)
        {
            List<Element> userDetailsElements = detailsElement.getChildren("userDetails");
            for (Element userDetailsElement : userDetailsElements)
            {
                user.details.add(getUserDetails(userDetailsElement));
            }
        }

        return user;
    }

    /**
     * Get a JDOM element from a User object.
     *
     * @param user The User.
     * @return A JDOM User representation.
     * @throws WriterException
     */
    protected final Element getElement(User<? extends Principal> user)
        throws WriterException
    {
        // Create the user Element.
        Element userElement = new Element("user");

        // userID element
        Element userIDElement = new Element("userID");
        userIDElement.addContent(getElement(user.getUserID()));
        userElement.addContent(userIDElement);

        // identities
        Set<Principal> identities = user.getIdentities();
        if (!identities.isEmpty())
        {
            Element identitiesElement = new Element("identities");
            for (Principal identity : identities)
            {
                identitiesElement.addContent(getElement(identity));
            }
            userElement.addContent(identitiesElement);
        }

        // details
        if (!user.details.isEmpty())
        {
            Element detailsElement = new Element("details");
            Set<UserDetails> userDetails = user.details;
            for (UserDetails userDetail : userDetails)
            {
                detailsElement.addContent(getElement(userDetail));
            }
            userElement.addContent(detailsElement);
        }

        return userElement;
    }

    /**
     * Get a GroupProperty object from a JDOM element.
     *
     * @param element The GroupProperty JDOM element.
     * @return A GroupProperty object.
     * @throws ReaderException
     */
    protected final GroupProperty getGroupProperty(Element element)
        throws ReaderException
    {
        if (element == null)
        {
            String error = "null property element";
            throw new ReaderException(error);
        }

        if (!element.getName().equals(GroupProperty.NAME))
        {
            String error = "expected property element name, found " +
                element.getName();
            throw new ReaderException(error);
        }

        String key = element.getAttributeValue(GroupProperty.KEY_ATTRIBUTE);
        if (key == null)
        {
            String error = "required key attribute not found";
            throw new ReaderException(error);
        }

        String type = element.getAttributeValue(GroupProperty.TYPE_ATTRIBUTE);
        if (type == null)
        {
            String error = "required type attribute not found";
            throw new ReaderException(error);
        }
        Object value;
        if (type.equals(GroupProperty.STRING_TYPE))
        {
            value = String.valueOf(element.getText());
        }
        else
        {
            if (type.equals(GroupProperty.INTEGER_TYPE))
            {
                value = Integer.valueOf(element.getText());
            }
            else
            {
                String error = "Unsupported GroupProperty type: " + type;
                throw new ReaderException(error);
            }
        }
        Boolean readOnly = Boolean.valueOf(element.getAttributeValue(GroupProperty.READONLY_ATTRIBUTE));

        return new GroupProperty(key, value, readOnly);
    }

    /**
     * Get a JDOM element from a GroupProperty object.
     *
     * @param property The GroupProperty.
     * @return A JDOM GroupProperty representation.
     * @throws WriterException
     */
    protected final Element getElement(GroupProperty property)
        throws WriterException
    {
        if (property == null)
        {
            throw new WriterException("null GroupProperty");
        }

        Element propertyElement = new Element(GroupProperty.NAME);
        propertyElement.setAttribute(GroupProperty.KEY_ATTRIBUTE,
            property.getKey());
        if (property.isReadOnly())
        {
            propertyElement.setAttribute(GroupProperty.READONLY_ATTRIBUTE,
                "true");
        }

        Object value = property.getValue();
        if ((value instanceof String))
        {
            propertyElement.setAttribute(GroupProperty.TYPE_ATTRIBUTE,
                GroupProperty.STRING_TYPE);
        }
        else if ((value instanceof Integer))
        {
            propertyElement.setAttribute(GroupProperty.TYPE_ATTRIBUTE,
                GroupProperty.INTEGER_TYPE);
        }
        else
        {
            String error = "Unsupported value type: " +
                value.getClass().getSimpleName();
            throw new IllegalArgumentException(error);
        }
        propertyElement.setText(String.valueOf(property.getValue()));

        return propertyElement;
    }

    /**
     * Get a Principal object from a JDOM element.
     *
     * @param element The Principal JDOM element.
     * @return A Principal object.
     * @throws ReaderException
     */
    protected final Principal getPrincipal(Element element)
        throws ReaderException
    {
        if (element == null)
        {
            String error = "null identity element";
            throw new ReaderException(error);
        }

        if (!element.getName().equals("identity"))
        {
            String error = "expected identity element name, found " +
                element.getName();
            throw new ReaderException(error);
        }

        String type = element.getAttributeValue("type");
        if (type == null)
        {
            String error = "type attribute not found in identity element" +
                element.getName();
            throw new ReaderException(error);
        }

        String identity = element.getText();
        Principal principal;
        if (type.equals(IdentityType.OPENID.getValue()))
        {
            principal = new OpenIdPrincipal(identity);
        }
        else if (type.equals(IdentityType.UID.getValue()))
        {
            Integer cadcID;
            try
            {
                cadcID = Integer.valueOf(identity);
            }
            catch (NumberFormatException e)
            {
                String error = "Non-integer cadcID: " + identity;
                throw new ReaderException(error);
            }
            principal = new NumericPrincipal(cadcID);
        }
        else if (type.equals(IdentityType.USERNAME.getValue()))
        {
            principal = new HttpPrincipal(identity);
        }
        else if (type.equals(IdentityType.X500.getValue()))
        {
            principal = new X500Principal(identity);
        }
        else
        {
            String error = "Unknown type attribute: " + type;
            throw new ReaderException(error);
        }

        return principal;
    }

    /**
     * Get a JDOM element from a Principal object.
     *
     * @param identity The Principal.
     * @return A JDOM UserDetails representation.
     * @throws WriterException
     */
    protected final Element getElement(Principal identity)
        throws WriterException
    {
        if (identity == null)
        {
            String error = "null identity";
            throw new WriterException(error);
        }

        Element identityElement = new Element("identity");
        if ((identity instanceof HttpPrincipal))
        {
            identityElement.setAttribute("type", IdentityType.USERNAME.getValue());
        }
        else if ((identity instanceof NumericPrincipal))
        {
            identityElement.setAttribute("type", IdentityType.UID.getValue());
        }
        else if ((identity instanceof OpenIdPrincipal))
        {
            identityElement.setAttribute("type", IdentityType.OPENID.getValue());
        }
        else if ((identity instanceof X500Principal))
        {
            identityElement.setAttribute("type", IdentityType.X500.getValue());
        }
        else
        {
            String error = "Unsupported Principal type " +
                identity.getClass().getSimpleName();
            throw new IllegalArgumentException(error);
        }
        identityElement.setText(identity.getName());

        return identityElement;
    }

    /**
     * Get a UserDetails object from a JDOM element.
     *
     * @param element The UserDetails JDOM element.
     * @return A UserDetails object.
     * @throws ReaderException
     */
    protected final UserDetails getUserDetails(Element element)
        throws ReaderException
    {
        if (element == null)
        {
            throw new ReaderException("null UserDetails");
        }

        if (!element.getName().equals(UserDetails.NAME))
        {
            String error = "expected element name userDetails, found " +
                element.getName();
            throw new ReaderException(error);
        }

        String type = element.getAttributeValue(UserDetails.TYPE_ATTRIBUTE);
        if (type == null)
        {
            String error = "userDetails missing required attribute type";
            throw new ReaderException(error);
        }

        if (type.equals(PosixDetails.NAME))
        {
            return getPosixDetails(element);
        }
        if (type.equals(PersonalDetails.NAME))
        {
            return getPersonalDetails(element);
        }

        String error = "Unknown UserDetails attribute type " + type;
        throw new ReaderException(error);
    }

    /**
     * Get a PosixDetails object from a JDOM element.
     *
     * @param element The PosixDetails JDOM element.
     * @return A PosixDetails object.
     * @throws ReaderException
     */
    protected final PosixDetails getPosixDetails(Element element)
        throws ReaderException
    {
        // uid
        Element uidElement = element.getChild(PosixDetails.UID);
        if (uidElement == null)
        {
            String error = "posixDetails missing required element uid";
            throw new ReaderException(error);
        }
        long uid;
        try
        {
            uid = Long.valueOf(uidElement.getText());
        }
        catch (NumberFormatException e)
        {
            String error = "Cannot parse posixDetails uid to a long";
            throw new ReaderException(error);
        }

        // gid
        Element gidElement = element.getChild(PosixDetails.GID);
        if (gidElement == null)
        {
            String error = "posixDetails missing required element gid";
            throw new ReaderException(error);
        }
        long gid;
        try
        {
            gid = Long.valueOf(gidElement.getText());
        }
        catch (NumberFormatException e)
        {
            String error = "Cannot parse posixDetails gid to a long";
            throw new ReaderException(error);
        }

        // homeDirectory
        Element homeDirElement = element.getChild(PosixDetails.HOME_DIRECTORY);
        if (homeDirElement == null)
        {
            String error = "posixDetails missing required element homeDirectory";
            throw new ReaderException(error);
        }
        String homeDirectory = homeDirElement.getText();

        return new PosixDetails(uid, gid, homeDirectory);
    }

    /**
     * Get a PersonalDetails object from a JDOM element.
     *
     * @param element The PersonalDetails JDOM element.
     * @return A PersonalDetails object.
     * @throws ReaderException
     */
    protected final PersonalDetails getPersonalDetails(Element element)
        throws ReaderException
    {
        // firstName
        Element firstNameElement = element.getChild(PersonalDetails.FIRSTNAME);
        if (firstNameElement == null)
        {
            String error = "personalDetails missing required element firstName";
            throw new ReaderException(error);
        }
        String firstName = firstNameElement.getText();

        // lastName
        Element lastNameElement = element.getChild(PersonalDetails.LASTNAME);
        if (lastNameElement == null)
        {
            String error = "personalDetails missing required element lastName";
            throw new ReaderException(error);
        }
        String lastName = lastNameElement.getText();

        PersonalDetails details = new PersonalDetails(firstName, lastName);

        // email
        Element emailElement = element.getChild(PersonalDetails.EMAIL);
        if (emailElement != null)
        {
            details.email = emailElement.getText();
        }

        // address
        Element addressElement = element.getChild(PersonalDetails.ADDRESS);
        if (addressElement != null)
        {
            details.address = addressElement.getText();
        }

        // institute
        Element instituteElement = element.getChild(PersonalDetails.INSTITUTE);
        if (instituteElement != null)
        {
            details.institute = instituteElement.getText();
        }

        // city
        Element cityElement = element.getChild(PersonalDetails.CITY);
        if (cityElement != null)
        {
            details.city = cityElement.getText();
        }

        // country
        Element countryElement = element.getChild(PersonalDetails.COUNTRY);
        if (countryElement != null)
        {
            details.country = countryElement.getText();
        }

        return details;
    }

    /**
     * Get a JDOM element from a UserDetails object.
     *
     * @param details The UserDetails.
     * @return A JDOM UserDetails representation.
     * @throws WriterException
     */
    protected final Element getElement(UserDetails details)
        throws WriterException
    {
        if (details == null)
        {
            throw new WriterException("null UserDetails");
        }

        if ((details instanceof PosixDetails))
        {
            return getElement((PosixDetails) details);
        }
        if ((details instanceof PersonalDetails))
        {
            return getElement((PersonalDetails) details);
        }

        String error = "Unknown UserDetails implementation: " +
            details.getClass().getName();
        throw new WriterException(error);
    }

    /**
     * Get a JDOM element from a PosixDetails object.
     *
     * @param details The PosixDetails.
     * @return A JDOM PosixDetails representation.
     */
    protected final Element getElement(PosixDetails details)
    {
        Element detailsElement = new Element(UserDetails.NAME);
        detailsElement.setAttribute(UserDetails.TYPE_ATTRIBUTE,
            PosixDetails.NAME);

        Element uidElement = new Element(PosixDetails.UID);
        uidElement.setText(String.valueOf(details.getUid()));
        detailsElement.addContent(uidElement);

        Element gidElement = new Element(PosixDetails.GID);
        gidElement.setText(String.valueOf(details.getGid()));
        detailsElement.addContent(gidElement);

        Element homeDirElement = new Element(PosixDetails.HOME_DIRECTORY);
        homeDirElement.setText(details.getHomeDirectory());
        detailsElement.addContent(homeDirElement);

        return detailsElement;
    }

    /**
     * Get a JDOM element from a PersonalDetails object.
     *
     * @param details The PersonalDetails.
     * @return JDOM PersonalDetails representation.
     */
    protected final Element getElement(PersonalDetails details)
    {
        Element detailsElement = new Element(UserDetails.NAME);
        detailsElement.setAttribute(UserDetails.TYPE_ATTRIBUTE,
            PersonalDetails.NAME);

        Element firstNameElement = new Element(PersonalDetails.FIRSTNAME);
        firstNameElement.setText(details.getFirstName());
        detailsElement.addContent(firstNameElement);

        Element lastNameElement = new Element(PersonalDetails.LASTNAME);
        lastNameElement.setText(details.getLastName());
        detailsElement.addContent(lastNameElement);

        if (details.email != null)
        {
            Element emailElement = new Element(PersonalDetails.EMAIL);
            emailElement.setText(details.email);
            detailsElement.addContent(emailElement);
        }

        if (details.address != null)
        {
            Element addressElement = new Element(PersonalDetails.ADDRESS);
            addressElement.setText(details.address);
            detailsElement.addContent(addressElement);
        }

        if (details.institute != null)
        {
            Element instituteElement = new Element(PersonalDetails.INSTITUTE);
            instituteElement.setText(details.institute);
            detailsElement.addContent(instituteElement);
        }

        if (details.city != null)
        {
            Element cityElement = new Element(PersonalDetails.CITY);
            cityElement.setText(details.city);
            detailsElement.addContent(cityElement);
        }

        if (details.country != null)
        {
            Element countryElement = new Element(PersonalDetails.COUNTRY);
            countryElement.setText(details.country);
            detailsElement.addContent(countryElement);
        }

        return detailsElement;
    }


}
