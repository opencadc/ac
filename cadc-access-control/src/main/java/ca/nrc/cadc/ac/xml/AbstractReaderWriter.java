/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2024.                            (c) 2024.
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

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupProperty;
import ca.nrc.cadc.ac.InternalID;
import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.PosixDetails;
import ca.nrc.cadc.ac.ReaderException;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.ac.WriterException;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityType;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.date.DateUtil;
import java.io.IOException;
import java.io.Writer;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.jdom2.Attribute;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.opencadc.gms.GroupURI;

/**
 * AbstractReaderWriter TODO describe class
 */
public abstract class AbstractReaderWriter {
    public static final String ADDRESS = "address";
    public static final String AUTHORITY = "authority";
    public static final String CITY = "city";
    public static final String COUNTRY = "country";
    public static final String EMAIL = "email";
    public static final String DESCRIPTION = "description";
    public static final String FIRST_NAME = "firstName";
    public static final String GID = "gid";
    public static final String GROUP = "group";
    public static final String GROUPS = "groups";
    public static final String GROUP_ADMINS = "groupAdmins";
    public static final String GROUP_MEMBERS = "groupMembers";
    public static final String HOME_DIRECTORY = "homeDirectory";
    public static final String ID = "id";
    public static final String IDENTITY = "identity";
    public static final String IDENTITIES = "identities";
    public static final String INSTITUTE = "institute";
    public static final String INTEGER = "Integer";
    public static final String INTERNAL_ID = "internalID";
    public static final String KEY = "key";
    public static final String LAST_MODIFIED = "lastModified";
    public static final String LAST_NAME = "lastName";
    public static final String OWNER = "owner";
    public static final String PASSWORD = "password";
    public static final String PERSONAL_DETAILS = "personalDetails";
    public static final String POSIX_DETAILS = "posixDetails";
    public static final String PROPERTIES = "properties";
    public static final String PROPERTY = "property";
    public static final String READ_ONLY = "readOnly";
    public static final String STRING = "String";
    public static final String TYPE = "type";
    public static final String UID = "uid";
    public static final String URI = "uri";
    public static final String USER = "user";
    public static final String USERNAME = "username";
    public static final String USERS = "users";
    public static final String USER_ADMINS = "userAdmins";
    public static final String USER_MEMBERS = "userMembers";
    public static final String USER_REQUEST = "userRequest";

    public AbstractReaderWriter() {
    }

    /**
     * Write to root Element to a writer.
     *
     * @param root   Root Element to write.
     * @param writer Writer to write to.
     * @throws IOException if the writer fails to write.
     */
    protected void write(Element root, Writer writer)
            throws IOException {
        XMLOutputter outputter = new XMLOutputter();
        outputter.setFormat(Format.getPrettyFormat());
        outputter.output(new Document(root), writer);
    }

    /**
     * Get a User object from a JDOM element.
     *
     * @param element The User JDOM element.
     * @return A User object.
     * @throws ReaderException
     */
    protected final User getUser(Element element)
            throws ReaderException {
        User user = new User();

        // id
        Element internalIDElement = element.getChild(INTERNAL_ID);
        if (internalIDElement != null) {
            setInternalID(user, internalIDElement);
        }

        // identities
        Element identitiesElement = element.getChild(IDENTITIES);
        if (identitiesElement != null) {
            List<Element> identityElements = identitiesElement.getChildren(IDENTITY);
            for (Element identityElement : identityElements) {
                user.getIdentities().add(getPrincipal(identityElement));
            }
        }

        // personalDetails
        Element personalDetailsElement = element.getChild(PERSONAL_DETAILS);
        if (personalDetailsElement != null) {
            user.personalDetails = getPersonalDetails(personalDetailsElement);
        }

        // posixDetails
        Element posixDetailsElement = element.getChild(POSIX_DETAILS);
        if (posixDetailsElement != null) {
            user.posixDetails = getPosixDetails(posixDetailsElement);
        }

        return user;
    }

    /**
     * Get a UserRequest object from a JDOM element.
     *
     * @param element The UserRequest JDOM element.
     * @return A UserRequest object.
     * @throws ReaderException
     */
    protected final UserRequest getUserRequest(Element element)
            throws ReaderException {
        // user element of the UserRequest element
        Element userElement = element.getChild(USER);
        if (userElement == null) {
            String error = "user element not found in userRequest element";
            throw new ReaderException(error);
        }
        User user = getUser(userElement);

        // password element of the userRequest element
        Element passwordElement = element.getChild(PASSWORD);
        if (passwordElement == null) {
            String error = "password element not found in userRequest element";
            throw new ReaderException(error);
        }
        String password = passwordElement.getText();

        return new UserRequest(user, password.toCharArray());
    }

    /**
     * Get a Principal object from a JDOM element.
     *
     * @param element The Principal JDOM element.
     * @return A Principal object.
     * @throws ReaderException
     */
    protected final Principal getPrincipal(Element element)
            throws ReaderException {
        if (element == null) {
            String error = "null identity element";
            throw new ReaderException(error);
        }

        if (!element.getName().equals(IDENTITY)) {
            String error = "expected identity element name, found "
                    + element.getName();
            throw new ReaderException(error);
        }

        String type = element.getAttributeValue(TYPE);
        if (type == null) {
            String error = "type attribute not found in identity element"
                    + element.getName();
            throw new ReaderException(error);
        }

        String identity = element.getText();
        Principal principal;
        if (type.equals(IdentityType.CADC.getValue())) {
            principal = new NumericPrincipal(UUID.fromString(identity));
        } else if (type.equals(IdentityType.USERNAME.getValue())) {
            principal = new HttpPrincipal(identity);
        } else if (type.equals(IdentityType.X500.getValue())) {
            principal = new X500Principal(identity);
        } else if (type.equals(IdentityType.ENTRY_DN.getValue())) {
            principal = new DNPrincipal(identity);
        } else if (type.equals(IdentityType.OPENID.getValue())) {
            String[] parts = identity.split(" ");
            if (parts.length != 2) {
                String error = "Invalid OpenID identity: " + identity;
                throw new ReaderException(error);
            }
            URL issuer = null;
            try {
                issuer = new URL(parts[0]);
            } catch (MalformedURLException e) {
                String error = "Invalid issuer OpenID identiy: " + identity;
                throw new ReaderException(error);
            }
            principal = new OpenIdPrincipal(issuer, parts[1]);
        } else if (type.equals(IdentityType.POSIX.getValue())) {
            principal = new PosixPrincipal(Integer.parseInt(identity));
        } else {
            String error = "Unknown type attribute: " + type;
            throw new ReaderException(error);
        }

        return principal;
    }

    /**
     * Get a PosixDetails object from a JDOM element.
     *
     * @param element The PosixDetails JDOM element.
     * @return A PosixDetails object.
     * @throws ReaderException
     */
    protected final PosixDetails getPosixDetails(Element element)
            throws ReaderException {
        if (element == null) {
            String error = "null posixDetails element";
            throw new ReaderException(error);
        }

        // userName
        Element userNameElement = element.getChild(USERNAME);
        if (userNameElement == null) {
            String error = "posixDetails missing required element username";
            throw new ReaderException(error);
        }

        // uid
        Element uidElement = element.getChild(UID);
        if (uidElement == null) {
            String error = "posixDetails missing required element uid";
            throw new ReaderException(error);
        }
        int uid;
        try {
            uid = Integer.parseInt(uidElement.getText());
        } catch (NumberFormatException e) {
            String error = "Cannot parse posixDetails uid to a long";
            throw new ReaderException(error);
        }

        // gid
        Element gidElement = element.getChild(GID);
        if (gidElement == null) {
            String error = "posixDetails missing required element gid";
            throw new ReaderException(error);
        }
        int gid;
        try {
            gid = Integer.parseInt(gidElement.getText());
        } catch (NumberFormatException e) {
            String error = "Cannot parse posixDetails gid to a long";
            throw new ReaderException(error);
        }

        // homeDirectory
        Element homeDirElement = element.getChild(HOME_DIRECTORY);
        if (homeDirElement == null) {
            String error = "posixDetails missing required element homeDirectory";
            throw new ReaderException(error);
        }
        String homeDirectory = homeDirElement.getText();

        String username = userNameElement.getText();
        return new PosixDetails(username, uid, gid, homeDirectory);
    }

    /**
     * Get a PersonalDetails object from a JDOM element.
     *
     * @param element The PersonalDetails JDOM element.
     * @return A PersonalDetails object.
     * @throws ReaderException
     */
    protected final PersonalDetails getPersonalDetails(Element element)
            throws ReaderException {
        if (element == null) {
            String error = "null personalDetails element";
            throw new ReaderException(error);
        }

        // firstName
        Element firstNameElement = element.getChild(FIRST_NAME);
        if (firstNameElement == null) {
            String error = "personalDetails missing required element firstName";
            throw new ReaderException(error);
        }
        String firstName = firstNameElement.getText();

        // lastName
        Element lastNameElement = element.getChild(LAST_NAME);
        if (lastNameElement == null) {
            String error = "personalDetails missing required element lastName";
            throw new ReaderException(error);
        }
        String lastName = lastNameElement.getText();

        PersonalDetails details = new PersonalDetails(firstName, lastName);

        // email
        Element emailElement = element.getChild(EMAIL);
        if (emailElement != null) {
            details.email = emailElement.getText();
        }

        // address
        Element addressElement = element.getChild(ADDRESS);
        if (addressElement != null) {
            details.address = addressElement.getText();
        }

        // institute
        Element instituteElement = element.getChild(INSTITUTE);
        if (instituteElement != null) {
            details.institute = instituteElement.getText();
        }

        // city
        Element cityElement = element.getChild(CITY);
        if (cityElement != null) {
            details.city = cityElement.getText();
        }

        // country
        Element countryElement = element.getChild(COUNTRY);
        if (countryElement != null) {
            details.country = countryElement.getText();
        }

        return details;
    }

    /**
     * Get a UserRequest object from a JDOM element.
     *
     * @param element The UserRequest JDOM element.
     * @return A UserRequest object.
     * @throws ReaderException
     */
    protected final Group getGroup(Element element)
            throws ReaderException {
        String uri = element.getAttributeValue(URI);
        if (uri == null) {
            String error = "group missing required uri attribute";
            throw new ReaderException(error);
        }

        // Group owner
        User user = null;
        Element ownerElement = element.getChild(OWNER);
        if (ownerElement != null) {
            // Owner user
            Element userElement = ownerElement.getChild(USER);
            if (userElement == null) {
                String error = "owner missing required user element";
                throw new ReaderException(error);
            }
            user = getUser(userElement);
        }

        Group group;
        try {
            GroupURI groupURI = new GroupURI(uri);
            group = new Group(groupURI);
        } catch (URISyntaxException ex) {
            throw new ReaderException("invalid group URI: " + uri);
        }

        // set owner field
        setField(group, user, OWNER);

        // gid
        Element gidElement = element.getChild(GID);
        if (gidElement != null) {
            group.gid = Integer.parseInt(gidElement.getText());
        }

        // description
        Element descriptionElement = element.getChild(DESCRIPTION);
        if (descriptionElement != null) {
            group.description = descriptionElement.getText();
        }

        // lastModified
        Element lastModifiedElement = element.getChild(LAST_MODIFIED);
        if (lastModifiedElement != null) {
            try {
                DateFormat df = DateUtil.getDateFormat(DateUtil.IVOA_DATE_FORMAT, DateUtil.UTC);
                group.lastModified = df.parse(lastModifiedElement.getText());
            } catch (ParseException e) {
                String error = "Unable to parse group lastModified because " + e.getMessage();

                throw new ReaderException(error);
            }
        }

        // properties
        Element propertiesElement = element.getChild(PROPERTIES);
        if (propertiesElement != null) {
            List<Element> propertyElements = propertiesElement.getChildren(PROPERTY);
            for (Element propertyElement : propertyElements) {
                group.getProperties().add(getGroupProperty(propertyElement));
            }
        }

        // groupMembers
        Element groupMembersElement = element.getChild(GROUP_MEMBERS);
        if (groupMembersElement != null) {
            List<Element> groupElements = groupMembersElement.getChildren(GROUP);
            for (Element groupMember : groupElements) {
                group.getGroupMembers().add(getGroup(groupMember));
            }
        }

        // userMembers
        Element userMembersElement = element.getChild(USER_MEMBERS);
        if (userMembersElement != null) {
            List<Element> userElements = userMembersElement.getChildren(USER);
            for (Element userMember : userElements) {
                group.getUserMembers().add(getUser(userMember));
            }
        }

        // groupAdmins
        Element groupAdminsElement = element.getChild(GROUP_ADMINS);
        if (groupAdminsElement != null) {
            List<Element> groupElements = groupAdminsElement.getChildren(GROUP);
            for (Element groupMember : groupElements) {
                group.getGroupAdmins().add(getGroup(groupMember));
            }
        }

        // userAdmins
        Element userAdminsElement = element.getChild(USER_ADMINS);
        if (userAdminsElement != null) {
            List<Element> userElements = userAdminsElement.getChildren(USER);
            for (Element userMember : userElements) {
                group.getUserAdmins().add(getUser(userMember));
            }
        }

        return group;
    }

    /**
     * Get a GroupProperty object from a JDOM element.
     *
     * @param element The GroupProperty JDOM element.
     * @return A GroupProperty object.
     * @throws ReaderException
     */
    protected final GroupProperty getGroupProperty(Element element)
            throws ReaderException {
        if (element == null) {
            String error = "null property element";
            throw new ReaderException(error);
        }

        if (!element.getName().equals(PROPERTY)) {
            String error = "expected property element name, found "
                    + element.getName();
            throw new ReaderException(error);
        }

        String key = element.getAttributeValue(KEY);
        if (key == null) {
            String error = "required key attribute not found";
            throw new ReaderException(error);
        }

        String type = element.getAttributeValue(TYPE);
        if (type == null) {
            String error = "required type attribute not found";
            throw new ReaderException(error);
        }
        Object value;
        if (type.equals(STRING)) {
            value = String.valueOf(element.getText());
        } else {
            if (type.equals(INTEGER)) {
                value = Integer.valueOf(element.getText());
            } else {
                String error = "Unsupported GroupProperty type: " + type;
                throw new ReaderException(error);
            }
        }
        Boolean readOnly = Boolean.valueOf(element.getAttributeValue(READ_ONLY));

        return new GroupProperty(key, value, readOnly);
    }

    /**
     * Get a JDOM element from a User object.
     *
     * @param user The User.
     * @return A JDOM User representation.
     * @throws WriterException
     */
    protected final Element getElement(User user)
            throws WriterException {
        if (user == null) {
            throw new WriterException("null User");
        }

        // Create the user Element.
        Element userElement = new Element(USER);

        // internalID element
        if (user.getID() != null) {
            userElement.addContent(getElement(user.getID()));
        }

        // identities
        Set<Principal> identities = user.getIdentities();
        if (!identities.isEmpty()) {  // includes alternate identities
            Element identitiesElement = new Element(IDENTITIES);
            for (Principal identity : identities) {
                identitiesElement.addContent(getElement(identity));
            }
            userElement.addContent(identitiesElement);
        }

        // personalDetails
        if (user.personalDetails != null) {
            userElement.addContent(getElement(user.personalDetails));
        }

        // posixDetails
        if (user.posixDetails != null) {
            userElement.addContent(getElement(user.posixDetails));
        }

        return userElement;
    }

    /**
     * Get a JDOM element from a UserRequest object.
     *
     * @param userRequest The UserRequest.
     * @return A JDOM UserRequest representation.
     * @throws WriterException
     */
    protected final Element getElement(UserRequest userRequest)
            throws WriterException {
        if (userRequest == null) {
            throw new WriterException("null UserRequest");
        }

        // Create the userRequest Element.
        Element userRequestElement = new Element(USER_REQUEST);

        // user element
        Element userElement = getElement(userRequest.getUser());
        userRequestElement.addContent(userElement);

        // password element
        Element passwordElement = new Element(PASSWORD);
        passwordElement.setText(String.valueOf(userRequest.getPassword()));
        userRequestElement.addContent(passwordElement);

        return userRequestElement;
    }

    /**
     * Get a JDOM element from a InternalID object.
     *
     * @param internalID The InternalID.
     * @return A JDOM InternalID representation.
     * @throws WriterException
     */
    protected final Element getElement(InternalID internalID)
            throws WriterException {
        if (internalID == null) {
            throw new WriterException("null InternalID");
        }

        // Create the internalID Element.
        Element internalIDElement = new Element(INTERNAL_ID);

        // uri element
        Element uriElement = new Element(URI);
        uriElement.addContent(internalID.getURI().toString());
        internalIDElement.addContent(uriElement);

        return internalIDElement;
    }

    /**
     * Get a JDOM element from a Principal object.
     *
     * @param identity The Principal.
     * @return A JDOM UserDetails representation.
     * @throws WriterException
     */
    protected final Element getElement(Principal identity)
            throws WriterException {
        if (identity == null) {
            String error = "null Principal";
            throw new WriterException(error);
        }

        Element identityElement = new Element(IDENTITY);
        if ((identity instanceof HttpPrincipal)) {
            identityElement.setAttribute(TYPE, IdentityType.USERNAME.getValue());
        } else if ((identity instanceof NumericPrincipal)) {
            identityElement.setAttribute(TYPE, IdentityType.CADC.getValue());
        } else if ((identity instanceof X500Principal)) {
            identityElement.setAttribute(TYPE, IdentityType.X500.getValue());
        } else if ((identity instanceof DNPrincipal)) {
            identityElement.setAttribute(TYPE, IdentityType.ENTRY_DN.getValue());
        } else if ((identity instanceof OpenIdPrincipal)) {
            identityElement.setAttribute(TYPE, IdentityType.OPENID.getValue());
        } else if ((identity instanceof PosixPrincipal)) {
            identityElement.setAttribute(TYPE, IdentityType.POSIX.getValue());
        } else {
            String error = "Unsupported Principal type "
                    + identity.getClass().getSimpleName();
            throw new IllegalArgumentException(error);
        }
        if ((identity instanceof OpenIdPrincipal)) {
            identityElement.setText(((OpenIdPrincipal) identity).getIssuer() + " " + identity.getName());
        } else {
            identityElement.setText(identity.getName());
        }

        return identityElement;
    }

    /**
     * Get a JDOM element from a PosixDetails object.
     *
     * @param details The PosixDetails.
     * @return A JDOM PosixDetails representation.
     */
    protected final Element getElement(PosixDetails details)
            throws WriterException {
        if (details == null) {
            String error = "null PosixDetails";
            throw new WriterException(error);
        }

        Element detailsElement = new Element(POSIX_DETAILS);

        Element usernameElement = new Element(USERNAME);
        usernameElement.setText(details.getUsername());
        detailsElement.addContent(usernameElement);

        Element uidElement = new Element(UID);
        uidElement.setText(String.valueOf(details.getUid()));
        detailsElement.addContent(uidElement);

        Element gidElement = new Element(GID);
        gidElement.setText(String.valueOf(details.getGid()));
        detailsElement.addContent(gidElement);

        Element homeDirElement = new Element(HOME_DIRECTORY);
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
            throws WriterException {
        if (details == null) {
            String error = "null PersonalDetails";
            throw new WriterException(error);
        }

        Element detailsElement = new Element(PERSONAL_DETAILS);

        Element firstNameElement = new Element(FIRST_NAME);
        firstNameElement.setText(details.getFirstName());
        detailsElement.addContent(firstNameElement);

        Element lastNameElement = new Element(LAST_NAME);
        lastNameElement.setText(details.getLastName());
        detailsElement.addContent(lastNameElement);

        if (details.email != null) {
            Element emailElement = new Element(EMAIL);
            emailElement.setText(details.email);
            detailsElement.addContent(emailElement);
        }

        if (details.address != null) {
            Element addressElement = new Element(ADDRESS);
            addressElement.setText(details.address);
            detailsElement.addContent(addressElement);
        }

        if (details.institute != null) {
            Element instituteElement = new Element(INSTITUTE);
            instituteElement.setText(details.institute);
            detailsElement.addContent(instituteElement);
        }

        if (details.city != null) {
            Element cityElement = new Element(CITY);
            cityElement.setText(details.city);
            detailsElement.addContent(cityElement);
        }

        if (details.country != null) {
            Element countryElement = new Element(COUNTRY);
            countryElement.setText(details.country);
            detailsElement.addContent(countryElement);
        }

        return detailsElement;
    }

    /**
     * Get a JDOM element from a Group object.
     *
     * @param group The UserRequest.
     * @return A JDOM Group representation.
     * @throws WriterException
     */
    protected final Element getElement(Group group)
            throws WriterException {
        return getElement(group, true);
    }

    /**
     * Get a JDOM element from a Group object.
     *
     * @param group    The UserRequest.
     * @param deepCopy Return all Group elements.
     * @return A JDOM Group representation.
     * @throws WriterException
     */
    protected final Element getElement(Group group, boolean deepCopy)
            throws WriterException {
        if (group == null) {
            throw new WriterException("null Group");
        }

        // Create the root group element.
        Element groupElement = new Element(GROUP);
        String groupURI = group.getID().toString();
        groupElement.setAttribute(new Attribute(URI, groupURI));

        // gid
        if (group.gid != null) {
            Element gidElement = new Element(GID);
            gidElement.setText(group.gid.toString());
            groupElement.addContent(gidElement);
        }

        // Group owner
        if (group.getOwner() != null) {
            Element ownerElement = new Element(OWNER);
            Element userElement = getElement(group.getOwner());
            ownerElement.addContent(userElement);
            groupElement.addContent(ownerElement);
        }

        if (deepCopy) {
            // Group description
            if (group.description != null) {
                Element descriptionElement = new Element(DESCRIPTION);
                descriptionElement.setText(group.description);
                groupElement.addContent(descriptionElement);
            }

            // lastModified
            if (group.lastModified != null) {
                Element lastModifiedElement = new Element(LAST_MODIFIED);
                DateFormat df = DateUtil.getDateFormat(DateUtil.IVOA_DATE_FORMAT, DateUtil.UTC);
                lastModifiedElement.setText(df.format(group.lastModified));
                groupElement.addContent(lastModifiedElement);
            }

            // Group properties
            if (!group.getProperties().isEmpty()) {
                Element propertiesElement = new Element(PROPERTIES);
                for (GroupProperty property : group.getProperties()) {
                    propertiesElement.addContent(getElement(property));
                }
                groupElement.addContent(propertiesElement);
            }

            // Group groupMembers.
            if ((group.getGroupMembers() != null) && (!group.getGroupMembers().isEmpty())) {
                Element groupMembersElement = new Element(GROUP_MEMBERS);
                for (Group groupMember : group.getGroupMembers()) {
                    groupMembersElement.addContent(getElement(groupMember, false));
                }
                groupElement.addContent(groupMembersElement);
            }

            // Group userMembers
            if ((group.getUserMembers() != null) && (!group.getUserMembers().isEmpty())) {
                Element userMembersElement = new Element(USER_MEMBERS);
                for (User userMember : group.getUserMembers()) {
                    userMembersElement.addContent(getElement(userMember));
                }
                groupElement.addContent(userMembersElement);
            }

            // Group groupAdmins.
            if ((group.getGroupAdmins() != null) && (!group.getGroupAdmins().isEmpty())) {
                Element groupAdminsElement = new Element(GROUP_ADMINS);
                for (Group groupMember : group.getGroupAdmins()) {
                    groupAdminsElement.addContent(getElement(groupMember, false));
                }
                groupElement.addContent(groupAdminsElement);
            }

            // Group userAdmins
            if ((group.getUserAdmins() != null) && (!group.getUserAdmins().isEmpty())) {
                Element userAdminsElement = new Element(USER_ADMINS);
                for (User userMember : group.getUserAdmins()) {
                    userAdminsElement.addContent(getElement(userMember));
                }
                groupElement.addContent(userAdminsElement);
            }
        }

        return groupElement;
    }

    /**
     * Get a JDOM element from a GroupProperty object.
     *
     * @param property The GroupProperty.
     * @return A JDOM GroupProperty representation.
     * @throws WriterException
     */
    protected final Element getElement(GroupProperty property)
            throws WriterException {
        if (property == null) {
            throw new WriterException("null GroupProperty");
        }

        Element propertyElement = new Element(PROPERTY);
        propertyElement.setAttribute(KEY, property.getKey());
        if (property.isReadOnly()) {
            propertyElement.setAttribute(READ_ONLY, Boolean.TRUE.toString());
        }

        Object value = property.getValue();
        if ((value instanceof String)) {
            propertyElement.setAttribute(TYPE, STRING);
        } else if ((value instanceof Integer)) {
            propertyElement.setAttribute(TYPE, INTEGER);
        } else {
            String error = "Unsupported value type: "
                    + value.getClass().getSimpleName();
            throw new IllegalArgumentException(error);
        }
        propertyElement.setText(String.valueOf(property.getValue()));

        return propertyElement;
    }

    private void setInternalID(User user, Element element)
            throws ReaderException {
        Element uriElement = element.getChild(URI);
        if (uriElement == null) {
            String error = "expected uri element not found in internalID element";
            throw new ReaderException(error);
        }
        String text = uriElement.getText();
        URI uri;
        try {
            uri = new URI(text);
        } catch (URISyntaxException e) {
            throw new ReaderException("Invalid InternalID URI " + text, e);
        }

        InternalID internalID = new InternalID(uri);
        setField(user, internalID, ID);
    }

    // set private field using reflection
    private void setField(Object object, Object value, String name) {
        try {
            Field field = object.getClass().getDeclaredField(name);
            field.setAccessible(true);
            field.set(object, value);
        } catch (NoSuchFieldException e) {
            final String error = object.getClass().getSimpleName()
                    + " field " + name + "not found";
            throw new RuntimeException(error, e);
        } catch (IllegalAccessException e) {
            final String error = "unable to update " + name + " in "
                    + object.getClass().getSimpleName();
            throw new RuntimeException(error, e);
        }
    }

}
