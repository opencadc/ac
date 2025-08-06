/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2016.                            (c) 2016.
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
 *
 ************************************************************************
 */

package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.accesscontrol.mail.Mailer;
import ca.nrc.cadc.net.NetUtil;

import javax.mail.MessagingException;
import java.util.ResourceBundle;


public class WebMailer {
    private static final String ORG_FROM_EMAIL_ADDRESS_KEY_PREFIX = "ORG_FROM_EMAIL_ADDRESS_";

    private static final String ORG_REPLY_TO_EMAIL_ADDRESS_KEY = "ORG_REPLY_TO_EMAIL_ADDRESS";
    private static final String ORG_ACRONYM_KEY_PREFIX = "ORG_ACRONYM_";
    private static final String ORG_NAME_KEY_PREFIX = "ORG_NAME_";
    private static final String EMAIL_BODY_CONTENT_KEY = "BODY_CONTENT";
    private static final String NEW_PASSWORD_PAGE_KEY_PREFIX = "ORG_NEW_PASSWORD_PAGE_";
    private static final String EMAIL_SUBJECT_CONTENT_KEY = "EMAIL_SUBJECT";
    private static final String ORG_EMAIL_SENT_PAGE_KEY_PREFIX = "ORG_EMAIL_SENT_PAGE_";

    private final ResourceBundle i18nBundle;
    private final SiteRole siteRole;
    private final String hostName;


    public WebMailer(final SiteRole siteRole, final String hostName, final ResourceBundle i18nBundle) {
        this.siteRole = siteRole;
        this.hostName = hostName;
        this.i18nBundle = i18nBundle;
    }


    private String getURLPrefix() {
        return "https://" + hostName;
    }

    /**
     * Create the link to be sent in the e-mail to the user.
     *
     * @param token The unique token.
     * @return URL of the token.
     */
    String createLink(final String token) {
        return getURLPrefix() + i18nBundle.getString(NEW_PASSWORD_PAGE_KEY_PREFIX + siteRole.name())
               + "?token=" + NetUtil.encode(token);
    }

    /**
     * The mail message is the body of the e-mail.  It will contain paragraphs
     * with placeholders to enter variables, all of which is done here based on
     * the current locale bundle.
     *
     * @return String message.
     */
    private String assembleMessage(final String token) {
        final String organizationAcronym = i18nBundle.getString(ORG_ACRONYM_KEY_PREFIX + siteRole.name());
        final String organizationName = i18nBundle.getString(ORG_NAME_KEY_PREFIX + siteRole.name());
        final String linkText = createLink(token);
        return String.format(i18nBundle.getString(EMAIL_BODY_CONTENT_KEY), organizationAcronym, linkText,
                             organizationName);
    }

    /**
     * Send the mail and return the redirect location.
     *
     * @param mailAddress The e-mail address of the user.
     * @param token       The generated Token from the AC service.
     * @return The redirect location.
     * @throws MessagingException   If mail sending did not succeed.
     */
    public String sendMail(final String mailAddress, final String token) throws MessagingException {
        final String message = assembleMessage(token);
        getMailer(mailAddress, message).doSend();
        return getURLPrefix() + i18nBundle.getString(ORG_EMAIL_SENT_PAGE_KEY_PREFIX + siteRole.name());
    }

    private Mailer getMailer(final String mailAddress, final String message) {
        final Mailer mailer = createMailer();

        mailer.setFrom(i18nBundle.getString(ORG_FROM_EMAIL_ADDRESS_KEY_PREFIX + siteRole.name()));
        mailer.setSubject(i18nBundle.getString(EMAIL_SUBJECT_CONTENT_KEY));
        mailer.setToList(new String[] {mailAddress});
        mailer.setBody(message);
        if (i18nBundle.containsKey(ORG_REPLY_TO_EMAIL_ADDRESS_KEY)) {
            mailer.setReplyToList(new String[] {i18nBundle.getString(ORG_REPLY_TO_EMAIL_ADDRESS_KEY)});
        }
        mailer.setContentType(Mailer.DEFAULT_CONTENT_TYPE);

        return mailer;
    }

    /**
     * Create a new Mailer.  Test implementors can override.
     *
     * @return Mailer instance.
     */
    Mailer createMailer() {
        return new Mailer();
    }
}
