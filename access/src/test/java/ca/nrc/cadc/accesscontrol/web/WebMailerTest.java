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

import ca.nrc.cadc.accesscontrol.AbstractAccessControlWebTest;

import java.util.*;

import ca.nrc.cadc.accesscontrol.mail.Mailer;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.easymock.EasyMock.*;


public class WebMailerTest extends AbstractAccessControlWebTest<WebMailer> {
    @Test
    public void createLink() {
        final ResourceBundle stubBundle = new ResourceBundle() {
            @Override
            protected Object handleGetObject(final String key) {
                assert key.equals("ORG_NEW_PASSWORD_PAGE_CANFAR");
                return "/canfar/newPassword.html";
            }

            @Override
            public Enumeration<String> getKeys() {
                return Collections.emptyEnumeration();
            }
        };

        setTestSubject(new WebMailer(SiteRole.CANFAR, "www.mysite.com", stubBundle));

        final String linkURL = getTestSubject().createLink("MYTOKEN88");
        assertEquals("Wrong link.",
                     "https://www.mysite.com/canfar/newPassword.html?token=MYTOKEN88", linkURL);
    }

    @Test
    public void sendMail() throws Exception {
        final Map<String, String> bundleMap = new HashMap<>();

        bundleMap.put("ORG_ACRONYM_CADC", "CCDA");
        bundleMap.put("ORG_NAME_CADC", "Centre canadien de données astronomiques");
        bundleMap.put("BODY_CONTENT", "MESSAGE %s WITH %s TOKEN REPLACEMENTS %s.");
        bundleMap.put("ORG_FROM_EMAIL_ADDRESS_CADC", "cadc@cadc.ca");
        bundleMap.put("ORG_NEW_PASSWORD_PAGE_CADC", "/fr/auth/nouveauMotDePasse.html");
        bundleMap.put("EMAIL_SUBJECT", "Mon sujet");
        bundleMap.put("ORG_EMAIL_SENT_PAGE_CADC", "/fra/auth/finis.html");

        final ResourceBundle stubBundle = new ResourceBundle() {
            @Override
            protected Object handleGetObject(final String key) {
                return bundleMap.get(key);
            }

            @Override
            public Enumeration<String> getKeys() {
                return Collections.emptyEnumeration();
            }
        };

        final Mailer mockMailer = createMock(Mailer.class);

        setTestSubject(new WebMailer(SiteRole.CADC, "www.astrosite.com",
                                     stubBundle) {
            @Override
            Mailer createMailer() {
                return mockMailer;
            }
        });

        mockMailer.setFrom("cadc@cadc.ca");
        expectLastCall().once();

        mockMailer.setSubject("Mon sujet");
        expectLastCall().once();

        mockMailer.setBody("MESSAGE CCDA WITH https://www.astrosite.com/fr/auth/nouveauMotDePasse.html?token=MYTOKEN99 "
                           + "TOKEN REPLACEMENTS Centre canadien de données astronomiques.");
        expectLastCall().once();

        mockMailer.setContentType(Mailer.DEFAULT_CONTENT_TYPE);
        expectLastCall().once();

        mockMailer.setToList(aryEq(new String[] {"me@where.com"}));
        expectLastCall().once();

        mockMailer.doSend();
        expectLastCall().once();

        replay(mockMailer);

        final String redirect = getTestSubject().sendMail("me@where.com", "MYTOKEN99");

        assertEquals("Wrong redirect.",
                     "https://www.astrosite.com/fra/auth/finis.html", redirect);

        verify(mockMailer);
    }
}
