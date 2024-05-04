/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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

package org.opencadc.posix.mapper.web;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.auth.PosixPrincipal;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;
import ca.nrc.cadc.util.MultiValuedProperties;
import org.opencadc.gms.GroupURI;
import org.opencadc.gms.IvoaGroupClient;
import org.opencadc.posix.mapper.Group;
import org.opencadc.posix.mapper.PosixClient;
import org.opencadc.posix.mapper.Postgres;
import org.opencadc.posix.mapper.PostgresPosixClient;
import org.opencadc.posix.mapper.User;
import org.opencadc.posix.mapper.web.group.AsciiGroupWriter;
import org.opencadc.posix.mapper.web.group.GroupWriter;
import org.opencadc.posix.mapper.web.group.TSVGroupWriter;
import org.opencadc.posix.mapper.web.user.AsciiUserWriter;
import org.opencadc.posix.mapper.web.user.TSVUserWriter;
import org.opencadc.posix.mapper.web.user.UserWriter;

import javax.security.auth.Subject;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import java.util.stream.Collectors;


public abstract class PosixMapperAction extends RestAction {

    protected PosixClient posixClient;
    protected static final MultiValuedProperties POSIX_CONFIGURATION = PosixInitAction.getConfig();
    protected static final String TSV_CONTENT_TYPE = "text/tab-separated-values";


    protected PosixMapperAction() {
        final Postgres postgres = Postgres.instance(PosixMapperAction.POSIX_CONFIGURATION
                                                            .getFirstPropertyValue(PosixInitAction.SCHEMA_KEY))
                                          .entityClass(User.class, Group.class)
                                          .build();
        this.posixClient = new PostgresPosixClient(postgres);
    }

    @Override
    public void initAction() throws Exception {
        super.initAction();
        checkAuthorization();
    }

    private void checkAuthorization() throws Exception {
        final Subject currentUser = AuthenticationUtil.getCurrentSubject();
        final AuthMethod authMethod = AuthenticationUtil.getAuthMethod(currentUser);
        if (AuthMethod.ANON.equals(authMethod)) {
            throw new NotAuthenticatedException("Caller is not authenticated.");
        } else {
            // Standard validate() will provide NumericPrincipal and HTTPPrincipal.  If they are missing, assume
            // API Key access and no Group check.
            final boolean missingPosixPrincipal = currentUser.getPrincipals(PosixPrincipal.class).isEmpty();
            final boolean missingHTTPPrincipal = currentUser.getPrincipals(HttpPrincipal.class).isEmpty();
            final boolean tokenFromAPIKey = AuthMethod.TOKEN.equals(authMethod) && missingPosixPrincipal
                                            && missingHTTPPrincipal;

            if (!tokenFromAPIKey) {
                checkGroupReadAccess(currentUser);
            }
        }
    }

    private void checkGroupReadAccess(final Subject currentUser) throws Exception {
        final IvoaGroupClient ivoaGroupClient = new IvoaGroupClient();
        final Set<GroupURI> allowedGroupURIs =
                PosixMapperAction.POSIX_CONFIGURATION.getProperty(PosixInitAction.ALLOWED_GROUPS_KEY)
                                                     .stream()
                                                     .map(groupURIString -> new GroupURI(URI.create(groupURIString)))
                                                     .collect(Collectors.toSet());

        Subject.doAs(currentUser, (PrivilegedExceptionAction<? extends Void>) () -> {
            if (ivoaGroupClient.getMemberships(allowedGroupURIs).isEmpty()) {
                throw new NotAuthenticatedException("Not authorized to use the POSIX Mapper service.");
            } else {
                return null;
            }
        });
    }

    protected GroupWriter getGroupWriter() throws IOException {
        final String writeContentType = setContentType();
        final Writer writer = new BufferedWriter(new OutputStreamWriter(this.syncOutput.getOutputStream()));
        if (PosixMapperAction.TSV_CONTENT_TYPE.equals(writeContentType)) {
            return new TSVGroupWriter(writer);
        } else {
            return new AsciiGroupWriter(writer);
        }
    }

    protected UserWriter getUserWriter() throws IOException {
        final String writeContentType = setContentType();
        final Writer writer = new BufferedWriter(new OutputStreamWriter(this.syncOutput.getOutputStream()));
        if (PosixMapperAction.TSV_CONTENT_TYPE.equals(writeContentType)) {
            return new TSVUserWriter(writer);
        } else {
            return new AsciiUserWriter(writer);
        }
    }

    private String setContentType() {
        final String requestContentType = syncInput.getHeader("accept");
        final String writeContentType = PosixMapperAction.TSV_CONTENT_TYPE.equals(requestContentType)
                ? PosixMapperAction.TSV_CONTENT_TYPE : "text/plain";
        this.syncOutput.addHeader("content-type", writeContentType);

        return writeContentType;
    }

    /**
     * Never used.
     * @return  null
     */
    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }
}
