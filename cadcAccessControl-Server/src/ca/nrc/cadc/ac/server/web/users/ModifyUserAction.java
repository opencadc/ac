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
package ca.nrc.cadc.ac.server.web.users;

import java.io.InputStream;
import java.net.URL;
import java.security.Principal;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.CookiePrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityType;
import ca.nrc.cadc.auth.NumericPrincipal;


public class ModifyUserAction extends AbstractUserAction
{
    private static final Logger log = Logger.getLogger(ModifyUserAction.class);

    private final InputStream inputStream;
    private final HttpServletRequest request;


    ModifyUserAction(final InputStream inputStream, final HttpServletRequest request)
    {
        super();

        this.inputStream = inputStream;
        this.request = request;
    }


    public void doAction() throws Exception
    {
        final User user = readUser(this.inputStream);
        final User modifiedUser = userPersistence.modifyUser(user);
        logUserInfo(modifiedUser.getHttpPrincipal().getName());

        final URL requestURL = new URL(request.getRequestURL().toString());
        final StringBuilder sb = new StringBuilder();
        sb.append(requestURL.getProtocol());
        sb.append("://");
        sb.append(requestURL.getHost());
        if (requestURL.getPort() > 0)
        {
            sb.append(":");
            sb.append(requestURL.getPort());
        }
        sb.append(request.getContextPath());
        sb.append(request.getServletPath());
        sb.append(request.getPathInfo());
        sb.append("?idType=");

        // Need to find the principal type for this userID
        String idType = null;
        for (Principal principal : user.getIdentities())
        {
            if (principal.getName().equals(modifiedUser.getHttpPrincipal().getName()))
            {
                if (principal instanceof HttpPrincipal)
                {
                    idType = IdentityType.USERNAME.getValue();
                }
                else if (principal instanceof X500Principal)
                {
                    idType = IdentityType.X500.getValue();
                }
                else if (principal instanceof NumericPrincipal)
                {
                    idType = IdentityType.CADC.getValue();
                }
                else if (principal instanceof CookiePrincipal)
                {
                    idType = IdentityType.COOKIE.getValue();
                }
            }
        }

        if (idType == null)
        {
            throw new IllegalArgumentException(
                "Bad POST request to " + request.getServletPath() +
                    " because unknown userID Principal");
        }

        sb.append(idType);

        final String redirectUrl = sb.toString();
        log.debug("redirect URL: " + redirectUrl);

        syncOut.setHeader("Location", redirectUrl);
        syncOut.setCode(303);
    }

}
