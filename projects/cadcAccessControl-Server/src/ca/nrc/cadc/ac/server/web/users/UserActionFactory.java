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

import ca.nrc.cadc.ac.IdentityType;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.CookiePrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import ca.nrc.cadc.util.StringUtil;

import java.io.IOException;
import java.security.Principal;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;


public class UserActionFactory
{
    private static final Logger log = Logger
            .getLogger(UserActionFactory.class);

    static AbstractUserAction getUsersAction(HttpServletRequest request, UserLogInfo logInfo)
            throws IOException
    {
        AbstractUserAction action = null;
        String method = request.getMethod();
        String path = request.getPathInfo();
        log.debug("method: " + method);
        log.debug("path: " + path);

        if (path == null)
        {
            path = "";
        }

        if (path.startsWith("/"))
        {
            path = path.substring(1);
        }

        if (path.endsWith("/"))
        {
            path = path.substring(0, path.length() - 1);
        }

        String[] segments = new String[0];
        if (StringUtil.hasText(path))
        {
            segments = path.split("/");
        }

        if (segments.length == 0)
        {
            if (method.equals("GET"))
            {
                action = new GetUserListAction(logInfo);
            }
            else if (method.equals("PUT"))
            {
                action = new CreateUserAction(logInfo,
                                              request.getInputStream());
                action.setRedirectURLPrefix(request.getRequestURL().toString());
            }
        }
        else
        {
            User user = getUser(segments[0], request.getParameter("idType"),
                                method, path);
            if (method.equals("GET"))
            {
                action = new GetUserAction(logInfo, user.getUserID());
            }
            else if (method.equals("DELETE"))
            {
                action = new DeleteUserAction(logInfo, user.getUserID());
            }
            else if (method.equals("POST"))
            {
                action = new ModifyUserAction(logInfo,
                                              request.getInputStream());
                action.setRedirectURLPrefix(request.getRequestURL().toString());
            }
        }

        if (action != null)
        {
            log.debug("Returning action: " + action.getClass());
            return action;
        }
        final String error = "Bad users request: " + method + " on " + path;
        throw new IllegalArgumentException(error);
    }

    private static User<? extends Principal> getUser(final String userName,
                                                     final String idType,
                                                     final String method,
                                                     final String path)
    {
        if (idType == null || idType.isEmpty())
        {
            throw new IllegalArgumentException("User endpoint missing idType parameter");
        }
        else if (idType.equals(IdentityType.USERNAME.getValue()))
        {
            return new User<HttpPrincipal>(new HttpPrincipal(userName));
        }
        else if (idType.equals(IdentityType.X500.getValue()))
        {
            return new User<X500Principal>(new X500Principal(userName));
        }
        else if (idType.equals(IdentityType.UID.getValue()))
        {
            return new User<NumericPrincipal>(new NumericPrincipal(
                    Long.parseLong(userName)));
        }
        else if (idType.equals(IdentityType.OPENID.getValue()))
        {
            return new User<OpenIdPrincipal>(new OpenIdPrincipal(userName));
        }
        else if (idType.equals(IdentityType.COOKIE.getValue()))
        {
            return new User<CookiePrincipal>(new CookiePrincipal(userName));
        }
        else
        {
            final String error = "Bad users request: " + method + " on " + path +
                                 " because of unknown principal type " + idType;
            throw new IllegalArgumentException(error);
        }
    }

}
