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

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.server.web.WebUtil;
import ca.nrc.cadc.auth.CookiePrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityType;
import ca.nrc.cadc.auth.NumericPrincipal;
import ca.nrc.cadc.auth.OpenIdPrincipal;
import org.apache.log4j.Logger;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URL;
import java.security.Principal;


public abstract class UserActionFactory
{
    private static final Logger log = Logger.getLogger(UserActionFactory.class);

    public abstract AbstractUserAction createAction(HttpServletRequest request)
        throws IllegalArgumentException, IOException;

    public static UserActionFactory httpGetFactory()
    {
        return new UserActionFactory()
        {
            public AbstractUserAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                AbstractUserAction action = null;
                String path = request.getPathInfo();
                log.debug("path: " + path);

                String[] segments = WebUtil.getPathSegments(path);

                if (segments.length == 0)
                {
                    action = new GetUserListAction();
                }
                else if (segments.length == 1)
                {
                    User user = getUser(segments[0], request.getParameter("idType"), path);
                    action = new GetUserAction(user.getUserID(), request.getParameter("detail"));
                }

                if (action != null)
                {
                    log.debug("Returning action: " + action.getClass());
                    return action;
                }

                 throw new IllegalArgumentException("Bad GET request to " + path);
            }
        };
    }

    public static UserActionFactory httpPutFactory()
    {
        return new UserActionFactory()
        {
            public AbstractUserAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                AbstractUserAction action = null;
                String path = request.getPathInfo();
                log.debug("path: " + path);

                String[] segments = WebUtil.getPathSegments(path);

                if (segments.length == 0)
                {
                    action = new CreateUserAction(request.getInputStream());
                }

                if (action != null)
                {
                    log.debug("Returning action: " + action.getClass());
                    return action;
                }

                 throw new IllegalArgumentException("Bad PUT request to " + path);
            }
        };
    }

    public static UserActionFactory httpPostFactory()
    {
        return new UserActionFactory()
        {
            public AbstractUserAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                AbstractUserAction action = null;
                String path = request.getPathInfo();
                log.debug("path: " + path);

                String[] segments = WebUtil.getPathSegments(path);

                if (segments.length == 1)
                {
                    action = new ModifyUserAction(request.getInputStream(), request);
                }

                if (action != null)
                {
                    log.debug("Returning action: " + action.getClass());
                    return action;
                }

                 throw new IllegalArgumentException("Bad POST request to " + path);
            }
        };
    }

    public static UserActionFactory httpDeleteFactory()
    {
        return new UserActionFactory()
        {
            public AbstractUserAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                AbstractUserAction action = null;
                String path = request.getPathInfo();
                log.debug("path: " + path);

                String[] segments = WebUtil.getPathSegments(path);

                if (segments.length == 1)
                {
                    User user = getUser(segments[0], request.getParameter("idType"), path);
                    action = new DeleteUserAction(user.getUserID());
                }

                if (action != null)
                {
                    log.debug("Returning action: " + action.getClass());
                    return action;
                }

                 throw new IllegalArgumentException("Bad DELETE request to " + path);
            }
        };
    }

    public static UserActionFactory httpHeadFactory()
    {
        return new UserActionFactory()
        {
            public AbstractUserAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                // http head not supported
                throw new UnsupportedOperationException();
            }
        };
    }

    private static User<? extends Principal> getUser(final String userName,
                                                     final String idType,
                                                     final String path)
    {
        if (idType == null || idType.isEmpty())
        {
            throw new IllegalArgumentException("User endpoint missing idType parameter");
        }
        else if (idType.equalsIgnoreCase(IdentityType.USERNAME.getValue()))
        {
            return new User<HttpPrincipal>(new HttpPrincipal(userName));
        }
        else if (idType.equalsIgnoreCase(IdentityType.X500.getValue()))
        {
            return new User<X500Principal>(new X500Principal(userName));
        }
        else if (idType.equalsIgnoreCase(IdentityType.CADC.getValue()))
        {
            return new User<NumericPrincipal>(new NumericPrincipal(
                    Integer.parseInt(userName)));
        }
        else if (idType.equalsIgnoreCase(IdentityType.OPENID.getValue()))
        {
            return new User<OpenIdPrincipal>(new OpenIdPrincipal(userName));
        }
        else if (idType.equalsIgnoreCase(IdentityType.COOKIE.getValue()))
        {
            return new User<CookiePrincipal>(new CookiePrincipal(userName));
        }
        else
        {
            throw new IllegalArgumentException("Unregonized userid");
        }
    }

}
