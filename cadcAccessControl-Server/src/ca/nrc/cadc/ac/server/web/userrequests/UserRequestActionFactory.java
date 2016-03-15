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
package ca.nrc.cadc.ac.server.web.userrequests;

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
import java.util.UUID;


public abstract class UserRequestActionFactory
{
    private static final Logger log = Logger.getLogger(UserRequestActionFactory.class);

    public abstract AbstractUserRequestAction createAction(HttpServletRequest request)
        throws IllegalArgumentException, IOException;

    public static UserRequestActionFactory httpGetFactory()
    {
        return new UserRequestActionFactory()
        {
            public AbstractUserRequestAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                // http get not supported
                throw new UnsupportedOperationException();
            }
        };
    }

    public static UserRequestActionFactory httpPutFactory()
    {
        return new UserRequestActionFactory()
        {
            public AbstractUserRequestAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                AbstractUserRequestAction action = null;
                String path = request.getPathInfo();
                log.debug("path: " + path);

                String[] segments = WebUtil.getPathSegments(path);

                if (segments.length == 0)
                {
                    action = new CreateUserRequestAction(request.getInputStream());
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

    public static UserRequestActionFactory httpPostFactory()
    {
        return new UserRequestActionFactory()
        {
            public AbstractUserRequestAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                // http post not supported
                throw new UnsupportedOperationException();
            }
        };
    }

    public static UserRequestActionFactory httpDeleteFactory()
    {
        return new UserRequestActionFactory()
        {
            public AbstractUserRequestAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                // http delete not supported
                throw new UnsupportedOperationException();
            }
        };
    }

    public static UserRequestActionFactory httpHeadFactory()
    {
        return new UserRequestActionFactory()
        {
            public AbstractUserRequestAction createAction(HttpServletRequest request)
                throws IllegalArgumentException, IOException
            {
                // http head not supported
                throw new UnsupportedOperationException();
            }
        };
    }

    private static User getUser(String userName, String idType)
    {
        User user = new User();
        if (idType == null || idType.isEmpty())
        {
            throw new IllegalArgumentException("User endpoint missing idType parameter");
        }
        else if (idType.equalsIgnoreCase(IdentityType.USERNAME.getValue()))
        {
            user.getIdentities().add(new HttpPrincipal(userName));
        }
        else if (idType.equalsIgnoreCase(IdentityType.X500.getValue()))
        {
            user.getIdentities().add(new X500Principal(userName));
        }
        else if (idType.equalsIgnoreCase(IdentityType.CADC.getValue()))
        {
            user.getIdentities().add(new NumericPrincipal(UUID.fromString(userName)));
        }
        else if (idType.equalsIgnoreCase(IdentityType.OPENID.getValue()))
        {
            user.getIdentities().add(new OpenIdPrincipal(userName));
        }
        else if (idType.equalsIgnoreCase(IdentityType.COOKIE.getValue()))
        {
            user.getIdentities().add(new CookiePrincipal(userName));
        }
        else
        {
            throw new IllegalArgumentException("Unregonized userid");
        }
        return user;
    }

}
