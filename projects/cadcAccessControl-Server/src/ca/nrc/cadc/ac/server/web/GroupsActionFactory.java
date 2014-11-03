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
package ca.nrc.cadc.ac.server.web;

import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import ca.nrc.cadc.util.StringUtil;

public class GroupsActionFactory
{
    private static final Logger log = Logger.getLogger(GroupsActionFactory.class);

    static GroupsAction getGroupsAction(HttpServletRequest request, GroupLogInfo logInfo)
        throws IOException
    {
        GroupsAction action = null;
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
                action = new GetGroupNamesAction(logInfo);
            }
            else if (method.equals("PUT"))
            {
                action = new CreateGroupAction(logInfo, request.getInputStream());
            }

        }
        else if (segments.length == 1)
        {
            String groupName = segments[0];
            if (method.equals("GET"))
            {
                action = new GetGroupAction(logInfo, groupName);
            }
            else if (method.equals("DELETE"))
            {
                action = new DeleteGroupAction(logInfo, groupName);
            }
            else if (method.equals("POST"))
            {
                final URL requestURL =
                        new URL(request.getRequestURL().toString());
                final String redirectURI = requestURL.getProtocol() + "://"
                                           + requestURL.getHost() + ":"
                                           + requestURL.getPort()
                                           + request.getContextPath()
                                           + request.getServletPath()
                                           + "/" + path;
                action = new ModifyGroupAction(logInfo, groupName, redirectURI,
                                               request.getInputStream());
            }
        }
        else if (segments.length == 3)
        {
            String groupName = segments[0];
            String memberCategory = segments[1];
            if (method.equals("PUT"))
            {
                if (memberCategory.equals("groupMembers"))
                {
                    String groupMemberName = segments[2];
                    action = new AddGroupMemberAction(logInfo, groupName, groupMemberName);
                }
                else if (memberCategory.equals("userMembers"))
                {
                    String userMemberID = URLDecoder.decode(segments[2], "UTF-8");
                    String userMemberIDType = request.getParameter("idType");
                    action = new AddUserMemberAction(logInfo, groupName, userMemberID, userMemberIDType);
                }
            }
            else if (method.equals("DELETE"))
            {
                if (memberCategory.equals("groupMembers"))
                {
                    String groupMemberName = segments[2];
                    action = new RemoveGroupMemberAction(logInfo, groupName, groupMemberName);
                }
                else if (memberCategory.equals("userMembers"))
                {
                    String memberUserID = URLDecoder.decode(segments[2], "UTF-8");
                    String memberUserIDType = request.getParameter("idType");
                    action = new RemoveUserMemberAction(logInfo, groupName, memberUserID, memberUserIDType);
                }
            }
        }

        if (action != null)
        {
            return action;
        }
        throw new IllegalArgumentException("Bad groups request: " + method + " on " + path);
    }

}
