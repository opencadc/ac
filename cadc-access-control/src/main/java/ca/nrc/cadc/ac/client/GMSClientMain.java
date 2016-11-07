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

package ca.nrc.cadc.ac.client;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupURI;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.CertCmdArgUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.Log4jInit;

/**
 * Prototype main class for the GMSClient.  Currently
 * only used for testing.  Should not be used for production
 * work.
 */
public class GMSClientMain implements PrivilegedAction<Object>
{

    private static Logger log = Logger.getLogger(GMSClientMain.class);

    public static final String ARG_ADD_MEMBER = "add-member";
    public static final String ARG_DEL_MEMBER = "remove-member";
    public static final String ARG_ADD_ADMIN = "add-admin";
    public static final String ARG_DEL_ADMIN = "remove-admin";
    public static final String ARG_CREATE_GROUP = "create";
    public static final String ARG_GET_GROUP = "get";
    public static final String ARG_DELETE_GROUP = "delete";

    public static final String ARG_USERID = "userid";
    public static final String ARG_GROUP = "group";

    public static final String ARG_HELP = "help";
    public static final String ARG_VERBOSE = "verbose";
    public static final String ARG_DEBUG = "debug";
    public static final String ARG_H = "h";
    public static final String ARG_V = "v";
    public static final String ARG_D = "d";

    private GMSClient client;
    private ArgumentMap argMap;

    private GMSClientMain()
    {
        client = new GMSClient();
    }

    public static void main(String[] args)
    {
        ArgumentMap argMap = new ArgumentMap(args);

        if (argMap.isSet(ARG_HELP) || argMap.isSet(ARG_H))
        {
            usage();
            System.exit(0);
        }

        // Set debug mode
        if (argMap.isSet(ARG_DEBUG) || argMap.isSet(ARG_D))
        {
            Log4jInit.setLevel("ca.nrc.cadc.ac.client", Level.DEBUG);
            Log4jInit.setLevel("ca.nrc.cadc.net", Level.DEBUG);
        }
        else if (argMap.isSet(ARG_VERBOSE) || argMap.isSet(ARG_V))
        {
            Log4jInit.setLevel("ca.nrc.cadc.ac.client", Level.INFO);
        }
        else
            Log4jInit.setLevel("ca", Level.WARN);

        GMSClientMain main = new GMSClientMain();
        main.argMap = argMap;

        Subject subject = CertCmdArgUtil.initSubject(argMap, true);

        final Object response;

        if (subject != null)
            response = Subject.doAs(subject, main);
        else
            response = main.run();

        log.debug("Response: " + response);
    }

    private String getCommand()
    {
        if (argMap.isSet(ARG_ADD_MEMBER))
            return ARG_ADD_MEMBER;

        if (argMap.isSet(ARG_CREATE_GROUP))
            return ARG_CREATE_GROUP;

        if (argMap.isSet(ARG_GET_GROUP))
            return ARG_GET_GROUP;

        if (argMap.isSet(ARG_DELETE_GROUP))
            return ARG_DELETE_GROUP;

        if (argMap.isSet(ARG_DEL_MEMBER))
            return ARG_DEL_MEMBER;

        if (argMap.isSet(ARG_ADD_ADMIN))
            return ARG_ADD_ADMIN;

        if (argMap.isSet(ARG_DEL_ADMIN))
            return ARG_DEL_ADMIN;

        throw new IllegalArgumentException("No valid commands");
    }

    private static void usage()
    {
        System.out.println("--create --group=<g>");
        System.out.println("--get --group=<g>");
        System.out.println("--delete --group=<g>");
        System.out.println();
        System.out.println("--add-member --group=<g> --userid=<u>");
        System.out.println("--remove-member --group=<g> --userid=<u>");
        System.out.println();
        System.out.println("--add-admin --group=<g> --userid=<u>");
        System.out.println("--remove-admin --group=<g> --userid=<u>");
    }

    @Override
    public Object run()
    {
        try
        {
            String command = getCommand();

            GroupURI groupID = null;

            if (command.equals(ARG_ADD_MEMBER))
            {
                String group = argMap.getValue(ARG_GROUP);
                String userID = argMap.getValue(ARG_USERID);

                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                if (userID == null)
                    throw new IllegalArgumentException("No userid specified");

                client.addUserMember(new GroupURI(group), new HttpPrincipal(userID));
            }
            else if (command.equals(ARG_DEL_MEMBER))
            {
                String group = argMap.getValue(ARG_GROUP);
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                String member = argMap.getValue(ARG_USERID);
                if (member == null)
                    throw new IllegalArgumentException("No user specified");

                client.removeUserMember(new GroupURI(group), new HttpPrincipal(member));
            }
            else if (command.equals(ARG_ADD_ADMIN))
            {
                String group = argMap.getValue(ARG_GROUP);
                String userID = argMap.getValue(ARG_USERID);

                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                if (userID == null)
                    throw new IllegalArgumentException("No userid specified");
                HttpPrincipal hp = new HttpPrincipal(userID);

                Group cur = client.getGroup(new GroupURI(group));
                boolean update = true;
                for (User admin : cur.getUserAdmins())
                {
                    for (Principal p : admin.getIdentities())
                    {
                        if (p instanceof HttpPrincipal)
                        {
                            HttpPrincipal ahp = (HttpPrincipal) p;
                            if (hp.equals(ahp))
                            {
                                update = false;
                                break;
                            }
                        }
                    }
                }

                if (update)
                {
                    User adminUser = new User();
                    adminUser.getIdentities().add(hp);
                    cur.getUserAdmins().add(adminUser);
                    client.updateGroup(cur);
                    log.info("admin added: " + userID);
                }
                else
                    log.info("admin found: " + userID);
            }
            else if (command.equals(ARG_DEL_ADMIN))
            {
                String group = argMap.getValue(ARG_GROUP);
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                String userID = argMap.getValue(ARG_USERID);
                if (userID == null)
                    throw new IllegalArgumentException("No user specified");
                HttpPrincipal hp = new HttpPrincipal(userID);

                Group cur = client.getGroup(new GroupURI(group));
                boolean update = false;
                Iterator<User> iter = cur.getUserAdmins().iterator();
                while (iter.hasNext())
                {
                    User admin = iter.next();
                    for (Principal p : admin.getIdentities())
                    {
                        if (p instanceof HttpPrincipal)
                        {
                            HttpPrincipal ahp = (HttpPrincipal) p;
                            if (hp.equals(ahp))
                            {
                                iter.remove();
                                update = true;
                                break;
                            }
                        }
                    }
                }
                if (update)
                {
                    client.updateGroup(cur);
                    log.info("admin removed: " + userID);
                }
                else
                    log.info("admin not found: " + userID);
            }
            else if (command.equals(ARG_CREATE_GROUP))
            {
                String group = argMap.getValue(ARG_GROUP);
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                GroupURI groupURI = null;
                try
                {
                    groupURI = new GroupURI(group);
                }
                catch (Exception e)
                {
                    String message = "Invalid group URI format '" +
                        group + "': " + e.getMessage();
                    log.debug(message, e);
                    throw new IllegalArgumentException(message);
                }

                AccessControlContext accessControlContext = AccessController.getContext();
                Subject subject = Subject.getSubject(accessControlContext);
                Set<X500Principal> principals = subject.getPrincipals(X500Principal.class);
                X500Principal p = principals.iterator().next();

                Group g = new Group(groupURI);

                User member = new User();
                member.getIdentities().add(p);
                g.getUserMembers().add(member);
                client.createGroup(g);
            }
            else if (command.equals(ARG_GET_GROUP))
            {
                String group = argMap.getValue(ARG_GROUP);
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                Group g = client.getGroup(new GroupURI(group));
                System.out.println("found: " + g.getID());
                System.out.println("\t" + g.description);
                System.out.println("owner: " + g.getOwner());

                for (User u : g.getUserAdmins())
                    System.out.println("admin: " + u);

                for (Group ga : g.getGroupAdmins())
                    System.out.println("admin: " + ga);

                for (User u : g.getUserMembers())
                    System.out.println("member: " + u);

                for (Group gm : g.getGroupMembers())
                    System.out.println("member: " + gm);

            }
            else if (command.equals(ARG_DELETE_GROUP))
            {
                String group = argMap.getValue(ARG_GROUP);
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                client.deleteGroup(new GroupURI(group));
            }

            return null;
        }
        catch (Throwable t)
        {
            log.error("ERROR", t);
            return t;
        }
    }
}
