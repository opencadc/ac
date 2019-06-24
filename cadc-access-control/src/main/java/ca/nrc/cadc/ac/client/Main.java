/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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

import java.net.URI;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.CertCmdArgUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.gms.GroupURI;
import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.Log4jInit;

/**
 * Prototype main class for the GMSClient.  Currently
 * only used for testing.  Should not be used for production
 * work.
 */
public class Main implements PrivilegedAction<Object>
{

    private static Logger log = Logger.getLogger(Main.class);

    public static final String ARG_ADD_MEMBER = "add-member";
    public static final String ARG_DEL_MEMBER = "remove-member";
    public static final String ARG_ADD_ADMIN = "add-admin";
    public static final String ARG_DEL_ADMIN = "remove-admin";
    public static final String ARG_CREATE_GROUP = "create";
    public static final String ARG_GET_GROUP = "get";
    public static final String ARG_DELETE_GROUP = "delete";

    public static final String ARG_GROUP = "group";

    public static final String ARG_HELP = "help";
    public static final String ARG_VERBOSE = "verbose";
    public static final String ARG_DEBUG = "debug";
    public static final String ARG_H = "h";
    public static final String ARG_V = "v";
    public static final String ARG_D = "d";

    private ArgumentMap argMap;

    private Main(ArgumentMap args)
    {
        this.argMap = args;
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

        Main main = new Main(argMap);

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

        return null;
    }

    private static void usage()
    {
        System.out.println("Usage: Group management command line tool");
        System.out.println();
        System.out.println("  --create --group=<uri>");
        System.out.println("  --get --group=<uri>");
        System.out.println("  --delete --group=<uri>");
        System.out.println();
        System.out.println("  --add-member --group=<uri> [member]...");
        System.out.println("  --remove-member --group=<uri> [member]...");
        System.out.println();
        System.out.println("  --add-admin --group=<uri> [member]...");
        System.out.println("  --remove-admin --group=<uri> [member]...");
        System.out.println();
        System.out.println("      [member] can be a userID (string) or a");
        System.out.println("      group URI in the form:");
        System.out.println("         ivo://<authority>/gms?<group>  eg:");
        System.out.println("         ivo://cadc.nrc.ca/gms?mygroup");
        System.out.println();
    }

    @Override
    public Object run()
    {
        try
        {
            String command = getCommand();
            if (command == null)
            {
                System.err.println("No valid commands.");
                System.out.println();
                usage();
                return null;
            }

            String suri = argMap.getValue(ARG_GROUP);
            if (suri == null)
                throw new IllegalArgumentException("No group specified");

            GroupURI guri = new GroupURI(new URI(suri));
            GMSClient client = new GMSClient(guri.getServiceID());
            String group = guri.getName();

            List<String> members = argMap.getPositionalArgs();

            if (command.equals(ARG_ADD_MEMBER))
            {

                if (members.isEmpty())
                    throw new IllegalArgumentException("No members specified");

                for (String member : members)
                {
                    try
                    {
                        // try creating a group URI
                        GroupURI memberURI = new GroupURI(new URI(member));
                        client.addGroupMember(group, memberURI.getName());
                    }
                    catch (IllegalArgumentException e)
                    {
                        // assume the string is a userid
                        client.addUserMember(group, new HttpPrincipal(member));
                    }
                }
            }
            else if (command.equals(ARG_DEL_MEMBER))
            {
                if (members.isEmpty())
                    throw new IllegalArgumentException("No members specified");

                for (String member : members)
                {
                    try
                    {
                        // try creating a group URI
                        GroupURI memberURI = new GroupURI(new URI(member));
                        client.removeGroupMember(group, memberURI.getName());
                    } catch (IllegalArgumentException e)
                    {
                        // assume the string is a userid
                        client.removeUserMember(group, new HttpPrincipal(member));
                    }
                }
            }
            else if (command.equals(ARG_ADD_ADMIN))
            {
                if (members.isEmpty())
                    throw new IllegalArgumentException("No members specified");

                Group cur = client.getGroup(group);
                boolean changes = false;

                for (String member : members)
                {
                    GroupURI memberURI = null;
                    HttpPrincipal hp = null;
                    try
                    {
                        // try creating a group URI
                        memberURI = new GroupURI(new URI(member));
                    }
                    catch (IllegalArgumentException e)
                    {
                        // assume the string is a userID
                        hp = new HttpPrincipal(member);
                    }

                    boolean update = true;
                    if (hp != null)
                    {
                        if (hp != null)
                        {
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
                                log.info("admin added: " + member);
                                changes = true;
                            }
                            else
                                log.info("admin found: " + member);
                        }
                        else
                        {
                            for (Group admin : cur.getGroupAdmins())
                            {
                                if (admin.getID().equals(memberURI))
                                {
                                    update = false;
                                    break;
                                }
                            }
                            if (update)
                            {
                                Group adminGroup = new Group(memberURI);
                                cur.getGroupAdmins().add(adminGroup);
                                log.info("group admin added: " + member);
                                changes = true;
                            }
                            else
                                log.info("group admin found: " + member);
                        }
                    }
                }

                if (changes)
                {
                    client.updateGroup(cur);
                    log.info("Group updated.");
                }
            }
            else if (command.equals(ARG_DEL_ADMIN))
            {
                if (members.isEmpty())
                    throw new IllegalArgumentException("No members specified");

                Group cur = client.getGroup(group);
                boolean changes = false;

                for (String member : members)
                {
                    GroupURI memberURI = null;
                    HttpPrincipal hp = null;
                    try
                    {
                        // try creating a group URI
                        memberURI = new GroupURI(new URI(member));
                    } catch (IllegalArgumentException e)
                    {
                        // assume the string is a userID
                        hp = new HttpPrincipal(member);
                    }

                    boolean update = false;
                    if (hp != null)
                    {
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
                            log.info("admin removed: " + member);
                            changes = true;
                        } else
                            log.info("admin not found: " + member);
                    }
                    else
                    {
                        Iterator<Group> iter = cur.getGroupAdmins().iterator();
                        while (iter.hasNext())
                        {
                            Group admin = iter.next();
                            if (admin.getID().equals(memberURI))
                            {
                                iter.remove();
                                update = true;
                                break;
                            }
                        }
                        if (update)
                        {
                            log.info("group admin removed: " + member);
                            changes = true;
                        } else
                            log.info("group admin not found: " + member);
                    }
                }

                if (changes)
                {
                    client.updateGroup(cur);
                    log.info("Group updated.");
                }
            }
            else if (command.equals(ARG_CREATE_GROUP))
            {
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                AccessControlContext accessControlContext = AccessController.getContext();
                Subject subject = Subject.getSubject(accessControlContext);
                Set<X500Principal> principals = subject.getPrincipals(X500Principal.class);
                X500Principal p = principals.iterator().next();

                Group g = new Group(guri);

                User member = new User();
                member.getIdentities().add(p);
                g.getUserMembers().add(member);
                client.createGroup(g);
            }
            else if (command.equals(ARG_GET_GROUP))
            {
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                Group g = client.getGroup(group);
                System.out.println("found: " + g.getID());
                if (g.description != null)
                    System.out.println("\t" + g.description);
                System.out.println("owner: " + g.getOwner());

                for (User u : g.getUserAdmins())
                    System.out.println("admin: " + u.toPrettyString());

                for (Group ga : g.getGroupAdmins())
                    System.out.println("admin: " + ga);

                for (User u : g.getUserMembers())
                    System.out.println("member: " + u.toPrettyString());

                for (Group gm : g.getGroupMembers())
                    System.out.println("member: " + gm);

            }
            else if (command.equals(ARG_DELETE_GROUP))
            {
                if (group == null)
                    throw new IllegalArgumentException("No group specified");

                client.deleteGroup(group);
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
