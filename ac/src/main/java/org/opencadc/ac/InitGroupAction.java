/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026.                            (c) 2026.
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

package org.opencadc.ac;

import ca.nrc.cadc.ac.server.web.UserServlet;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.rest.InitAction;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

public class InitGroupAction extends InitAction {
    private static final Logger log = Logger.getLogger(InitGroupAction.class);

    private String jndiConfigKey;

    public InitGroupAction() {
        super();
    }

    @Override
    public void doInit() {
        log.info("initConfig: START");
        // set init initConfig, used by subsequent init methods
        // TODO - call default GroupsConfig ctor when init privileged subjects from gms.properties
        GroupsConfig config = new GroupsConfig(getPrivilegedSubjectsFromServletConfig());
        jndiConfigKey = appName + "-" + GroupsConfig.class.getName();
        try {
            Context ctx = new InitialContext();
            try {
                ctx.unbind(jndiConfigKey);
            } catch (NamingException ignore) {
                log.debug("unbind previous JNDI key (" + jndiConfigKey + ") failed... ignoring");
            }
            ctx.bind(jndiConfigKey, config);

            log.info("created JNDI key: " + jndiConfigKey + " object: " + config.getClass().getName());
        } catch (Exception ex) {
            log.error("Failed to create JNDI Key " + jndiConfigKey, ex);
        }
        log.info("initConfig: OK");
    }

    @Override
    public void doShutdown() {
        super.doShutdown();
        try {
            Context ctx = new InitialContext();
            ctx.unbind(jndiConfigKey);
        } catch (NamingException ex) {
            log.debug("failed to remove config from JNDI", ex);
        }
    }

    // get config from JNDI
    static GroupsConfig getConfig(String appName) {
        String key = appName + "-" + GroupsConfig.class.getName();
        try {
            Context ctx = new InitialContext();
            return (GroupsConfig) ctx.lookup(key);
        } catch (NamingException ex) {
            throw new RuntimeException("BUG: failed to get config from JNDI", ex);
        }
    }

    protected List<Subject> getPrivilegedSubjectsFromServletConfig() {
        List<Subject> result = new ArrayList<>();
        String contextName = UserServlet.class.getName().replace("UserServlet", "GroupServlet");
        String x500Users = initParams.get(contextName + ".PrivilegedX500Principals");
        log.debug("PrivilegedX500Users: " + x500Users);

        String httpUsers = initParams.get(contextName + ".PrivilegedHttpPrincipals");
        log.debug("PrivilegedHttpUsers: " + httpUsers);

        List<String> x500List = new ArrayList<String>();
        List<String> httpList = new ArrayList<String>();
        if (x500Users != null && httpUsers != null) {
            Pattern pattern = Pattern.compile("([^\"]\\S*|\".+?\")\\s*");
            Matcher x500Matcher = pattern.matcher(x500Users);
            Matcher httpMatcher = pattern.matcher(httpUsers);

            while (x500Matcher.find()) {
                String next = x500Matcher.group(1);
                x500List.add(next.replace("\"", ""));
            }

            while (httpMatcher.find()) {
                String next = httpMatcher.group(1);
                httpList.add(next.replace("\"", ""));
            }

            if (x500List.size() != httpList.size()) {
                throw new RuntimeException("Init exception: Lists of augment subject principals not equivalent in length");
            }

            for (int i = 0; i < x500List.size(); i++) {
                Subject s = new Subject();
                s.getPrincipals().add(new X500Principal(x500List.get(i)));
                s.getPrincipals().add(new HttpPrincipal(httpList.get(i)));
                result.add(s);
            }

        } else {
            log.warn("No Privileged users configured.");
        }
        return result;
    }

}
