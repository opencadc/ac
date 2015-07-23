/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2015.                            (c) 2015.
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

package ca.nrc.cadc.ac.client;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.InputStreamWrapper;
import ca.nrc.cadc.util.StringUtil;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

public class JSONUserListInputStreamWrapper implements InputStreamWrapper
{
    private static final Logger LOGGER = Logger
            .getLogger(JSONUserListInputStreamWrapper.class);
    private final List<User<HttpPrincipal>> output;


    public JSONUserListInputStreamWrapper(
            final List<User<HttpPrincipal>> output)
    {
        this.output = output;
    }


    /**
     * Read the stream in.
     *
     * @param inputStream The stream to read from.
     * @throws IOException Any reading exceptions.
     */
    @Override
    public void read(final InputStream inputStream) throws IOException
    {
        String line = null;

        try
        {
            final InputStreamReader inReader =
                    new InputStreamReader(inputStream);
            final BufferedReader reader = new BufferedReader(inReader);

            while (StringUtil.hasText(line = reader.readLine()))
            {
                // Deal with arrays stuff.
                while (line.startsWith("[") || line.startsWith(","))
                {
                    line = line.substring(1);
                }

                while (line.endsWith("]") || line.endsWith(","))
                {
                    line = line.substring(0, (line.length() - 1));
                }

                if (StringUtil.hasText(line))
                {
                    LOGGER.debug(String.format("Reading: %s", line));

                    final JSONObject jsonObject = new JSONObject(line);
                    final User<HttpPrincipal> webUser =
                            new User<HttpPrincipal>(
                                    new HttpPrincipal(jsonObject
                                                              .getString("id")));
                    final String firstName = jsonObject.getString("firstName");
                    final String lastName = jsonObject.getString("lastName");

                    webUser.details
                            .add(new PersonalDetails(firstName, lastName));

                    output.add(webUser);
                }
            }
        }
        catch (Exception bug)
        {
            throw new IOException(bug + (StringUtil.hasText(line)
                                         ? "Error line is " + line : ""));
        }
    }
}
