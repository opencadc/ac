/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2020.                            (c) 2020.
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
 ************************************************************************
 */
package ca.nrc.cadc.ac.server.oidc;

import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.rest.InlineContentException;
import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.xml.JsonInputter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

import org.apache.log4j.Logger;
import org.jdom2.Document;
import org.jdom2.Element;

/**
 * @author majorb
 *
 */
public class AuthorizePostAction extends AuthorizeAction implements InlineContentHandler {
    
    private static final Logger log = Logger.getLogger(AuthorizePostAction.class);
    private static final String CONTENT_JSON = "json";

    @Override
    public void loadRequestInput() {
        String json = (String) syncInput.getContent(CONTENT_JSON);
        if (json == null) {
            return;
        }
        JsonInputter jsonInputter = new JsonInputter();
        Document document = jsonInputter.input(json);
        Element root = document.getRootElement();
        List<Element> children = root.getChildren();
        String name = null;
        String value = null;
        for (Element child : children) {
            name = child.getName();
            value = child.getValue();
            if ("scope".equals(name)) {
                scope = value;
            }
            if ("response_type".equals(name)) {
                responseType = value;
            }
            if ("client_id".equals(name)) {
                clientID = value;
            }
            if ("redirect_uri".equals(name)) {
                redirectURI = value;
            }
            if ("state".equals(name)) {
                state = value;
            }
            if ("response_mode".equals(name)) {
                responseMode = value;
            }
            if ("nonce".equals(name)) {
                nonce = value;
            }
            if ("display".equals(name)) {
                display = value;
            }
            if ("prompt".equals(name)) {
                prompt = value;
            }
            if ("max_age".equals(name)) {
                maxAge = value;
            }
            if ("ui_locales".equals(name)) {
                uiLocales = value;
            }
            if ("id_token_hint".equals(name)) {
                idTokenHint = value;
            }
            if ("login_hint".equals(name)) {
                loginHint = value;
            }
        }
    }
    
    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return this;
    }

    @Override
    public Content accept(String name, String contentType, InputStream inputStream)
            throws InlineContentException, IOException, ResourceNotFoundException {
        
        log.debug("Content-Type: " + contentType);
        if ("application/json".equals(contentType)) {
            InputStreamReader inReader = new InputStreamReader(inputStream);
            BufferedReader bufReader = new BufferedReader(inReader);
            StringBuilder jsonBuilder = new StringBuilder();
            int i = 0;
            while ((i = bufReader.read()) != -1) {
                jsonBuilder.append(i);
            }
            String json = jsonBuilder.toString();
            log.debug("JSON: " + json);
            Content content = new Content();
            content.name = CONTENT_JSON;
            content.value = json;
            return content;
        }
        return null;
    }

}
