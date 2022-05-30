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
 ************************************************************************
 */
package ca.nrc.cadc.ac.server.oidc;

import ca.nrc.cadc.rest.InlineContentHandler;
import ca.nrc.cadc.rest.RestAction;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;
import java.io.OutputStreamWriter;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.security.KeyFactory;

import org.apache.log4j.Logger;

/**
 * This class responds to HTTP GET calls and returns the public key used to decrypt
 * signed JWTs.
 * 
 * @author majorb
 *
 */
public class PublicKeyAction extends RestAction {
    
    private static final Logger log = Logger.getLogger(PublicKeyAction.class);
    private static final String KID = UUID.randomUUID().toString();

    @Override
    public void doAction() throws Exception {
        log.debug("returning public key as jwks");

        Set<PublicKey> pubKeys = OIDCUtil.getPublicKeys();
        RSAPublicKey key = ((RSAPublicKey) pubKeys.iterator().next());

        // This code uses nimbus library
        JWK jwk = new RSAKey.Builder(key)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(KID)
            .build();
        String jwkJSON = jwk.toPublicJWK().toJSONString();

        // -----------------------------------------------------------------
        // This code is/was the first attempt to replace nimbus code with CADC code,
        // in order to use java Base64.encode methods to build the JWK
//        StringBuilder json = new StringBuilder();
        //        JWK jwk = new CadcJWKBuilder.Builder(key)
//            .keyUse(KeyUse.SIGNATURE)
//            .keyID(KID)
//            .algorithm(JWSAlgorithm.RS256)
//            .build();

//        String jwkJson = jwk.toPublicJWK().toJSONString();

//        String jwkJson = buildJWK(key);

        // -----------------------------------------------------------------
        // This code was a start into building JSON for the key manually.
        // It's not clear how to encode 'n' properly yet.,
        // May 30/22: stopped work on this section part way through in order to
        // revert back to a 'last known good' version using the nimbus library
        // so draft branch could be checked in.
//        response: {  "keys": [

//        StringBuilder jwkJSON = new StringBuilder();
        // {"kty":"RSA","e":"AQAB","use":"sig","kid":"4dc4b6e5-71fc-4e85-9862-5acd1e707d7d","alg":"RS256","n":"sc73IJCnuaob7BB1JlWnDbkwMe7B5VsGKXSXO9HxtI-DaYjwc9LNRpIq-x4N3biN1cknat-ZBjYoWgWpT4KBZvNd1f8hQM-9BqDcEgwoQL8DotYiZJ0trvba_BC8wOwNNbMrUT-mHkba3lqb3jJNgRf5NXmIL1BbmtoB3jepi1q48ZQK-Njt7KFLUjwgsmYvPQ0BYjYE0iU9qD-JwWJrlrjitx4qM_XiWjNNOW_hbIZqtjNh6EN0KytwHWLKsZouPyH3-MzSD6Se7N5JAQ1_J5OFlAB-CHFLbylSd6_6Pi3zSm3t3xXJ-61kDHnscYlbRea0e7-b00z5a2tSvcQ_cQ"}  ]}

//        jwkJSON.append("{\"kty\":\"RSA\",\"use\":\"sig\",");
//        jwkJSON.append("\"alg\":\"RSA\"");
//        jwkJSON.append("\"kid\":\"");
//        jwkJSON.append(KID);
//        jwkJSON.append("\",\"");
//        jwkJSON.append("\"n\":\"");

//        byte[] nBytes = Base64.getUrlEncoder().encode(BigIntegerUtils.toBytesUnsigned(key.getModulus()));
//        jwkJSON.append(nBytes.toString());
//        jwkJSON.append("\",\"");
//        byte[] eBytes = Base64.getUrlEncoder().encode(BigIntegerUtils.toBytesUnsigned(key.getPublicExponent()));


//        jwkJSON.append(KID);
//        jwkJSON.append("\",\"");


        // -----------------------------------------------------------------
        // Original return code that builds JSON envelope to return JWKS from service
        StringBuilder json = new StringBuilder();

        json.append("{");
        json.append("  \"keys\": [");
        json.append(jwkJSON);
        json.append("  ]");
        json.append("}");

        log.debug("JWKS:\n" + json.toString());
        syncOutput.setHeader("Content-Type", "application/json");
        OutputStreamWriter out = new OutputStreamWriter(syncOutput.getOutputStream());
        out.write(json.toString());
        out.flush();
    }



    @Override
    protected InlineContentHandler getInlineContentHandler() {
        return null;
    }
}