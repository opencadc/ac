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

package org.opencadc.permissions;

import ca.nrc.cadc.util.Base64;
import ca.nrc.cadc.util.RsaSignatureGenerator;
import ca.nrc.cadc.util.RsaSignatureVerifier;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.AccessControlException;
import java.security.InvalidKeyException;
import org.apache.log4j.Logger;

/**
 * Utilities the generation and validation of pre-authorized tokens for artifact
 * download and upload.
 *
 * @author majorb
 */
public class TokenTool {

    private static final Logger log = Logger.getLogger(TokenTool.class);

    private static final String KEY_META_URI = "uri";
    private static final String KEY_META_GRANT = "gnt";
    private static final String KEY_META_SUBJECT = "sub";

    private final RsaSignatureGenerator sg;
    private final RsaSignatureVerifier sv;

    private static final String TOKEN_DELIM = "~";

    /**
     * Constructor for a TokenTool that can validate tokens.
     *
     * @param publicKey public key file to validate
     */
    public TokenTool(File publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }
        this.sv = new RsaSignatureVerifier(publicKey);
        this.sg = null;
    }

    /**
     * Constructor for a TokenTool that can generate and validate tokens.
     *
     * @param publicKey  public key file to validate
     * @param privateKey private key file to generate
     */
    public TokenTool(File publicKey, File privateKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey cannot be null");
        }
        this.sv = new RsaSignatureVerifier(publicKey);
        ;
        this.sg = new RsaSignatureGenerator(privateKey);
    }

    public TokenTool(byte[] publicKey) {
        this.sv = new RsaSignatureVerifier(publicKey);
        this.sg = null;
    }

    public TokenTool(byte[] publicKey, byte[] privateKey) {
        this.sv = new RsaSignatureVerifier(publicKey);
        ;
        this.sg = new RsaSignatureGenerator(privateKey);
    }


    /**
     * Generate an artifact token given the input parameters.
     *
     * @param uri        The artifact URI
     * @param grantClass The grant to be applied to the artifact.
     * @param user       The user initiating the action on the artifact.
     * @return A pre-authorized signed token.
     */
    public String generateToken(URI uri, Class<? extends Grant> grantClass, String user) {
        if (sg == null) {
            throw new IllegalStateException("cannot generate token: no private key");
        }

        log.debug("[TokenTool.generateToken]: uri: " + uri);
        log.debug("[TokenTool.generateToken]: grant: " + grantClass);
        log.debug("[TokenTool.generateToken]: subject: " + user);

        // create the metadata and signature segments
        StringBuilder metaSb = new StringBuilder();
        metaSb.append(KEY_META_URI).append("=").append(uri.toString());
        metaSb.append("&");
        metaSb.append(KEY_META_GRANT).append("=").append(grantClass.getSimpleName());
        if (user != null) {
            metaSb.append("&");
            metaSb.append(KEY_META_SUBJECT).append("=").append(user);
        }
        byte[] metaBytes = metaSb.toString().getBytes();


        String sig;
        try {
            byte[] sigBytes = sg.sign(new ByteArrayInputStream(metaBytes));
            sig = new String(Base64.encode(sigBytes));
            log.debug("Created signature: " + sig + " for meta: " + metaSb.toString());
        } catch (InvalidKeyException | IOException | RuntimeException e) {
            throw new IllegalStateException("Could not sign token", e);
        }
        String meta = new String(Base64.encode(metaBytes));
        log.debug("meta: " + meta);
        log.debug("sig: " + sig);

        // build the token
        StringBuilder token = new StringBuilder();
        String metaURLEncoded = base64URLEncode(meta);
        String sigURLEncoded = base64URLEncode(sig);

        log.debug("metaURLEncoded: " + metaURLEncoded);
        log.debug("sigURLEncoded: " + sigURLEncoded);

        token.append(metaURLEncoded);
        token.append(TOKEN_DELIM);
        token.append(sigURLEncoded);
        log.debug("Created token path: " + token.toString());

        return token.toString();
    }

    /**
     * Validate the given token with the expectations expressed in the parameters.
     *
     * @param token              The token to validate.
     * @param expectedURI        The expected artifact URI.
     * @param expectedGrantClass one or more expected grant types (single match is valid)
     * @return The user contained in the token.
     * @throws AccessControlException If any of the expectations are not met or if the token is invalid.
     * @throws IOException            If a processing error occurs.
     */
    public String validateToken(String token, URI expectedURI, Class<? extends Grant>... expectedGrantClass)
            throws AccessControlException, IOException {

        log.debug("validating token: " + token);
        String[] parts = token.split(TOKEN_DELIM);
        if (parts.length != 2) {
            log.debug("invalid format, not two parts");
            throw new AccessControlException("Invalid auth token");
        }

        byte[] metaBytes = Base64.decode(base64URLDecode(parts[0]));
        byte[] sigBytes = Base64.decode(base64URLDecode(parts[1]));

        boolean verified;
        try {
            verified = sv.verify(new ByteArrayInputStream(metaBytes), sigBytes);
        } catch (InvalidKeyException | RuntimeException e) {
            log.debug("Received invalid signature", e);
            throw new AccessControlException("Invalid auth token");
        }
        if (!verified) {
            log.debug("verified==false");
            throw new AccessControlException("Invalid auth token");
        }

        String[] metaParams = new String(metaBytes).split("&");
        String uri = null;
        String grant = null;
        String user = null;
        for (String metaParam : metaParams) {
            log.debug("Processing param: " + metaParam);
            int eqIndex = metaParam.indexOf("=");
            if (eqIndex < 2) {
                log.debug("invalid param key/value pair");
                throw new AccessControlException("Invalid auth token");
            }
            String key = metaParam.substring(0, eqIndex);
            String value = metaParam.substring(eqIndex + 1);
            if (KEY_META_URI.equals(key)) {
                uri = value;
            }
            if (KEY_META_GRANT.equals(key)) {
                grant = value;
            }
            if (KEY_META_SUBJECT.equals(key)) {
                user = value;
            }
        }
        log.debug("[TokenTool.validateToken]: uri: " + uri);
        log.debug("[TokenTool.validateToken]: grant: " + grant);
        log.debug("[TokenTool.validateToken]: subject: " + user);

        if (!expectedURI.toString().equals(uri)) {
            log.debug("[TokenTool.validateToken]: wrong target uri: " + uri + " - expected URI: " + expectedURI.toString());
            throw new AccessControlException("Invalid auth token");
        }
        boolean grantMatch = false;
        for (Class<? extends Grant> c : expectedGrantClass) {
            grantMatch = grantMatch || c.getSimpleName().equals(grant);
            log.debug("grant class from token: " + c.getSimpleName());
        }
        if (!grantMatch) {
            log.debug("[TokenTool.validateToken]: wrong grant class: " + grant);
            throw new AccessControlException("Invalid auth token");
        }

        // validation passed, return the user for logging
        return user;

    }

    /**
     * Make a base 64 string safe for URLs.
     *
     * @param s The string to encode.
     * @return The encoded string.
     */
    static String base64URLEncode(String s) {
        if (s == null) {
            return null;
        }
        return s.replace("/", "-").replace("+", "_");
    }

    /**
     * Decode a URL encoded base 64 string.
     *
     * @param s The string to decode.
     * @return The decoded string.
     */
    static String base64URLDecode(String s) {
        if (s == null) {
            return null;
        }
        return s.replace("_", "+").replace("-", "/");
    }

}
