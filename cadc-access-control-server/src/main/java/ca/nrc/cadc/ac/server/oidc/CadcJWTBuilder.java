

/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ca.nrc.cadc.ac.server.oidc;

import ca.nrc.cadc.util.RsaSignatureGenerator;
import ca.nrc.cadc.util.RsaSignatureGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.impl.crypto.DefaultJwtSigner;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.impl.lang.LegacyServices;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

/**
 * CADC adaptation the nimbus library DefaultJWTBuilder code, that leverages that library's
 * base JWT-related classes (Header, Claims, etc,) - and replaces the 'compact()' method with
 * CADC tools for doing RSA signatures
 */
public class CadcJWTBuilder implements JwtBuilder {
    private static Logger log = Logger.getLogger(CadcJWTBuilder.class);

    private Header header;
    private Claims claims;
    private String payload;

    private SignatureAlgorithm algorithm;
    private Key key;

//    private Serializer<Map<String,?>> serializer;

//     Replace this encoder with the java.util.Base64 encoder
    // TODO: remove this when signer is replaced with our code
//    private Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;

    private CompressionCodec compressionCodec;
    private RsaSignatureGenerator rsaSignatureGenerator;

    // *Maybe* a wrapper class rather than using this directly is better,
    // but this removes some extra nimbus library complexity
    // TODO: remove prior comment if this proven to work more simply
    private ObjectMapper jacksonObjMapper;
    private Base64.Encoder b64Encoder;

    public CadcJWTBuilder (RsaSignatureGenerator rsaSigGen) {
        super();
        this.rsaSignatureGenerator = rsaSigGen;
        this.jacksonObjMapper = new ObjectMapper();
        this.b64Encoder = Base64.getUrlEncoder();
    }



    @Override
    public JwtBuilder setHeader(Header header) {
        this.header = header;
        return this;
    }

    @Override
    public JwtBuilder setHeader(Map<String, Object> header) {
        this.header = new DefaultHeader(header);
        return this;
    }

    @Override
    public JwtBuilder setHeaderParams(Map<String, Object> params) {
        if (!Collections.isEmpty(params)) {

            Header header = ensureHeader();

            for (Map.Entry<String, Object> entry : params.entrySet()) {
                header.put(entry.getKey(), entry.getValue());
            }
        }
        return this;
    }

    protected Header ensureHeader() {
        if (this.header == null) {
            this.header = new DefaultHeader();
        }
        return this.header;
    }

    @Override
    public JwtBuilder setHeaderParam(String name, Object value) {
        ensureHeader().put(name, value);
        return this;
    }

    @Override
    public JwtBuilder signWith(Key key) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        SignatureAlgorithm alg = SignatureAlgorithm.forSigningKey(key);
        return signWith(key, alg);
    }

    @Override
    public JwtBuilder signWith(Key key, SignatureAlgorithm alg) throws InvalidKeyException {
        Assert.notNull(key, "Key argument cannot be null.");
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        alg.assertValidSigningKey(key); //since 0.10.0 for https://github.com/jwtk/jjwt/issues/334
        this.algorithm = alg;
        this.key = key;
        return this;
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, byte[] secretKeyBytes) throws InvalidKeyException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notEmpty(secretKeyBytes, "secret key byte array cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        SecretKey key = new SecretKeySpec(secretKeyBytes, alg.getJcaName());
        return signWith(key, alg);
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, String base64EncodedSecretKey) throws InvalidKeyException {
        Assert.hasText(base64EncodedSecretKey, "base64-encoded secret key cannot be null or empty.");
        Assert.isTrue(alg.isHmac(), "Base64-encoded key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.");
        byte[] bytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return signWith(alg, bytes);
    }

    @Override
    public JwtBuilder signWith(SignatureAlgorithm alg, Key key) {
        return signWith(key, alg);
    }

    @Override
    public JwtBuilder compressWith(CompressionCodec compressionCodec) {
        Assert.notNull(compressionCodec, "compressionCodec cannot be null");
        this.compressionCodec = compressionCodec;
        return this;
    }

    @Override
    public JwtBuilder setPayload(String payload) {
        this.payload = payload;
        return this;
    }

    protected Claims ensureClaims() {
        if (this.claims == null) {
            this.claims = new DefaultClaims();
        }
        return this.claims;
    }

    @Override
    public JwtBuilder setClaims(Claims claims) {
        this.claims = claims;
        return this;
    }

    @Override
    public JwtBuilder setClaims(Map<String, ?> claims) {
        this.claims = new DefaultClaims(claims);
        return this;
    }

    @Override
    public JwtBuilder addClaims(Map<String, Object> claims) {
        ensureClaims().putAll(claims);
        return this;
    }

    @Override
    public JwtBuilder setIssuer(String iss) {
        if (Strings.hasText(iss)) {
            ensureClaims().setIssuer(iss);
        } else {
            if (this.claims != null) {
                claims.setIssuer(iss);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setSubject(String sub) {
        if (Strings.hasText(sub)) {
            ensureClaims().setSubject(sub);
        } else {
            if (this.claims != null) {
                claims.setSubject(sub);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setAudience(String aud) {
        if (Strings.hasText(aud)) {
            ensureClaims().setAudience(aud);
        } else {
            if (this.claims != null) {
                claims.setAudience(aud);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setExpiration(Date exp) {
        if (exp != null) {
            ensureClaims().setExpiration(exp);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setExpiration(exp);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setNotBefore(Date nbf) {
        if (nbf != null) {
            ensureClaims().setNotBefore(nbf);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setNotBefore(nbf);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setIssuedAt(Date iat) {
        if (iat != null) {
            ensureClaims().setIssuedAt(iat);
        } else {
            if (this.claims != null) {
                //noinspection ConstantConditions
                this.claims.setIssuedAt(iat);
            }
        }
        return this;
    }

    @Override
    public JwtBuilder setId(String jti) {
        if (Strings.hasText(jti)) {
            ensureClaims().setId(jti);
        } else {
            if (this.claims != null) {
                claims.setId(jti);
            }
        }
        return this;
    }


    public String getClaimsJSONStr() {
        // Use Jackson ObjectMapper
        try {
//            ObjectMapper objectMapper = new ObjectMapper();
            return jacksonObjMapper.writeValueAsString(claims);
        } catch (JsonProcessingException jpe) {
            log.error("couldn't process claims list: " + claims.toString());
        }
        return null;
    }


    @Override
    public JwtBuilder claim(String name, Object value) {
        Assert.hasText(name, "Claim property name cannot be null or empty.");
        if (this.claims == null) {
            if (value != null) {
                ensureClaims().put(name, value);
            }
        } else {
            if (value == null) {
                this.claims.remove(name);
            } else {
                this.claims.put(name, value);
            }
        }

        return this;
    }

    // TODO: rewrite this function
    @Override
    public String compact() {

        if (payload == null && Collections.isEmpty(claims)) {
            payload = "";
        }

        if (payload != null && !Collections.isEmpty(claims)) {
            throw new IllegalStateException("Both 'payload' and 'claims' cannot both be specified. Choose either one.");
        }

        // Loads a default header if none specified
        Header header = ensureHeader();

        // TODO: can this just be a 'you must set the values' beast?
        // or does a default need to be set? Why this extra somersault with JwsHeader & Header?
        JwsHeader jwsHeader;
        if (header instanceof JwsHeader) {
            jwsHeader = (JwsHeader) header;
        } else {
            //noinspection unchecked
            jwsHeader = new DefaultJwsHeader(header);
        }

        if (key != null) {
            jwsHeader.setAlgorithm(algorithm.getValue());
        } else {
            //no signature - plaintext JWT:
            jwsHeader.setAlgorithm(SignatureAlgorithm.NONE.getValue());
        }

        if (compressionCodec != null) {
            jwsHeader.setCompressionAlgorithm(compressionCodec.getAlgorithmName());
        }

        String base64UrlEncodedHeader = base64UrlEncode(jwsHeader, "Unable to serialize header to json.");

        byte[] bytes;
        try {
            bytes = this.payload != null ? payload.getBytes(Strings.UTF_8) : toJsonBytes(claims);
        } catch (SerializationException e) {
            throw new IllegalArgumentException("Unable to serialize claims object to json: " + e.getMessage(), e);
        }

        if (compressionCodec != null) {
            bytes = compressionCodec.compress(bytes);
        }

//        String base64UrlEncodedBody = base64UrlEncoder.encode(bytes);
        String base64UrlEncodedBody = b64Encoder.encodeToString(bytes);
        log.info("b64encoder.encodeToString: " + base64UrlEncodedBody);
//             base64UrlEncodedBody = new String(b64Encoder.encode(bytes), StandardCharsets.UTF_8);
//        log.info("b64encoder.encode, String with UTF_8: " + base64UrlEncodedBody);


//            log.info("base64URLEncoded: " + base64UrlEncodedBody);

        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
        log.info("jwt: " + jwt);

        if (key != null) { //jwt must be signed:
            log.info("signing JWT");

            // Build signature first
//            byte[] jwtSignature =  b64Encoder.encode(jwt.getBytes());
            // Replace this somehow with RsaSignatureGenerator code.

//            JwtSigner signer = createSigner(algorithm, key);

//            String base64UrlSignature = signer.sign(jwt);

//            InputStream jwtStream = new ByteArrayInputStream(jwtSignature);
            InputStream jwtStream = IOUtils.toInputStream(jwt);

            String base64UrlSignature = null;
            try {
                byte[] jwtBytes = Base64.getUrlEncoder().encode(rsaSignatureGenerator.sign(jwtStream));
                base64UrlSignature = new String(jwtBytes);

                log.info("new signature: " + base64UrlSignature);

            } catch (IOException e) {
                e.printStackTrace();
            } catch (java.security.InvalidKeyException e) {
                e.printStackTrace();
            }

            jwt += JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        } else {
            // no signature (plaintext), but must terminate w/ a period, see
            // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1
            jwt += JwtParser.SEPARATOR_CHAR;
        }

        log.info("final jwt: " + jwt);

        return jwt;
    }

    // TODO: probably getting rid of this
    /*
     * @since 0.5 mostly to allow testing overrides
     */
//    protected JwtSigner createSigner(SignatureAlgorithm alg, Key key) {
//        return new DefaultJwtSigner(alg, key, base64UrlEncoder);
//    }


    protected String base64UrlEncode(Object o, String errMsg) {
        Assert.isInstanceOf(Map.class, o, "object argument must be a map.");
        Map m = (Map)o;
        byte[] bytes;
        try {
            bytes = toJsonBytes(m);
        } catch (SerializationException e) {
            log.error(errMsg);
            throw new IllegalStateException(errMsg, e);
        }

        // Use java.util Base64 encoding class
        return b64Encoder.encodeToString(bytes);
    }


    @SuppressWarnings("unchecked")
    protected byte[] toJsonBytes(Object object) throws SerializationException {
        Assert.isInstanceOf(Map.class, object, "object argument must be a map.");
        Map m = (Map)object;

        try {
            return jacksonObjMapper.writeValueAsBytes(m);
        } catch (JsonProcessingException e) {
            String msg = "Unable to serialize object: " + e.getMessage();
            log.error(msg);
            throw new SerializationException(msg, e);
        }
    }

    // ----- functions I'd rather not have but can't not implement because of the base class requirements
    @Override
    public JwtBuilder serializeToJsonWith(Serializer<Map<String,?>> serializer) {
        log.debug(" not implemented ");
        return this;
    }

    @Override
    public JwtBuilder base64UrlEncodeWith(Encoder<byte[], String> base64UrlEncoder) {
        log.debug("not implemented: java.util.Base64 used for encoding.");
        return this;
    }
}
