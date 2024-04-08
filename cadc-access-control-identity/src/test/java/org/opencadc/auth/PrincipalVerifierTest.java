package org.opencadc.auth;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import org.junit.Test;
import org.junit.Assert;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class PrincipalVerifierTest {

    // DN is CN=jenkinsd_e7f, OU=cadc, O=hia, C=ca
    private static final String CERTIFICATE_CONTENT = "-----BEGIN CERTIFICATE-----\n" +
            "MIID7zCCAtegAwIBAgIGAY6GOiJPMA0GCSqGSIb3DQEBCwUAMEExCzAJBgNVBAYT\n" +
            "AmNhMQwwCgYDVQQKEwNoaWExDTALBgNVBAsTBGNhZGMxFTATBgNVBAMMDGplbmtp\n" +
            "bnNkX2U3ZjAeFw0yNDAzMjgxNjU3MjBaFw0yNDA0MjcxNzAyMjBaMFYxCzAJBgNV\n" +
            "BAYTAmNhMQwwCgYDVQQKEwNoaWExDTALBgNVBAsTBGNhZGMxFTATBgNVBAMMDGpl\n" +
            "bmtpbnNkX2U3ZjETMBEGA1UEAxMKMTExMDkwMjI1MzCCASIwDQYJKoZIhvcNAQEB\n" +
            "BQADggEPADCCAQoCggEBAJ10Gj0Ca/6UwQSt5KtwaDJlDH7G8jw4N4HaCWnM3zDu\n" +
            "o1FbCN9PK3V4ORWOliUpe9qNFuBZvQZTzwOKWCaQy9u/KmSBhJgRph9n7VBGWpBz\n" +
            "Y+W8Q3rQIFjZ+WYwG27QUyeaR3OwbKytqYJveCD43GBarctkJ+TvWfcGLHiqdHXk\n" +
            "7og6atajJhqklElQntuem0pQelcgU/LGfAAmMbR6/ErpYiJPqVrj3Z1cyR4+J1Q2\n" +
            "frDD8XEqAJxwb02bTmcupFe/0z6PRsxK5CGVmmYsOqX2Ju+uxuuff2wcHgkGVEYF\n" +
            "/VeshUNN9YWy8lUITM+vFinfv+aH6DMFRzZkECUujSUCAwEAAaOB1zCB1DAOBgNV\n" +
            "HQ8BAf8EBAMCBaAwdgYDVR0jBG8wbYAU+r0H4eFAGlUfAkNYUPD+/8Oi38ihTaRL\n" +
            "MEkxCzAJBgNVBAYTAmNhMQswCQYDVQQIEwJiYzENMAsGA1UEChMEY2FkYzEeMBwG\n" +
            "A1UECxMVY2FkYyBpbnRlcm5hbCByb290IGNhggYBjY8bhHkwHQYDVR0OBBYEFG7j\n" +
            "mjR7VZeLWKUdSXflJyn1P7GIMAwGA1UdEwEB/wQCMAAwHQYIKwYBBQUHAQ4BAf8E\n" +
            "DjAMMAoGCCsGAQUFBxUBMA0GCSqGSIb3DQEBCwUAA4IBAQBOOOD5Hix2nwrYccWw\n" +
            "MpyRZYxP47n+7f6R9jBbtOsXLa5xv5IdrSIOBZSer751NUzqpweko/z3Ckw0GWTv\n" +
            "HZjME9LwCEK9dw2VRMNyYXHrpkaA9smfxyoO/0xNBXSHADLKyFJAP07XXkv3hApT\n" +
            "q5yGYOr1NT48bvBeSSc5KB7pKT5zslQCqxFslIMiPROqBb5OB3WFcMaZKdtAWoY8\n" +
            "Eqyv6z8g7dfZphGtzC9oUxvKBBKqRPx1m/OoXnUsMd37z4CVMeUKl8Rs5wFuBp6E\n" +
            "YlVCgmGuv7r8COmMsoq3uAwKmPiz3tehhwPkcsNGaSfbOpNyvapdrMCkS/2Ip2oh\n" +
            "vUMC\n" +
            "-----END CERTIFICATE-----\n";

    @Test
    public void testVerifyNotAuthorized() throws Exception {
        final PrincipalVerifier testSubject =
                new PrincipalVerifier(new HttpPrincipal("testuser"));

        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (final InputStream inputStream =
                     new ByteArrayInputStream(PrincipalVerifierTest.CERTIFICATE_CONTENT.getBytes(
                             StandardCharsets.UTF_8))) {
            final X509Certificate x509Certificate =
                    (X509Certificate) certificateFactory.generateCertificate(inputStream);
            testSubject.verify(x509Certificate.getIssuerX500Principal());
            Assert.fail("Should throw NotAuthenticatedException");
        } catch (NotAuthenticatedException notAuthenticatedException) {
            // Good!
        }
    }

    @Test
    public void testVerify() throws Exception {
        final PrincipalVerifier testSubject =
                new PrincipalVerifier(new HttpPrincipal("testuser"),
                                      new X500Principal("CN=jenkinsd_e7f, OU=cadc, O=hia, C=ca"));

        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (final InputStream inputStream =
                     new ByteArrayInputStream(PrincipalVerifierTest.CERTIFICATE_CONTENT.getBytes(
                             StandardCharsets.UTF_8))) {
            final X509Certificate x509Certificate =
                    (X509Certificate) certificateFactory.generateCertificate(inputStream);
            testSubject.verify(x509Certificate.getIssuerX500Principal());
        }
    }
}
