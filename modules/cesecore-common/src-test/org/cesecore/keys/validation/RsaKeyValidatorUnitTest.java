/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests RSA key validator functions, see {@link RsaKeyValidator}.
 *
 * @version $Id$
 */
public class RsaKeyValidatorUnitTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(RsaKeyValidatorUnitTest.class);

    private static byte[] noRocaCert = Base64
            .decode(("MIIEdDCCA1ygAwIBAgIIVjkVCQFZomowDQYJKoZIhvcNAQEFBQAwNTEWMBQGA1UE"
                    +"AwwNTWFuYWdlbWVudCBDQTEOMAwGA1UECgwFUEstRE0xCzAJBgNVBAYTAkFFMB4X"
                    +"DTE2MDkyMjE1MDgxM1oXDTE2MDkyNDE1MDgxM1owMDEOMAwGA1UEAwwFeG1wcDIx"
                    +"ETAPBgNVBAoMCFByaW1lS2V5MQswCQYDVQQGEwJBRTCBnzANBgkqhkiG9w0BAQEF"
                    +"AAOBjQAwgYkCgYEAlYenj6Yh6/WGDyxpSIFu4p8JUn8Gs0+p8jYwNsdwut0n2jRs"
                    +"92u0ekrmao5C0sdOF3EgVojOAWMGbqA32Q/3skXQqKwapgVlJGJXpNeMm47EwB4z"
                    +"HTFKDwHNrnUOU3EB4kf4Z3leZU1KsDppVyt3he9M1gPHwnhSMKRkdPg64AkCAwEA"
                    +"AaOCAg8wggILMBkGB2eBCAEBBgIEDjAMAgEAMQcTAVATAklEMAwGA1UdEwEB/wQC"
                    +"MAAwHwYDVR0jBBgwFoAUu2ifcFjWKrS4wThm+sPPj8GYatowagYDVR0RBGMwYYgD"
                    +"KQECoBgGCisGAQQBgjcUAgOgCgwIZm9vQGEuc2WgIwYIKwYBBQUHCAWgFwwVdG9t"
                    +"YXNAeG1wcC5kb21haW4uY29toBsGCCsGAQUFBwgHoA8WDV9TZXJ2aWNlLk5hbWUw"
                    +"ggEDBgNVHSAEgfswgfgwKAYDKQECMCEwHwYIKwYBBQUHAgEWE2h0dHBzOi8vZWpi"
                    +"Y2Eub3JnLzIwKAYDKQEDMCEwHwYIKwYBBQUHAgEWE2h0dHBzOi8vZWpiY2Eub3Jn"
                    +"LzMwBQYDKQEBMD0GAykBBDA2MDQGCCsGAQUFBwICMCgeJgBNAHkAIABVAHMAZQBy"
                    +"ACAATgBvAHQAaQBjAGUAIABUAGUAeAB0MFwGAykBBTBVMDAGCCsGAQUFBwICMCQe"
                    +"IgBFAEoAQgBDAEEAIABVAHMAZQByACAATgBvAHQAaQBjAGUwIQYIKwYBBQUHAgEW"
                    +"FWh0dHBzOi8vZWpiY2Eub3JnL0NQUzAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB"
                    +"BQUHAwQwHQYDVR0OBBYEFMUFBPXfQktUn7WTMUxTHnYSXk8TMA4GA1UdDwEB/wQE"
                    +"AwIF4DANBgkqhkiG9w0BAQUFAAOCAQEAQ1K6zjPjCNFT1+KJ/E959khU/Hg5dObK"
                    +"p4LsS+LpPmFu4M9DjS2vwr48lLh+eBB65U+6/WMTO7/3fEeD3AaoD2+f9pnG6pq9"
                    +"tC3GlfQfuSWELIhebg+73+GcvEpGRqQIKQ0qguTZEJiGK6i7714ECRE+xVD81Hez"
                    +"BE3M3tBSK1Q6zJ36DdgSx99hz0p8IutMX6ntYDWbA1DJ+V3zzCc5zF3ZSogWv3+T"
                    +"CJG3EfrGDJ91eVUlGyfDpHRr9a3WOWbypLjh1Q92xxHOJbvgnS9J6mybaOpQYyCn"
                    +"MVWCdyTMTi9Ik0eybpeVMZYaSEO4xIqwoGbvuBgE2WKm+RuMnMOkfA==").getBytes());

    private static byte[] rocaCert = Base64
            .decode(("MIICpTCCAYwCCQC2u0PIfFaGMjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls"
                    +"b2NhbGhvc3QwHhcNMTcxMDE2MTkzODIxWhcNMTgxMDE2MTkzODIxWjAUMRIwEAYD"
                    +"VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQJZ"
                    +"J7UrpeaMjJJou5IY83ZzYUymVBj0dFsUPNTuU/lJHJoOHC8jqVFjBq/784ZnuHG8"
                    +"DMguYPW7Gp+hWlZxp2XJ8huVh9gBFZZDcqODyIOw3L9sd1cGsx6v8+P9SIVZoIze"
                    +"og+al8TFm2uKjuykV9SoINSVCfdZM2MCvKGjaQsICRgR+Fjy6M6lpiNVrW4EHRk1"
                    +"7aWSibWXaDtz4mV650v/x2Dk1RPMh9uTVZGOqgjTmLvl9oNdyHElIRubNrOgvHC5"
                    +"k6bLP30stAYd5z25cslCrfmVW2/kzZDwDQiK7ASvH17/kfIa9e1EYXx9uAk/lTZt"
                    +"smWAxK85neuU+bFBMFvhAgMBAAEwDQYJKoZIhvcNAQELBQADggECAAG7W49CYRUk"
                    +"YAFRGXu3M85MKOISyc/kkJ8nbHdV6GxJ05FkoDKbcbZ7nncJiIp2VMAMEIP4bRTJ"
                    +"5U4g4vSZlmCs8BDmV3Ts/tbDCM6eqK+2hwjhUnCnmmsLt4xVUeAAsWUHl9AVtjzd"
                    +"oYlm1Kk20QBzNpsvM/gFS5B+duHvTSfELfoq9Pdfvmn2gEXJHe9scO8bfT3fm15z"
                    +"R6AUYsSsxAhup2Rix6jgJ14KGsh6uVm6jhz9aBTBcgx7iMuuP8zUbUE6nryHYXnR"
                    +"cSvuYSesTCoFfnL7elrZDak/n0jLfwUD80aWnReJfu9QQGdqdDnSG8lSQ1XPOC7O"
                    +"/hFW9l0TCzOE").getBytes());

    @SuppressWarnings("unused")
    private static final String pubExp3Csr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIICyTCCAbECAQAwgYUxCzAJBgNVBAYTAlNFMRMwEQYDVQQIDApTb21lLVN0YXRl\n" +
            "MR4wHAYDVQQKDBVQcmltZUtleSBTb2x1dGlvbnMgQUIxHDAaBgNVBAMME0Jhc3Rp\n" +
            "YW4gRnJlZHJpa3Nzb24xIzAhBgkqhkiG9w0BCQEWFGJhc3RpYW5AcHJpbWVrZXku\n" +
            "Y29tMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA4hmdDGhY9G1o8bx7\n" +
            "b7uNShH1UEqzGLNuYPmnYPQo282+ufLru5ON6ySqDcIFSVStObAwkY/pe2Hibhbd\n" +
            "o6HcNdbJuoy/sbMEeykxDE2gAWsMp8NYGLfd5COL9I2mSnLHRbiICSuHKfsxIOpf\n" +
            "PR7IWgxGXUtBXxGnVhtfm8epKmQUwMMzQnbiYl5IrVAlt15r88qgL9uhI9AhyYth\n" +
            "3my4jSm/MKsIJfEq02OHzOrvWWNHU6d8ay0Xetoy8YSL95F1s/q1ONw39mTriLyH\n" +
            "IUHzHe6CinhiMdQuJ9GjrzGnyrkgAZW9bK3SEuZp3kGGDCDE/CP/cb/2B1d9R/DX\n" +
            "NHwv7QIBA6AAMA0GCSqGSIb3DQEBCwUAA4IBAQAB7V+//THv+dzTMn0P7JYqI8Ob\n" +
            "tVrRcPDr1taSFWBeRTzxchc3+D3JIsA1j00hdOFyje01dCt2LbDCAsJmRmD5JpWW\n" +
            "qu+j/Hg2gEF2pA3V8r9KKCVVYWCtKak45l8YrKyldvENTrqAgF6zHBvtfZGkk5ik\n" +
            "a0mu2joz3uTQD97k+t2+DlYXecc0Il57+KCefAqOcqYwO7HHDvWdxJESJDL8pVw4\n" +
            "Qmd5jcD0aZbh8UjlIROMyziCjMloK/8lKza59bkvdsWbAEdNy88YXnC1hljdisEK\n" +
            "fwpZY7RnlI0FPAp9qyQ7KAKt+hsTnfICkaINhM9ADxzToqaq8f1bjCdD3a95\n" +
            "-----END CERTIFICATE REQUEST-----";

    @SuppressWarnings("unused")
    private static final String powOfPrimeCsr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIE3zCCAscCAQAwgZkxCzAJBgNVBAYTAlNFMRMwEQYDVQQIDApTb21lLVN0YXRl\n" +
            "MRIwEAYDVQQHDAlTdG9ja2hvbG0xHjAcBgNVBAoMFVByaW1lS2V5IFNvbHV0aW9u\n" +
            "cyBBQjEcMBoGA1UEAwwTQmFzdGlhbiBGcmVkcmlrc3NvbjEjMCEGCSqGSIb3DQEJ\n" +
            "ARYUYmFzdGlhbkBwcmltZWtleS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\n" +
            "ggIKAoICAQDjf1K0BpT20vXA/e/rt7dYFLJDTWeS5YmIG3Ctr2DlpMlUMZ9eWWuz\n" +
            "b3x6GdH7PMGug0tjpm7E0pbSiJk3y4cr2qFp9UXufIcsPaVK7VRsqEkcGOsD6VwS\n" +
            "1zZamdGGeu5zD50YOOcdhqH0tKhhj+CtgEmbsoVXdkAkUtxC4HkkDZWnF/9DhEhM\n" +
            "wHh7iuOaTKOQsOakCYL34p+tbqm1t98HZjmTzIxsW890HzqWu+Crm/t5KQaJOluT\n" +
            "O4O20QI5iAB9dgsx6qK45K74mmeY20953na3j8kQ8Rs7O3aJCiZGkGpnFHQF6wOw\n" +
            "k8WPjRAernlP+1oefBHtDau3VEH1xbUz5adN+MOYS94o4hhARHoT+9WOWDBgzAIw\n" +
            "ZlYX8epvktElTglFq7lSf7mTkIFTYx5mIAGMwQXQw8Uvl86IvBPaHVZXosYm03BU\n" +
            "tY7htyw341rDyaHKn6Zt+05X337sai5VzxupAzgt1f16RUuHC15ItnUoQN/wYX8E\n" +
            "bOb+ViZmZ9wShALRIO75pNgzDS8P49eu1Nobq+wsAt7ZrbcvfzynTizgansrQnWI\n" +
            "pG6l465E/P/hIEyQtZzZva2HcNvxfPr/JOs79jsSUdyuyLLpvm9Z19jF4fZv7m84\n" +
            "1DrfiDfB4BYIiQD309heRwONlmLy2hxXbDdUkH/CdWT6W9VZ3xniwQIDAQABoAAw\n" +
            "DQYJKoZIhvcNAQELBQADggIBAK6upG22yKnetxbNt1P9gCw04syNyBwr3MtEkV8c\n" +
            "z0GNPwC0K77Vn75FASV3V4BqCyt8OOf9vT4F9KDi3m3zA1MaKtgVbFAHwhq1fepM\n" +
            "SVIS2kRLdwP/k4CXdlKxnpnIpJ69NFcW7gKrUNaS6KDcl46QQdwd5kOgrUNhUTqZ\n" +
            "kpPsFsgrnMA/7Nfhz1JTQcmuVe+wj3m+2x28YAkwli2YZhjL/74xHNvebMNV22ur\n" +
            "cSFE0dk1VsyEufl6zUqqtmyZD5uxFfvd7DvUwXg+hUfgBe1NsBaEjIsECuptmOAu\n" +
            "Vj8IBzFlXHXha1Bk/1KLK0CAmvJWdjmJQSAU8i4j6LO8jl5wQhuTx8QtPIVlhN+/\n" +
            "DHu9I9oT9hvQV9uLpe404PLN+qn6C02TIMFMH+o2GSazNAmKIRsFrkh5zEHrcoDI\n" +
            "V2qm1cf3xfRYw3krPOQ646I5Uk5WxHipjBYZ5OKX7+5TonShiQEDEwq0A5rddBx9\n" +
            "M3GoPMpvB38VIrmeD3WnSkAPPPvURusmuSqsEpXmsYcjdgaKXSMjGNCV2eawTOi0\n" +
            "eUvySPbD0ieV4cKvKuih8u95xKByU3TNf5BWdynGJyKVIE1Y6vG/rUTHjslVgYRy\n" +
            "jcC54t6oAAAlqPBMyX8DtwPAaWBueaV9FVd2RMeBLIatSyrKaKkFIjaJqg1GN4DM\n" +
            "+Zln\n" +
            "-----END CERTIFICATE REQUEST-----";


    @BeforeClass
    public static void setClassUp() throws Exception {
        log.trace("setClassUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("setClassUp()");
    }

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        // NOOP
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        // NOOP
        log.trace("<tearDown()");
    }

    /**
     * Testing that no fields for RSA Key Validator configuration can be set to a negative value
     * @throws Exception Exception
     */
    @Test
    public void testNoNegativeNumbers() throws Exception {
        log.trace(">testNoNegativeNumbers()");
        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-input_test", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        String numStringPos = "2";
        String numStringNeg = "-4";
        BigInteger exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyExponentMin(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyExponentMin(exponent);
        // Test that a negative number can not be set for setPublicKeyExponentMin
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ",
                keyValidator.getPublicKeyExponentMin(), new BigInteger(numStringPos) );
        // Test that a negative number can not be set for setPublicKeyExponentMax
        exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyExponentMax(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyExponentMax(exponent);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ",
                keyValidator.getPublicKeyExponentMax(), new BigInteger(numStringPos)  );
        // Test that a negative number can not be set for setPublicKeyModulusMin
        exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyModulusMin(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyModulusMin(exponent);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ",
                keyValidator.getPublicKeyModulusMin(),  new BigInteger(numStringPos));
        // Test that a negative number can not be set for setPublicKeyModulusMax
        exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyModulusMax(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyModulusMax(exponent);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ",
                keyValidator.getPublicKeyModulusMax(), new BigInteger(numStringPos) );
        // Test that a negative number can not be set for setPublicKeyModulusMinFactor
        keyValidator.setPublicKeyModulusMinFactor(2);
        keyValidator.setPublicKeyModulusMinFactor(-4);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ",
                keyValidator.getPublicKeyModulusMinFactor(), Integer.valueOf(2));
        log.trace("<testNoNegativeNumbers()");
   }

    /**
     * Tests that it is not possible to set a smaller maximum exponent than currently set minimum exponent and vice versa.
     * @throws Exception Exception
     */
    @Test
    public void testPublicKeyExponentMinSmallerThanMax() throws Exception {
        log.trace(">testPublicKeyExponentMinSmallerThanMax()");

        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-set-min-smaller-max-test", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());

        // Test that min and max can be changed from null.
        keyValidator.setPublicKeyExponentMinAsString("2");
        keyValidator.setPublicKeyExponentMaxAsString("3");
        Assert.assertEquals("It should be possible to set minimum exponent to 2 if maximum is null",
                keyValidator.getPublicKeyExponentMinAsString(),"2");
        Assert.assertEquals("It should be possible to set maximum exponent to 3 if miniimum is 2",
                keyValidator.getPublicKeyExponentMaxAsString(),"3");
        // Test not possible to set smaller max than min.
        keyValidator.setPublicKeyExponentMaxAsString("1");
        Assert.assertEquals("It should not be possible to set maximum exponent to 1 if minimum is 2",
                keyValidator.getPublicKeyExponentMaxAsString(),"3");
        // Test not possible to set larger min than max.
        keyValidator.setPublicKeyExponentMinAsString("4");
        Assert.assertEquals("It should not be possible to set minimum exponent to 4 if maximum is 3",
                keyValidator.getPublicKeyExponentMinAsString(),"2");
        // Test possible to set same min as max.
        keyValidator.setPublicKeyExponentMinAsString("3");
        keyValidator.setPublicKeyExponentMaxAsString("5");
        Assert.assertEquals("It should be possible to set minimum exponent to 3 if maximum is 3",
                keyValidator.getPublicKeyExponentMinAsString(),"3");
        Assert.assertEquals("It should be possible to set maximum exponent to 5 if minimum is 3",
                keyValidator.getPublicKeyExponentMaxAsString(),"5");
        // Test possible to set same max as min.
        keyValidator.setPublicKeyExponentMaxAsString("3");
        Assert.assertEquals("It should be possible to set maximum exponent to 3 if minimum is 3",
                keyValidator.getPublicKeyExponentMaxAsString(),"3");

        log.trace("<testPublicKeyExponentMinSmallerThanMax()");
    }

    /**
     * Tests that it is not possible to set a smaller maximum modulus than currently set minimum modulus and vice versa.
     * @throws Exception Exception
     */
    @Test
    public void testPublicKeyModulusMinSmallerThanMax() throws Exception {
        log.trace(">testPublicKeyModulusMinSmallerThanMax()");

        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-set-min-smaller-max-test", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());

        // Test that min and max can be changed from null.
        keyValidator.setPublicKeyModulusMinAsString("20");
        keyValidator.setPublicKeyModulusMaxAsString("30");
        Assert.assertEquals("It should be possible to set minimum modulus to 20 if maximum is null",
                keyValidator.getPublicKeyModulusMinAsString(),"20");
        Assert.assertEquals("It should be possible to set maximum modulus to 30 if miniimum is 20",
                keyValidator.getPublicKeyModulusMaxAsString(),"30");
        // Test not possible to set smaller max than min.
        keyValidator.setPublicKeyModulusMaxAsString("10");
        Assert.assertEquals("It should not be possible to set maximum modulus to 10 if minimum is 20",
                keyValidator.getPublicKeyModulusMaxAsString(),"30");
        // Test not possible to set larger min than max.
        keyValidator.setPublicKeyModulusMinAsString("40");
        Assert.assertEquals("It should not be possible to set minimum modulus to 40 if maximum is 30",
                keyValidator.getPublicKeyModulusMinAsString(),"20");
        // Test possible to set same min as max.
        keyValidator.setPublicKeyModulusMinAsString("30");
        keyValidator.setPublicKeyModulusMaxAsString("50");
        Assert.assertEquals("It should be possible to set minimum modulus to 30 if maximum is 30",
                keyValidator.getPublicKeyModulusMinAsString(),"30");
        Assert.assertEquals("It should be possible to set maximum modulus to 50 if minimum is 30",
                keyValidator.getPublicKeyModulusMaxAsString(),"50");
        // Test possible to set same max as min.
        keyValidator.setPublicKeyModulusMaxAsString("30");
        Assert.assertEquals("It should be possible to set maximum modulus to 30 if minimum is 30",
                keyValidator.getPublicKeyModulusMaxAsString(),"30");

        log.trace("<testPublicKeyModulusMinSmallerThanMax()");
    }

    @Test
    public void test01HasSmallerFactorThan() throws Exception {
        log.trace(">test01HasSmallerFactorThan()");

        // Test both zero -> false
        BigInteger modulus = new BigInteger("0");
        Assert.assertFalse("Modulus 0 and factor 0 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 0));

        // Factor is smaller than modulus -> false;
        Assert.assertFalse("Modulus 0 and factor 1 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 1));

        // Test both 1 -> false;
        modulus = new BigInteger("1");
        Assert.assertFalse("Modulus 1 and factor 1 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 1));

        // Test both 2 -> false;
        modulus = new BigInteger("2");
        Assert.assertFalse("Modulus 2 and factor 2 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 2));

        // All even numbers have the smallest factor 2 -> false;
        modulus = new BigInteger("12345678902");
        Assert.assertFalse("Even modulus must evaluate to smallest factor 2.", RsaKeyValidator.hasSmallerFactorThan(modulus, 2));
        Assert.assertTrue("Even modulus must evaluate to smallest factor 2.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));

        // Prime numbers smallest factor except 1 is itself.
        modulus = new BigInteger("3");
        Assert.assertTrue("A primes smallest factor except 1 is itself.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));
        modulus = new BigInteger("123");
        Assert.assertTrue("A primes smallest factor except 1 is itself.", RsaKeyValidator.hasSmallerFactorThan(modulus, 123));
        modulus = new BigInteger("9");
        Assert.assertTrue("The smallest factor of 9 is 3.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));
        modulus = new BigInteger("27");
        Assert.assertTrue("The smallest factor of 27 is 3.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));

        // Test large modulus.
        long time = System.currentTimeMillis();
        modulus = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390782");
        Assert.assertTrue("Test 2048 bits even modulus", RsaKeyValidator.hasSmallerFactorThan(modulus, 752));
        log.trace(">test01HasSmallerFactorThan() ms spent for 2048 bit even modulus: " + (System.currentTimeMillis() - time));

        BigInteger modulus2048 = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781");
        BigInteger modulus4096 = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781");
        BigInteger modulus8192 = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781");
        // Can be a time consuming task!
        int factor = 1522342;
        profileHasSmallerFactor(factor, new BigInteger[] { modulus2048, modulus4096, modulus8192 });

        log.trace("<test01HasSmallerFactorThan()");
    }

    @Test
    public void test03RsaParameterValidations() throws Exception {
        log.trace(">test03RsaParameterValidations()");

        final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_RSA, BouncyCastleProvider.PROVIDER_NAME);

        // A-1: Test RSA key validation OK with default settings except key size.
        // In order to create these keys, we need to override/disable some internal checks in BC
        org.bouncycastle.util.Properties.setThreadOverride(CertificateConstants.ENABLE_UNSAFE_RSA_KEYS, true);
        BigInteger modulus = BigInteger.valueOf(15);
        BigInteger exponent = BigInteger.valueOf(3);
        PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-test-1", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        // Set custom bit length.
        List<String> bitLengths = new ArrayList<>();
        bitLengths.add(Integer.toString(modulus.bitLength()));
        keyValidator.setBitLengths(bitLengths);
        keyValidator.setPublicKeyModulusDontAllowClosePrimes(false);
        List<String> messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertTrue("Key validation should have been successful.", messages.isEmpty());

        // A-2: Test RSA key validation failed RSA parameter bounds with even parameters.
        // Before BC 1.65 we could create a RSA public key like this, but since 1.65 there are built in blocks in BC
        // publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        modulus = BigInteger.valueOf(16);
        exponent = BigInteger.valueOf(4);
        publicKey = new RSAPublicKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public BigInteger getModulus() {
                return BigInteger.valueOf(16);
            }

            @Override
            public BigInteger getPublicExponent() {
                return BigInteger.valueOf(4);
            }
            
            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public String getFormat() {
                return null;
            }
        };

        keyValidator.setPublicKeyExponentMin(exponent.add(BigInteger.ONE));
        keyValidator.setPublicKeyExponentOnlyAllowOdd(true);
        keyValidator.setPublicKeyModulusMin(modulus.add(BigInteger.ONE));
        keyValidator.setPublicKeyModulusMax(modulus.subtract(BigInteger.ONE));
        keyValidator.setPublicKeyModulusOnlyAllowOdd(true);
        bitLengths = new ArrayList<>();
        bitLengths.add(Integer.toString(BigInteger.valueOf(16).bitLength()));
        keyValidator.setBitLengths(bitLengths);
        messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertEquals("Key valildation should have failed because of even RSA parameter and outside parameter bounds.", 4,
                messages.size());
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is odd.", messages.get(0));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is smaller than 5", messages.get(1));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is odd.", messages.get(2));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is smaller than 17", messages.get(3));
        // Need to set min to null before lowering max
        keyValidator.setPublicKeyExponentMin(null);
        keyValidator.setPublicKeyExponentMax(exponent.subtract(BigInteger.ONE));
        keyValidator.setPublicKeyModulusMin(null);
        keyValidator.setPublicKeyModulusMax(modulus.subtract(BigInteger.ONE));
        keyValidator.validate(publicKey, null);
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is greater than 3", keyValidator.validate(publicKey, null).get(1));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is greater than 15", keyValidator.validate(publicKey, null).get(3));

        // A-3: Test RSA key validation failed because of modulus factor restriction.
        modulus = BigInteger.valueOf(25);
        exponent = BigInteger.valueOf(3);
        publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        keyValidator.setPublicKeyExponentMin(exponent);
        keyValidator.setPublicKeyExponentMax(exponent);
        keyValidator.setPublicKeyExponentOnlyAllowOdd(true);
        keyValidator.setPublicKeyModulusMin(modulus);
        keyValidator.setPublicKeyModulusMax(modulus);
        keyValidator.setPublicKeyModulusOnlyAllowOdd(true);
        keyValidator.setPublicKeyModulusMinFactor(6); // smallest factor = 5
        messages = keyValidator.validate(publicKey, null);
        log.debug("Key validation error messages: " + messages);
        Assert.assertEquals("Key valildation should have failed because of smallest factor restriction for modulus.", 1,
                messages.size());
        Assert.assertEquals("smallest factor failure message isn't right",
                "Invalid: RSA public key modulus smallest factor is less than 6", messages.get(0));

        // A-4: Test RSA key validation failed because of modulus power of prime restriction.
        keyValidator.setPublicKeyModulusMinFactor(5); // smallest factor = 5
        keyValidator.setPublicKeyModulusDontAllowPowerOfPrime(true);
        messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertEquals("Key valildation should have failed because of power of prime restriction for modulus.", 1,
                messages.size());
        Assert.assertEquals("Power of prime failure message isn't right.",
                "Invalid: RSA public key modulus is not allowed to be the power of a prime.", messages.get(0));

        log.trace("<test03RsaParameterValidations()");
    }

    /** Tests public key validation for the ROCA vulnerable key generation. CVE-2017-15361
     */
    @Test
    public void testRocaWeakKeys() throws CertificateParsingException, InstantiationException, IllegalAccessException, ValidatorNotApplicableException, ValidationException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
        log.trace(">testRocaWeakKeys()");
        X509Certificate noroca = CertTools.getCertfromByteArray(noRocaCert, X509Certificate.class);
        X509Certificate roca = CertTools.getCertfromByteArray(rocaCert, X509Certificate.class);

        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-test-1", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        keyValidator.setPublicKeyModulusDontAllowRocaWeakKeys(false);

        // With disabled validation of ROCA, everything should pass
        List<String> bitLengths = new ArrayList<>();
        bitLengths.add("1024");
        bitLengths.add("2048");
        bitLengths.add("2050"); // The positive sample ROCA cert is 2050 bits
        keyValidator.setBitLengths(bitLengths);
        keyValidator.setPublicKeyModulusDontAllowClosePrimes(false);
        List<String> messages = keyValidator.validate(noroca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have been successful: "+messages, 0, messages.size());
        messages = keyValidator.validate(roca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have been successful: "+messages, 0, messages.size());

        // Check for ROCA weak keys
        keyValidator.setPublicKeyModulusDontAllowRocaWeakKeys(true);
        messages = keyValidator.validate(noroca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have been successful: "+messages, 0, messages.size());
        messages = keyValidator.validate(roca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have failes", 1, messages.size());
        assertEquals("It should have been a ROCA failure.",
                "Invalid: RSA public key modulus is a weak key according to CVE-2017-15361.", messages.get(0));

        log.trace("<testRocaWeakKeys()");

    }
    
    /**
     * Tests public key modulus for close primes vulnerability.
     * Close primes expected not found in public key modulus.
     * @throws Exception
     */
    @Test
    public void test04ClosePrimesVulnerabilityExpectNotFoundInPublicKey() throws Exception{
        log.trace(">test04ClosePrimesVulnerabilityExpectNotFoundInPublicKey()");
        // Given
        // A valid modulus from a valid public key extracted from the noRocaCert certificate used in previous tests
        final String modulusNoClosePrimes = "105003467046593454352683938240292328205912882700809092403379043610929156939171312301804108647669125604"
                + "9236869084916382921991484666296419264424098541486132035493327283855499759787264494221234528815777431092176571559477"
                + "88591842311514058951402543187594309637097123004507084482521049525100106193027001852383387657";
        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-test-11", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CAB_FORUM_SETTINGS.getOption());
        keyValidator.setPublicKeyModulusDontAllowClosePrimes(true);
        List<String> bitLengths = new ArrayList<>();
        bitLengths.add("1024");
        bitLengths.add("2048");
        keyValidator.setBitLengths(bitLengths);
        X509Certificate certWithValidKey = CertTools.getCertfromByteArray(noRocaCert, X509Certificate.class);
        // We extract the valid public key from a valid certificate 
        final PublicKey validPublicKey = certWithValidKey.getPublicKey();
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) validPublicKey;
        final BigInteger validModulus = rsaPublicKey.getModulus();
        // Make sure we use the above valid modulus and not anyone computed from close primes
        assertEquals(validModulus.toString(), modulusNoClosePrimes);
        // When
        List <String> messages_validPublicKey = keyValidator.validate(validPublicKey, null);
        // Then
        assertEquals("Close primes vulnerability should not have been fond. Returned List should have been empty.", 0, messages_validPublicKey.size());
        log.trace("<test04ClosePrimesVulnerabilityExpectNotFoundInPublicKey()");        
    }

    /**
     * Tests public key modulus for close primes vulnerability.
     * Close primes expected found in public key modulus.
     * @throws Exception
     */
    @Test
    public void test05ClosePrimesVulnerabilityExpectFoundInPublicKeys() throws Exception{
        log.trace(">test05ClosePrimesVulnerabilityExpectFoundInPublicKeys()");
        // Given
        final String VALIDATION_FAILED_MESSAGE = "Invalid: RSA public key modulus from close primes detected.";
        // Two vulnerable modulus...
        final String modulusClosePrimesString_1 = "66511"; 
        final String modulusClosePrimesString_2 = "130924909";   
        //The modulus n66511 is calculated from the primes p293 and q227 so we can expect a=293 (260+33) and b=227 (260-33) since n = a²-b² or n = (a+b)(a-b)
        //The modulus n130924909 is calculated from the primes p11777 and q11117
        final String exponentString = "7";//Random odd number for exponent 
        final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_RSA, BouncyCastleProvider.PROVIDER_NAME);
        org.bouncycastle.util.Properties.setThreadOverride(CertificateConstants.ENABLE_UNSAFE_RSA_KEYS, true);
        final BigInteger modulus_closePrimes_1 = new BigInteger(modulusClosePrimesString_1);
        final BigInteger modulus_closePrimes_2 = new BigInteger(modulusClosePrimesString_2);
        final BigInteger exponent = new BigInteger(exponentString);
        RsaKeyValidator keyValidator = (RsaKeyValidator) ValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-test-11", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CAB_FORUM_SETTINGS.getOption());
        keyValidator.setPublicKeyModulusDontAllowClosePrimes(true);
        final PublicKey invalidPublicKey_1 = keyFactory.generatePublic(new RSAPublicKeySpec(modulus_closePrimes_1, exponent));
        final PublicKey invalidPublicKey_2 = keyFactory.generatePublic(new RSAPublicKeySpec(modulus_closePrimes_2, exponent));
        List<String> bitLengths = new ArrayList<>();
        bitLengths.add("1024");
        bitLengths.add("2048");
        bitLengths.add(Integer.toString(BigInteger.valueOf(66511).bitLength()));
        bitLengths.add(Integer.toString(BigInteger.valueOf(130924909).bitLength()));
        keyValidator.setBitLengths(bitLengths);
        // When
        List <String> messages_invalidPublicKey_1 = keyValidator.validate(invalidPublicKey_1, null);
        // Then
        assertEquals("Close primes vulnerability should have been found. Returned List should include 1 element.", 1, messages_invalidPublicKey_1.size());
        assertTrue("The message returned was not the expected message: " + messages_invalidPublicKey_1.get(0), messages_invalidPublicKey_1.get(0).contains(VALIDATION_FAILED_MESSAGE));
        // When
        List <String> messages_invalidPublicKey_2 = keyValidator.validate(invalidPublicKey_2, null);
        // Then
        assertEquals("Close primes vulnerability should have been found. Returned List should include 1 element.", 1, messages_invalidPublicKey_2.size());
        assertTrue("The message returned was not the expected message: " + messages_invalidPublicKey_2.get(0), messages_invalidPublicKey_2.get(0).contains(VALIDATION_FAILED_MESSAGE));
        log.trace("<test05ClosePrimesVulnerabilityExpectFoundInPublicKeys()");        
    }

    private void profileHasSmallerFactor(final int factor, final BigInteger... modulus) {
        log.trace(">profileHasSmallerFactor()");

        final long time = System.currentTimeMillis();
        int size;
        for (BigInteger m : modulus) {
            size = m.bitLength();
            Assert.assertFalse("Test " + size + " bits modulus", RsaKeyValidator.hasSmallerFactorThan(m, factor));
            if (log.isTraceEnabled()) {
                log.trace(">ms spent for " + size + " bit odd modulus with factor " + factor + ": " + (System.currentTimeMillis() - time));
            }
        }

        log.trace("<profileHasSmallerFactor()");
    }
}
