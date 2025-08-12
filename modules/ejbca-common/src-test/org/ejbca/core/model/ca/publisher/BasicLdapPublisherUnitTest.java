/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ca.publisher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.LogRedactionUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

/**
 * Unit tests for {@link NASHLdapPublisher}
 * 
 * Will need a suitable LDAP service for these tests. 
 * Note: As this Publisher creates a 'dc' attribute in the LDAP entry, the 'iNetOrgPerson' schema needs to
 * include an optional 'dc' attribute.
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)   // Order is important for these tests.
public class BasicLdapPublisherUnitTest {

    //
    // DEFAULT SETTINGS FOR TESTING
    //
    private static String BASEDN = "c=au"; 
    private static String HOSTNAMES = "localhost"; 
    private static String PORT = "389"; 
    private static String LOGINDN = "cn=Manager,c=au"; 
    private static String LOGINPASSWORD = "Verizon1!"; 
    private static String CONNECTIONSECURITY = "PLAIN";
    
    //
    /// Test Certs. NASH example cert with various differences for testing.
    //
    // "CN=general.8003625833400002.id.electronichealth.net.au,O=TestABC,DC=8003625833400002,DC=id,DC=electronichealth,DC=net,DC=AU"
    // HCID: 8003625833400002
    // RANumber: 9879879871
    // CP OID: 1.2.36.174030967.1.20.1.1
    private static String certTestABC_3 = "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";
    private static String certTestABC_2 = "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";

    private static String certTestRCA = "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";
    private static String dnTestRCA = "cn=TEST Medicare Australia Root Certification Authority 2,ou=Humanservices,o=GOV,c=AU";
    private static String crlTestRCA = "MIIC7jCB1wIBATANBgkqhkiG9w0BAQsFADB0MT8wPQYDVQQDDDZURVNUIE1lZGljYXJlIEF1c3RyYWxpYSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IDIxFjAUBgNVBAsMDUh1bWFuc2VydmljZXMxDDAKBgNVBAoMA0dPVjELMAkGA1UEBhMCQVUXDTI1MDYxODAwMDg1NVoXDTI1MDcxOTAwMDg1NFqgLzAtMB8GA1UdIwQYMBaAFKXbDLSN74nJNv+VNSy5PLBofM26MAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEBCwUAA4ICAQBkPjbY+lB0WcbORMqbQWBqEijGu3ESun9v3WrfpA2+J6MVYNS387LYB8JyYlTsAaYoyi4Y3spAI+sTPM+mpc+uZ+1KPMEZSBzFTRPomHrS0rf6uwYx7cshp4DYPr/c1m0c7y+M2sFMXvSmIXQCuovAlLLclvaoyndHuswlqSFNQln/mMKvoOUB+rUbY89zmtRuTeOXP7oqPglm4Zi7xBsbJuNJImDewBGxZ9hMgrPiohNYAa+it+eNL/w4/EXR8BAhkkkZA22BYHtRU6zHN/7+KFuwjRFb3Q5GyLs+dMv0WzaERJMeAuAF00/5Y6tUp1E6TMXjA9oQcTyqEyIrhz03CKFsW2B/zVBkVbzkitv3CNqX3kjiqtBVbsiVf1YRUc5KaeqaNjm/sZBK8M+smSeK/pcyHLud0Ti3Ni0ea6RMoeUIaTvcRIVAdfbx4hfE6SXVgko3bis8ItLVB2Ild65VHLGzdghwlpTXidwZEnOXGZf3fUHlR4UwFvg+AkQwR81FAVmimr1g0I4NSC22X9q2bOlDRcafkaWBFJ2By7IQR0BrsUyUrZRYuqsQILn/FCu+9Ohv32WbILiR964/ttdfR5agHnuCfa5HeUWs/auwepU6r61AJLD9i/DlJrxtsQDDchMSgue0SBq4l97poPA82Zh80EzJfauy7gDs7SJPOQ==";
    private static String certTestRCAReplacement = "MIIFyTCCA7GgAwIBAgIURZhb4bmhpX9iffd6u1HjwcQMDBMwDQYJKoZIhvcNAQELBQAwdDELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0dPVjEWMBQGA1UECwwNSHVtYW5zZXJ2aWNlczE/MD0GA1UEAww2VEVTVCBNZWRpY2FyZSBBdXN0cmFsaWEgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAyMB4XDTI1MDgxMTA3MzYxNFoXDTM1MDgwOTA3MzYxNFowdDELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0dPVjEWMBQGA1UECwwNSHVtYW5zZXJ2aWNlczE/MD0GA1UEAww2VEVTVCBNZWRpY2FyZSBBdXN0cmFsaWEgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsIrNKhmi3tEh7aJVu3OkXc/YVngSel1vm2xNOFQMGYxAPEiBnhWnxhj+2a1CeieBNhAvtGJGY5OnoEgrt6FCu15nCcQ5T3oBeuVi7IFsS/vBUVunH7nOz2df+Q8MJf1MhNiimYa02jhgTbWQEacq/wPxjLhcj20TynOBXfELJK6HM4GZFx0XeSmclPjgWU+zfW7C9kakGu4gg2NEI0SaSXme5AlnMZJiRzmswMObY0tU06Xkqm6wJRodlH+gDz5tDIui6o0vyLaQCryGzkpjs+eJrWe8Jbw4C0fw6sLss04fNI62lhLmhlKNDwpUsnvuUuppqy4bnTyneCeD7bmAoXLzRuGG+WVGgKM1VDl3gAS45gW9xGqAToKKNNyfsoTb3NYYnRNc+mqq9/uqdd/OKQq1XtYho7E/gdeTtl47mdml9wUcAmGpaZXZJGdAtbxubvvHc++lNCMBJr8yS5i6U6sVgH6f56jU1IEeCRK3z6OP7vQZkTuCgeRJe7yAkfSTz0wB0BogUQ9lbBmEt+1GDvnEwf5FijGzWXruvk94VdgN6dz426V8dof1nawfRNZ/0dP1PGHr+35JzBHVIenqGVeJpjPgClB2EpdRuzNiQZS85J15k9tL5L65JTL6H5RgfuDvdeUXzCslUy3GrIUXSZYN4yAD+68I4jdlc4/zz08CAwEAAaNTMFEwHQYDVR0OBBYEFPYUlH1HW7R2pga4XQJO3BVjtzFHMB8GA1UdIwQYMBaAFPYUlH1HW7R2pga4XQJO3BVjtzFHMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBADT1raq+2SeAR4ywnACdZrxDjwsRIjiM6qE2IznVdR1yi+SRj4UmRv5+KINSI3Hq4T+RdAIcpms0y/6chiLiLTN7ocpZRxhA6ejsJVgpAhTPl6vGQ3FfuKXbdN9eXOMu3dryWZd29ltmGSZyBw7XjshCpZmnjv9lPaPGjDed1R60sofN36Su/gFh6HCRP2KEJWN9TrWmT1ASHBEt1L0gDS17P/SbdnwIebiugGBlC+MMsAtojtSE3BaaX+/Ohg6K6rhpwKAkS3R868xGD/9zMblzIh3TB/tqAJjpAYGPJuoOP60DRCgjD3fvW0xyEDzLC69+MN+LwKQ4dyRWbYFxvjnx21MXxkNzgZa64Ll0oPFMrPtPlWQU0mPQjfNR4Ap30gVmjRoYoP6z+AilMS8Ws7+KL//g/QqVmEhGGuYHITONGhEr9KT0W3ygRZSko9sBmxXoVzTmIPqeOTn9XLwSbeT1vZQQs0i1JX9bAO4cttuUr0o+EuUOHaS+ce21/CcEx3Hsryiyhr1fxY/MDZCF5ktV29BcHrqeFWW9I2GqYP1LjxKGbrfGpuRoJVCGGnI5E4JN1uRRz2+IE37S/BV0vtSk1TGYKKjHlbkRKMheTvavHQYItRTnS13bqySYnstUYY6sADlkxTL1aluqxP8yQKvH1BeBCS3k8q4NuqBGTQSy";
    private static String certTestOCA = "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";
    
    @BeforeClass
    static public void setup() {

        // Perform setup tasks
       
        // Ensure we start with a clean LDAP
        BasicLdapPublisher publ = new BasicLdapPublisher();
        publ.setBaseDN(BASEDN);
        
        // Remove the test user entry
        String userDN = "CN=general.8003625833400002.id.electronichealth.net.au,O=TestABC,DC=8003625833400002,DC=id,DC=electronichealth,DC=net,DC=au";
        userDN = publ.constructLDAPDN( userDN, null);
        // Remove the parent nodes
        deleteNode( userDN,false);
        userDN = "O=TestABC,DC=8003625833400002,DC=id,DC=electronichealth,DC=net,DC=au";
        userDN = publ.constructLDAPDN( userDN, null);
        deleteNode( userDN,true);
        
        // Delete test CA nodes
        deleteNode( "cn=TEST Medicare Australia Root Certification Authority 2,ou=Humanservices,o=GOV,c=AU", false); 
        deleteNode( "cn=TEST Medicare Australia Organisation Certification Authority 2,ou=Humanservices,o=GOV,c=AU", false);  
        deleteNode( "ou=Humanservices,o=GOV,c=AU", true);  

    }
    
    @AfterClass
    static public void cleanup() {

        // Perform cleanup tasks
       
        // Ensure we remove things we added to LDAP
        BasicLdapPublisher publ = new BasicLdapPublisher();
        publ.setBaseDN(BASEDN);
        
        // Remove the test user entry
        String userDN = "CN=general.8003625833400002.id.electronichealth.net.au,O=TestABC,DC=8003625833400002,DC=id,DC=electronichealth,DC=net,DC=au";
        userDN = publ.constructLDAPDN( userDN, null);
        // Remove the parent nodes
        deleteNode( userDN,false);
        userDN = "O=TestABC,DC=8003625833400002,DC=id,DC=electronichealth,DC=net,DC=au";
        userDN = publ.constructLDAPDN( userDN, null);
        deleteNode( userDN,true);
        
        // Delete test CA nodes
        deleteNode( "cn=TEST Medicare Australia Root Certification Authority 2,ou=Humanservices,o=GOV,c=AU", false); 
        deleteNode( "cn=TEST Medicare Australia Organisation Certification Authority 2,ou=Humanservices,o=GOV,c=AU", false);  
        deleteNode( "ou=Humanservices,o=GOV,c=AU", true);  

    }

    //
    // The "A" tests are related to CA certificates
    //
    
    @Test
    public void A01_publishRCAcert() {
        // Tests:
        //   1. A CA cert is  published by the Publisher with correct objectClass.
        //   2. Intermediary nodes are also created.
        //   3. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestRCA); 
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        // Ensure the node does not exist, so we can check if it does get created.
        deleteNode( userDN, false);
        deleteNode( DnComponents.getParentDN( userDN), true);
        
        LDAPConnection lc = null;
        try {
            // ROOTCA
            boolean res = publ.storeCertificate(null,  cert, "N/A", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA, 0, 0, null, 0, 0, null );
            assertTrue("Expecting a true result.", res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }
        try {
            // Check CA node was created
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the CA should exist.",le!=null);
            
            // Check the cert was published correctly. Can get the cACertificate, then remove cert. The size should change.
            LDAPAttribute la = le.getAttribute( "cACertificate;binary");
            assertTrue("The CA Certificate attribute should exist", la !=null);
            int totalCerts = la.size();
            la.removeValue(certInBytes);
            assertTrue("Cert was not in LDAP entry.", la.size() < totalCerts);
            
            // Check CRL/ARL - These will have a fake CRL data, so no need to check contents.
            // Check CRL attributes
            la = le.getAttribute( "certificateRevocationList;binary");
            assertTrue("The CRL attribute should exist", la !=null);
            // Check ARL attributes
            la = le.getAttribute( "authorityRevocationList;binary");
            assertTrue("The ARL attribute should exist", la !=null);
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }   

    @Test
    public void A02_publishSubCAcert() {
        // Tests:
        //   1. A Sub CA cert is  published by the Publisher with correct objectClass.
        //   2. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestOCA); 
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        // Ensure the node does not exist, so we can check if it does get created. Can leave intermediaries in place for this test.
        deleteNode( userDN, false);
        
        LDAPConnection lc = null;
        try {
            // RSubCA
            boolean res = publ.storeCertificate(null,  cert, "N/A", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_SUBCA, 0, 0, null, 0, 0, null );
            assertTrue("Expecting a true result.", res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }
        try {
            // Check CA node was created
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the CA should exist.",le!=null);
            
            // Check the cert was published correctly. Can get the cACertificate, then remove cert. The size should change.
            LDAPAttribute la = le.getAttribute( "cACertificate;binary");
            assertTrue("The CA Certificate attribute should exist", la !=null);
            int totalCerts = la.size();
            la.removeValue(certInBytes);
            assertTrue("Cert was not in LDAP entry.", la.size() < totalCerts);
            
            // Check CRL/ARL - These will have a fake CRL data, so no need to check contents.
            // Check CRL attributes 
            la = le.getAttribute( "certificateRevocationList;binary");
            assertTrue("The CRL attribute should exist", la !=null);
            // Check ARL attributes
            la = le.getAttribute( "authorityRevocationList;binary");
            assertTrue("The ARL attribute should exist", la !=null);
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }   


    @Test
    public void A03_republishSubCAcert() {
        // Tests:
        //   1. A Sub CA cert is republished by the Publisher.
        //   2. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestOCA); 
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        LDAPConnection lc = null;
        try {
            // SubCA
            boolean res = publ.storeCertificate(null,  cert, "N/A", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_SUBCA, 0, 0, null, 0, 0, null );
            assertTrue("Expecting a true result.", res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }
        try {
            // Check CA node was created
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the CA should exist.",le!=null);
            
            // Check the cert was published correctly. Can get the cACertificate, then remove cert. The size should change.
            LDAPAttribute la = le.getAttribute( "cACertificate;binary");
            assertTrue("The CA Certificate attribute should exist", la !=null);
            int totalCerts = la.size();
            la.removeValue(certInBytes);
            assertTrue("Cert was not in LDAP entry.", la.size() < totalCerts);
           
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }   

    

    @Test
    public void A04_publishReplacementRCACert() {
        // Tests:
        //   1. A RCA cert can be replaced by the Publisher.
        //   2. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestRCAReplacement); 
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        LDAPConnection lc = null;
        try {
            // RootCA
            boolean res = publ.storeCertificate(null,  cert, "N/A", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA, 0, 0, null, 0, 0, null );
            assertTrue("Expecting a true result.", res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }
        try {
            // Check CA node was created
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the CA should exist.",le!=null);
            
            // Check the cert was published correctly. Can get the cACertificate, then remove cert. The size should change.
            LDAPAttribute la = le.getAttribute( "cACertificate;binary");
            assertTrue("The CA Certificate attribute should exist", la !=null);
            int totalCerts = la.size();
            la.removeValue(certInBytes);
            assertTrue("Cert was not in LDAP entry.", la.size() < totalCerts);
           
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }   

    

    @Test
    public void A05_publishRevokeCertNotRemoved() {
        // Tests:
        //   1. A Sub CA cert that is revoked, will not be removed form LDAP, as it breaks the LDAP schema.
        //   2. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestRCAReplacement); 
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        LDAPConnection lc = null;
        try {
            // SubCA
            boolean res = publ.storeCertificate(null,  cert, "N/A", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_SUBCA, 0, 0, null, 0, 0, null );
            assertTrue("Expecting a true result.", res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }
        try {
            // Check CA node was created
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the CA should exist.",le!=null);
            
            // Check the cert still remains. Can get the cACertificate, then remove cert. The size should change.
            LDAPAttribute la = le.getAttribute( "cACertificate;binary");
            assertTrue("The CA Certificate attribute should exist", la !=null);
            int totalCerts = la.size();
            la.removeValue(certInBytes);
            assertTrue("Cert was not in LDAP entry.", la.size() < totalCerts);
           
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }   

    @Test
    public void A06_publishBustLdapNotAvailable() {
        // Tests:
        //   1. The response is an exception. This lets the cert stay on the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT+1);  // Wrong PORT setup to show a service not responding
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestRCAReplacement); 
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        LDAPConnection lc = null;
        try {
            // SubCA
            boolean res = publ.storeCertificate(null,  cert, "N/A", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_SUBCA, 0, 0, null, 0, 0, null );
            assertTrue("Expecting a fasle result.", !res);
        } catch (PublisherException e) {
            assertTrue("Expected Publisher exception: "+e,true);
        }
    }   


    
    //
    // The "B" tests are related to EE certificates
    //

    
    @Test
    public void B01_publishNashCertandCreateIntermediaries() {
        // Tests:
        //   1. Intermediary nodes are created.
        //   2 The user entry is created
        //   3. User entry contains the certificate.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_3);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        // Ensure the node does not exist, and all parent nodes to ensure intermediaries are created by publisher.
        deleteNode( userDN, true);
        
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entrywas created
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should exist.",le != null);
            
            // Check the cert was published correctly. Can get the userCertificates, then remove cert. The size should change.
            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
            assertTrue("The userCertificate attribute should exist", la !=null);
            int totalCerts = la.size();
            la.removeValue(certInBytes);
            assertTrue("Cert was not in LDAP entry.", la.size() < totalCerts);
 
            // The SN attribute should exist
            la = le.getAttribute( "sn");
            assertTrue("The sn attribute should exist", la !=null);

          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }

 
    
    @Test
    public void B02_republishNashCert() {
        // Tests:
        //   1. A re-publish of an existing user with same certificate is fine.
        //   2. No errors or exceptions so the cert gets cleared from the publisher queue.
        //   

        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_3);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
       
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry not impacted
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should exist.",le != null);
            
            // Check the cert was published correctly. Number of userCertificates should be 1.
            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
            assertTrue("The userCertificate attribute should exist", la !=null);
            assertTrue("LDAP entry should have one cert", la.size() ==1);
            
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }
       
    @Test
    public void B03_publishNashNewCertWithChanges() {
        // Tests:
        //   1. LDAP entry is updated, with extra cert.
        //   2. The new cert could have different RA Number and/or CP OID value. The attributes should be updated (employeeNumber, employeeType).
        //   
        
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_2);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
       
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry was updated
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should exist.",le != null);
            
            // Check the cert was published correctly. Can get the userCertificates, then remove cert. The size should change to one.
            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
            assertTrue("The userCertificate attribute should exist", la !=null);
            assertTrue("LDAP entry should have 2 entries.", la.size() ==2);
            la.removeValue(certInBytes);
            assertTrue("New cert was not in LDAP entry.", la.size() ==1);
            
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }

    
    @Test
    public void B04_publishNashRevokeFirstCert() {
        // Tests:
        //   1. LDAP entry is updated to remove the first cert
        //   2. As the LDAP entry had two certs, The second cert will remains.
        //   
        
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_3);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
       
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry was updated
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should exist.",le != null);
            
            // Check the cert was removed correctly. Can get the userCertificates, then remove cert ourselves. The size should stay at one.
            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
            assertTrue("The userCertificate attribute should exist", la !=null);
            assertTrue("LDAP entry should have 1 entry: "+la.toString(), la.size() ==1);
            la.removeValue(certInBytes);
            assertTrue("The revoked cert should not have been in LDAP entry.", la.size() ==1);
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }

    
 
    
    @Test
    public void B05_publishNashRevokeFirstCertAgain() {
        // Tests:
        //   1. LDAP entry is not affected as the certificate was previously removed
        //   2. No errors/exceptions so that the cert gets cleared from the publisher queue.
        //   
        
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_3);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
       
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry was updated
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should exist.",le != null);
            
            // Check there are only one cert.
            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
            assertTrue("The userCertificate attribute should exist", la !=null);
            assertTrue("LDAP entry should have 1 entry.", la.size() ==1);
            la.removeValue(certInBytes);
            assertTrue("The revoked cert should not have been in LDAP entry.", la.size() ==1);
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }


    
    @Test
    public void B06_publishNashRevokeRemainingCert() {
        // Tests:
        //   1. LDAP entry is actually removed because all certs are cleared, and the default setting is to delete the User entry.
        //   
        //   
        
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_2);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
       
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry was updated
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should not exist.",le == null);
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            if(e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
                assertTrue("Unexpected LDAP exception: "+e,false);
            }
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }


    
    @Test
    public void B07_publishNashRevokeButUserNotExist() {
        // Tests:
        //   1. LDAP entry is unchanged as User entry doesn't exist.
        //   2. No exception raise.
        //   
        
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_2);
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
       
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry was updated
        LDAPConnection lc = null;
        try {
           
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the user should not exist.",le == null);
            
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            if(e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
                assertTrue("Unexpected LDAP exception: "+e,false);
            }
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }


    
    //
    // The "C tests are related to CRLs
    //


    @Test
    public void C01_publishCRLToExistingNode() {
        // Tests:
        //   1. A CRL from a CA can be published to an existing node.
        //   2. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
        //
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        byte[] crlInBytes = Base64.decode(crlTestRCA); 
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(dnTestRCA, null);
        
        LDAPConnection lc = null;
        try {
            // CRL
            boolean res = publ.storeCRL( null, crlInBytes, null, 0, userDN );
            assertTrue("Expecting a true result.", res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }
        try {
            // Check CA node was updated
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
            assertTrue("LDAP entry for the CA should exist.",le!=null);
            
            // Check the CRL is updated. Can get the certificateRevocationList, then remove CRL. The size should change.
            LDAPAttribute la = le.getAttribute( "certificateRevocationList;binary");
            assertTrue("The CRL attribute should exist", la !=null);
            int totalCRLs = la.size();
            assertTrue("The CRL attribute should have one entry", totalCRLs == 1);
            la.removeValue(crlInBytes);
            assertTrue("CRL was not in LDAP entry.", la.size() < totalCRLs);
             la = le.getAttribute( "authorityRevocationList;binary");
            assertTrue("The ARL attribute should exist", la !=null);
            totalCRLs = la.size();
            la.removeValue(crlInBytes);
            assertTrue("ARL was not in LDAP entry.", la.size() < totalCRLs);
          
          
            // Main things checked at this point.
            // Leave LDAP entry for next test
            
        } catch ( LDAPException e) {
            // Expecting a no such object error
            assertTrue("Unexpected LDAP exception: "+e,false);
        } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }
    }   


    
    // 
    // NOTE: The following test fails because a CRL can't be published if the CA Node does not exist (nor can a delta CRL).
    // The LdapPublisher.storeCRL() method will try to create the LDAP entry, but it will fail as it doesn't create intermediaries
    // and doesn't have the CA's certificate data to publish.
    // 
    @Test
    public void C02_publishCRLToNonNode() {
        // Tests:
        //   1. Creating a new node will fail.
        //   2. The response is an exception. 
        //
        
        deleteNode( "cn=TEST Medicare Australia Root Certification Authority 2,ou=Humanservices,o=GOV,c=AU", true); 

        
        BasicLdapPublisher publ = new BasicLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, ""); // Need to use empty BaseDN as the CA cert ends in c=AU.

        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        byte[] crlInBytes = Base64.decode(crlTestRCA); 
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(dnTestRCA, null);
        
        LDAPConnection lc = null;
        try {
            // CRL
            boolean res = publ.storeCRL( null, crlInBytes, null, 0, userDN );
            assertTrue("Expecting a false result.", !res);
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,true);
        }
          
          
        // Main things checked at this point.
        // Leave LDAP entry for next test
            
    }   



    //
    // Internal helpers
    //
    
    private static void deleteNode( String dn, boolean deleteParentNodes) {
        // Notes:
        // Assumes the 'dn' is the full DN, including any Base DN.
        // Parent nodes can also be deleted. Up until BaseDN is reached.
        // Any exceptions will stop any further deletions. For example, if the EE entry doesn't exist, 
        // then an exception is caught and a return occurs. Parent nodes will not then be deleted.
        
       NASHLdapPublisher publ = new NASHLdapPublisher();
       LDAPConnection lc = null;
        try {
            
            // Try to delete the node, given the dn value.
            lc = publ.createLdapConnection();
            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
            lc.bind( LDAPConnection.LDAP_V3, LOGINDN, LOGINPASSWORD.getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
            lc.delete(dn, publ.ldapStoreConstraints);
            
            // Success. Do we need to delete parent node.(unless parent node is the Base DN - no point deleting that one!).
            String parentNode=DnComponents.getParentDN(dn);
            if (deleteParentNodes && parentNode != null && !parentNode.isBlank() && !parentNode.equalsIgnoreCase(BASEDN)) {
                // Use recursion...
                deleteNode( parentNode, true);
            }
            
            
        } catch ( LDAPException e) {
            // Catch and ignore any exceptions. 
            System.out.println("Exception thrown deleting node: "+dn);
         } finally {
            if (lc != null) {
                try {
                    lc.disconnect();
                } catch (LDAPException e) {
                    //
                }
            }
        }

    }
}
