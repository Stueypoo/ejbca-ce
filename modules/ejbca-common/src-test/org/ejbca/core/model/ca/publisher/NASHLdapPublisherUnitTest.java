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
public class NASHLdapPublisherUnitTest {

    //
    // DEFAULT SETTINGS FOR TESTING
    //
    private static int CPFORNASH = 0; //1725522583
    private static String BASEDN = "c=au"; 
    private static String HOSTNAMES = "localhost"; 
    private static String PORT = "389"; 
    private static String LOGINDN = "cn=Manager,c=au"; 
    private static String LOGINPASSWORD = "Verizon1!"; 
    private static String VALIDCPOIDS = "1.2.36.174030967.1.20.1.1;1.2.36.174030967.1.22.1.1;1.2.36.174030967.1.10.1.1;1.2.36.174030967.1.12.1.1";
    private static String CONNECTIONSECURITY = "PLAIN";
    
    //
    /// Test Certs. NASH example cert with various differences for testing.
    //
    // "CN=general.8003625833400002.id.electronichealth.net.au,O=TestABC,DC=8003625833400002,DC=id,DC=electronichealth,DC=net,DC=AU"
    // HCID: 8003625833400002
    // RANumber: 9879879871
    // CP OID: 1.2.36.174030967.1.20.1.1
    private static String certTestABC_3 = "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";
    // private static String certTestABC_2 = "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";
    
    // RA number=9879879870 (HCID and OID as above)
    // private static String certTestABC_1 = "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";
    
    // RA number=9879879870 (HCID as above)
    // CP OID: 1.2.36.174030967.1.22.1.1
    private static String certTestABC_4 = "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";

    private static String certTestRCA = "MIIEujCCA6KgAwIBAgIBCjANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJBVTEMMAoGA1UEChMDR09WMRYwFAYDVQQLEw1IdW1hbnNlcnZpY2VzMT0wOwYDVQQDEzRURVNUIE1lZGljYXJlIEF1c3RyYWxpYSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTI1MDIxOTIzNDA1MVoXDTQ1MDIxOTIzNDA1MVowcjELMAkGA1UEBhMCQVUxDDAKBgNVBAoTA0dPVjEWMBQGA1UECxMNSHVtYW5zZXJ2aWNlczE9MDsGA1UEAxM0VEVTVCBNZWRpY2FyZSBBdXN0cmFsaWEgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANB/q/AVqubUAyv0/NSra8D1RYdXWriwdcyzIpDxNKhHZ7t7cuyaJHpnHc9YwImrIX9qlRbnQwqHeI178qIClWeNFn8idn0CFsqtRF69m+QTNBe7IwkueZVLI4YF6EU2mUDF/XAX162jwoOvGS1/iQm/vLTarJJZ7y3UMBpXPbqGgqKGM2Fw5jSgrQvN5/hin5qv0hNUYnvGeUjaJqYLWRrsaDtZ25xsSO9TWU6WbPZ6o+2+SZXMi+PN4NrDnp0t+FLP847dLLo4X4U+CwyHpw50wKzBS2LGclG5xZBN30ZAnbSUlkC2uC3YvLoapsh+9CpbbSlW58+CtrdTPH11reMCAwEAAaOCAVkwggFVMA8GA1UdEwEB/wQFMAMBAf8wgfQGA1UdIASB7DCB6TCB5gYKKiTS/oB3AQICATCB1zCBpwYIKwYBBQUHAgIwgZoagZdDZXJ0aWZpY2F0ZXMgdW5kZXIgdGhpcyBwb2xpY3kgYXJlIGlzc3VlZCBieSB0aGUgVEVTVCBNZWRpY2FyZSBBdXN0cmFsaWEgUm9vdCBDQSB0byBpdHNlbGYgb3IgdG8gQ0FzIHN1Ym9yZGluYXRlIHRvIHRoZSBURVNUIE1lZGljYXJlIEF1c3RyYWxpYSBSb290IENBMCsGCCsGAQUFBwIBFh9odHRwOi8vd3d3Lmh1bWFuc2VydmljZXMuZ292LmF1MAsGA1UdDwQEAwIBBjAfBgNVHSMEGDAWgBT+plzlGprY+KDPyM6YJBCwp91YFTAdBgNVHQ4EFgQU/qZc5Rqa2Pigz8jOmCQQsKfdWBUwDQYJKoZIhvcNAQELBQADggEBAA8cRT3Q8/xcUvZa8pBMx0Drsx9QyEWav96DCe//0nurqJAiF+1ZOSfJPEJeBS0ZUXKv+iG2zOzVmPk4SOSdw9r4pbJJn/STEUZ8fOx1GnTaQAqnH7n/o/dPu4thLsjIvzFdunS+sg4yxDGzlJc4ZEhGLAITOPnavFgJsCcoyKu25dGaU5gbeoo/b6jB6ltvdCdiKcB0IqTXaDgU+3a2792ol2TQpqlWA2IzxoKY7EyMWmzst/w64TmhUyynjEq9SE8tVLVjon02REHuGKqYbupZkZ3qC11WREOY5Zby+FSJKccKTqViXU4oIahwmwf7t39k6vxrwnxSW/M/wcm/0q4=";

    
    @BeforeClass
    static public void setup() {

        // Perform setup tasks
       
        // Ensure we start with a clean LDAP
        NASHLdapPublisher publ = new NASHLdapPublisher();
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
        deleteNode( "cn=TEST Medicare Australia Root Certification Authority,ou=Humanservices,o=GOV", false);  // baseDN is c=AU
        deleteNode( "ou=Humanservices,o=GOV", true);  // baseDN is c=AU

    }
 
    
    @Test
    public void A01_publishRCAcert() {
        // Tests:
        //   1. A CA cert is published  with correct objectClass.
        //   2. No NASH attributes are included
        //   3. The response is OK and no exception. This lets the cert get cleared from the publisher queue.
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
        byte[] certInBytes = Base64.decode(certTestABC_3);  // We can use a user cert, even if publishing a CA entry.
        try {
            cert = CertTools.getCertfromByteArray( certInBytes);
        } catch (CertificateParsingException e) {
            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
        }
        
        // Construct the LDAP DN
        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
        
        // Ensure the node does not exist, so we can check if it does get created.
        deleteNode( userDN, false);
        
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
            
            // Check employeeType attributes doesn't exist
            la = le.getAttribute( "employeeType");
            assertTrue("The employeeType attribute should not exist", la==null);
            // Check employeeNumber attributes doesn't exist
            la = le.getAttribute( "employeeNumber");
            assertTrue("The employeeNumber attribute should not exist", la==null);
            
          
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
    public void B01_publishNashCertandCreateIntermediaries() {
        // Tests:
        //   1. Intermediary nodes are created.
        //   2 The user entry is created
        //   3. User entry contains the certificate, plus attributes being: dc, employeeType, employeeNumber.
        //
        NASHLdapPublisher publ = new NASHLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

//        pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
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
        deleteNode( DnComponents.getParentDN( userDN), true);
        
        try {
            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
        } catch (PublisherException e) {
            assertTrue("Unexpected Publisher exception: "+e,false);
        }

        // Check the LDAP entry was created
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
            
            // There should be a dc attribute with healthcare ID
            la = le.getAttribute("dc");
            assertTrue( "The 'dc' value was missing", la!=null);
            //LDAPAttribute dcFromDN = (LDAPAttribute) publ.getAttributesFromDN(userDN, new String[] {"dc"}).toArray()[0];
            assertTrue( "The 'dc' value was incorrect: "+la.toString(),la.getStringValue().equals("8003625833400002"));
            
            // There should be an EmployeeType with CP OID
            la = le.getAttribute("employeeType");
            assertTrue( "The 'employeeType' value was missing", la!=null);
            // Get the CP OID from cert
            //List<ASN1ObjectIdentifier> cpOidsInCert;
            //try {
                // Get the CP OID from the certificate
                //cpOidsInCert = com.keyfactor.util.CertTools.getCertificatePolicyIds( cert);
                assertTrue("The 'employeeType' was not correct:"+la.toString(), la.getStringValue().equals( "1.2.36.174030967.1.20.1.1"));
            //} catch (IOException e) {
            //    assertTrue("Could not extract the Certificate Policy OID from certificate.", false);
            //}

            // There should be an eemployeeNumber with RA value (from cert extension) 
            la = le.getAttribute("employeeNumber");
            assertTrue( "The 'employeeNumber' value was missing", la!=null);
            //ASN1Primitive ans = CertTools.getExtensionValue( (X509Certificate) cert, "1.2.36.73665175.1.10009");
            //assertTrue( "The 'employeeNumber' value was missing from cert", ans!=null);
            //ASN1IA5String raNumber = ASN1IA5String.getInstance(ans);
            //assertTrue( "The 'RANumber' value was missing from cert", raNumber!=null);
            assertTrue("The 'employeeNumber' was not correct:"+la.toString(), la.getStringValue().equals( "9879879871"));
           
          
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
    public void B02_publishNashNewCertWithChanges() {
        // Tests:
        //   1. LDAP entry is updated, with extra cert.
        //   2. The new cert could have different RA Number and/or CP OID value. The attributes should be updated (employeeNumber, employeeType).
        //   
        
        NASHLdapPublisher publ = new NASHLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

//        pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_4);
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
            
            // There should be a dc attribute with healthcare ID
            la = le.getAttribute("dc");
            assertTrue( "The 'dc' value was missing", la!=null);
            assertTrue( "The 'dc' value was incorrect: "+la.toString(),la.getStringValue().equals("8003625833400002"));
            
            // There should be an EmployeeType with CP OID. Differrent OID this time.
            la = le.getAttribute("employeeType");
            assertTrue( "The 'employeeType' value was missing", la!=null);
            assertTrue("The 'employeeType' was not correct:"+la.toString(), la.getStringValue().equals( "1.2.36.174030967.1.22.1.1"));

            // There should be an eemployeeNumber with RA value (from cert extension. Different RA Number
            la = le.getAttribute("employeeNumber");
            assertTrue( "The 'employeeNumber' value was missing", la!=null);
            assertTrue("The 'employeeNumber' was not correct:"+la.toString(), la.getStringValue().equals( "9876543210"));
           
          
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
        
        NASHLdapPublisher publ = new NASHLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

 //       pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
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

    
 
//    
//    @Test
//    public void B05_publishNashRevokeFirstCertAgain() {
//        // Tests:
//        //   1. LDAP entry is not affected as the certificate was previously removed
//        //   2. No errors/exceptions so that the cert gets cleared from the publisher queue.
//        //   
//        
//        NASHLdapPublisher publ = new NASHLdapPublisher();
//        Properties pros = new Properties();
//        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
//        pros.setProperty( publ.PORT, PORT);
//        pros.setProperty( publ.LOGINDN, LOGINDN);
//        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
//        pros.setProperty( publ.BASEDN, BASEDN);
//
//        pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
//        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
//        publ.init( pros);
//
//        
//        Certificate cert=null;
//        byte[] certInBytes = Base64.decode(certTestABC_3);
//        try {
//            cert = CertTools.getCertfromByteArray( certInBytes);
//        } catch (CertificateParsingException e) {
//            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
//        }
//        
//        // Construct the LDAP DN
//        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
//        
//       
//        try {
//            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
//        } catch (PublisherException e) {
//            assertTrue("Unexpected Publisher exception: "+e,false);
//        }
//
//        // Check the LDAP entry was updated
//        LDAPConnection lc = null;
//        try {
//           
//            lc = publ.createLdapConnection();
//            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
//            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
//            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
//            assertTrue("LDAP entry for the user should exist.",le != null);
//            
//            // Check there are only one cert.
//            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
//            assertTrue("The userCertificate attribute should exist", la !=null);
//            assertTrue("LDAP entry should have 1 entry.", la.size() ==1);
//            la.removeValue(certInBytes);
//            assertTrue("The revoked cert should not have been in LDAP entry.", la.size() ==1);
//            
//          
//            // Main things checked at this point.
//            // Leave LDAP entry for next test
//            
//        } catch ( LDAPException e) {
//            assertTrue("Unexpected LDAP exception: "+e,false);
//        } finally {
//            if (lc != null) {
//                try {
//                    lc.disconnect();
//                } catch (LDAPException e) {
//                    //
//                }
//            }
//        }
//    }
//
//
    
    @Test
    public void B06_publishNashRevokeRemainingCert() {
        // Tests:
        //   1. LDAP entry is actually removed because all certs are cleared, and the default setting is to delete the User entry.
        //   
        //   
        
        NASHLdapPublisher publ = new NASHLdapPublisher();
        Properties pros = new Properties();
        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
        pros.setProperty( publ.PORT, PORT);
        pros.setProperty( publ.LOGINDN, LOGINDN);
        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
        pros.setProperty( publ.BASEDN, BASEDN);

//        pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
        publ.init( pros);

        
        Certificate cert=null;
        byte[] certInBytes = Base64.decode(certTestABC_4);
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


    
//    @Test
//    public void B07_publishNashRevokeButUserNotExist() {
//        // Tests:
//        //   1. LDAP entry is unchanged as User entry doesn't exist.
//        //   2. No exception raise.
//        //   
//        
//        NASHLdapPublisher publ = new NASHLdapPublisher();
//        Properties pros = new Properties();
//        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
//        pros.setProperty( publ.PORT, PORT);
//        pros.setProperty( publ.LOGINDN, LOGINDN);
//        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
//        pros.setProperty( publ.BASEDN, BASEDN);
//
//        pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
//        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
//        publ.init( pros);
//
//        
//        Certificate cert=null;
//        byte[] certInBytes = Base64.decode(certTestABC_4);
//        try {
//            cert = CertTools.getCertfromByteArray( certInBytes);
//        } catch (CertificateParsingException e) {
//            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
//        }
//        
//        // Construct the LDAP DN
//        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
//        
//       
//        try {
//            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
//        } catch (PublisherException e) {
//            assertTrue("Unexpected Publisher exception: "+e,false);
//        }
//
//        // Check the LDAP entry was updated
//        LDAPConnection lc = null;
//        try {
//           
//            lc = publ.createLdapConnection();
//            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
//            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
//            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
//            assertTrue("LDAP entry for the user should not exist.",le == null);
//            
//          
//            // Main things checked at this point.
//            // Leave LDAP entry for next test
//            
//        } catch ( LDAPException e) {
//            // Expecting a no such object error
//            if(e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
//                assertTrue("Unexpected LDAP exception: "+e,false);
//            }
//        } finally {
//            if (lc != null) {
//                try {
//                    lc.disconnect();
//                } catch (LDAPException e) {
//                    //
//                }
//            }
//        }
//    }
//

    
//    @Test
//    public void B08_publishNashRevokeButKeepUser() {
//        // Tests:
//        //   1. Use an option to prevent the deletion of a User when their one remaining cert is revoked.
//        //   
//        
//        NASHLdapPublisher publ = new NASHLdapPublisher();
//        Properties pros = new Properties();
//        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
//        pros.setProperty( publ.PORT, PORT);
//        pros.setProperty( publ.LOGINDN, LOGINDN);
//        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
//        pros.setProperty( publ.BASEDN, BASEDN);
//
//        pros.setProperty( publ.VALIDCPOIDS, VALIDCPOIDS);
//        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
//        publ.init( pros);
//
//        // Need this option turned off.
//        publ.setRemoveUsersWhenCertRevoked(false);
//        
//        Certificate cert=null;
//        byte[] certInBytes = Base64.decode(certTestABC_4);
//        try {
//            cert = CertTools.getCertfromByteArray( certInBytes);
//        } catch (CertificateParsingException e) {
//            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
//        }
//        
//        // Construct the LDAP DN
//        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert), null);
//        
//        // Ensure the User doesn't exit
//        deleteNode( userDN, false);
//        
//       
//        try {
//            // Publish cert. We can assume this works because we have tested it earlier
//            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
//            // Revoke cert
//            publ.storeCertificate(null,  cert, "UnitTestNash1", null, null, null, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
//        } catch (PublisherException e) {
//            assertTrue("Unexpected Publisher exception: "+e,false);
//        }
//
//        // Check the LDAP entry exists but has no certificates
//        LDAPConnection lc = null;
//        try {
//           
//            lc = publ.createLdapConnection();
//            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
//            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
//            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
//            assertTrue("LDAP entry for the user should  exist.",le != null);
// 
//            // Check there are only one cert.
//            LDAPAttribute la = le.getAttribute( "userCertificate;binary");
//            assertTrue("The userCertificate attribute should not exist", la ==null);
//
//          
//            // Main things checked at this point.
//            // Leave LDAP entry for next test
//            
//        } catch ( LDAPException e) {
//            // Expecting a no such object error
//            if(e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
//                assertTrue("Unexpected LDAP exception: "+e,false);
//            }
//        } finally {
//            if (lc != null) {
//                try {
//                    lc.disconnect();
//                } catch (LDAPException e) {
//                    //
//                }
//            }
//        }
//    }
//
//
//    
//    @Test
//    public void B9_InvalidCPOid() {
//        // Tests:
//        //   1. Certs are not published unless they have a valid CP OID.
//        //   2. No exceptions raised.
//        
//        NASHLdapPublisher publ = new NASHLdapPublisher();
//        Properties pros = new Properties();
//        pros.setProperty( publ.HOSTNAMES, HOSTNAMES);
//        pros.setProperty( publ.PORT, PORT);
//        pros.setProperty( publ.LOGINDN, LOGINDN);
//        pros.setProperty( publ.LOGINPASSWORD, LOGINPASSWORD);
//        pros.setProperty( publ.BASEDN, BASEDN);
//
//        // Policy OIDs here should not publish the test certs.
//        pros.setProperty( publ.VALIDCPOIDS, "1.3.36.174030967.1.20.1.1;1.2.36.174030967.1.22.1.2");
//        pros.setProperty( publ.CONNECTIONSECURITY, CONNECTIONSECURITY);
//        publ.init( pros);
//
//        // Try two different certs, neither should work.
//        Certificate cert3=null;
//        Certificate cert4=null;
//        byte[] certInBytes3= Base64.decode(certTestABC_3);
//        byte[] certInBytes4 = Base64.decode(certTestABC_4);
//        try {
//            cert3 = CertTools.getCertfromByteArray( certInBytes3);
//            cert4 = CertTools.getCertfromByteArray( certInBytes4);
//        } catch (CertificateParsingException e) {
//            assertEquals("Certificate encoding issue: "+e.getMessage(),false);
//        }
//        
//        // Construct the LDAP DN
//        String userDN = publ.constructLDAPDN(CertTools.getSubjectDN(cert4), null);
//        
//        // Ensure the User doesn't exit
//        deleteNode( userDN, false);
//        
//       
//        try {
//            // Try to publish cert.
//            publ.storeCertificate(null,  cert3, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
//            publ.storeCertificate(null,  cert4, "UnitTestNash1", null, null, null, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null );
//        } catch (PublisherException e) {
//            assertTrue("Unexpected Publisher exception: "+e,false);
//        }
//
//        // Check the LDAP entry should not exists 
//        LDAPConnection lc = null;
//        try {
//           
//            lc = publ.createLdapConnection();
//            lc.connect( HOSTNAMES, Integer.parseInt(PORT));
//            lc.bind( LDAPConnection.LDAP_V3, publ.getLoginDN(), publ.getLoginPassword().getBytes(StandardCharsets.UTF_8), publ.ldapBindConstraints);
//            LDAPEntry le = lc.read( userDN,  publ.ldapSearchConstraints);
//            assertTrue("LDAP entry for the user should not exist.",le == null);
// 
//          
//            // Main things checked at this point.
//            // Leave LDAP entry for next test
//            
//        } catch ( LDAPException e) {
//            // Expecting a no such object error
//            if(e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
//                assertTrue("Unexpected LDAP exception: "+e,false);
//            }
//        } finally {
//            if (lc != null) {
//                try {
//                    lc.disconnect();
//                } catch (LDAPException e) {
//                    //
//                }
//            }
//        }
//    }
//
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
