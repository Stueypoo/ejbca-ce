/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.audit.EjbcaAuditorTestSessionRemote;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Test the combined function for editing and requesting a keystore/certificate
 * in a single transaction.
 * 
 * Note that the rollback tests requires a transactional database, if using
 * MySQL this means InnoDB and not MyISAM.
 */
public class CertificateRequestSessionSystemTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CertificateRequestSessionSystemTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateRequestSessionSystemTest"));
    private final Random random = new Random();

    private static final CertificateRequestSessionRemote certificateRequestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateRequestSessionRemote.class);
    private static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private static final EjbcaAuditorTestSessionRemote ejbcaAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaAuditorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final static String DEVICE_NAME = IntegrityProtectedDevice.class.getSimpleName();

    private static final String EE_PROFILE_NAME = "TEST_AUTOGEN_USERNAME";
    private static final String PASSWORD = "foo123";
    private static final String CN_IGNORED = "CN=Ignored";
    private static final String NAME_SN_O = ",Name=removed,SN=removed,O=removed,C=SE";
    private static final String CERT_TOOLS_SUBJDN = "CertTools.getSubjectDN: ";
    private static final int NUM_THREADS = 10;
    private static final int NUM_REQUESTS = 3;


    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * Verify that a soft token can be generated in a single transaction.
     */
    @Test
    public void testSoftTokenRequestRollback() throws Exception {
        // First try a successful request and validate the returned KeyStore
        String username = "softTokenRequestTest-" + random.nextInt();
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_JKS, null);
        userdata.setPassword(PASSWORD);
        byte[] encodedKeyStore = certificateRequestSession.processSoftTokenReq(admin, userdata, "1024",
                AlgorithmConstants.KEYALGORITHM_RSA, true);
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encodedKeyStore)) {
            // Convert encoded KeyStore to the proper return type
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
            keyStore.load(byteArrayInputStream, userdata.getPassword().toCharArray());
            assertNotNull(keyStore);
            Enumeration<String> aliases = keyStore.aliases();
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (CertTools.isSelfSigned(cert)) {
                // Ignore the CA cert and get another one
                alias = aliases.nextElement();
                cert = keyStore.getCertificate(alias);
            }
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            keyStore.getKey(alias, PASSWORD.toCharArray());
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
        }
        // Try again with a user that does not exist and use values that we will
        // break certificate generation
        // If the transaction really is rolled back successfully there will be
        // no trace of the user in the database
        // We can do this by relying on the Unique Subject DN constraint
        String username2 = "softTokenRequestTest-" + random.nextInt();
        userdata.setUsername(username2); // Still the same Subject DN
        userdata.setPassword(PASSWORD);
        assertFalse(username2 + " already exists.", endEntityManagementSession.existsUser(username2));
        try {
            certificateRequestSession.processSoftTokenReq(admin, userdata, "1024", AlgorithmConstants.KEYALGORITHM_RSA, true);
            fail("Certificate creation did not fail as expected.");
        } catch (Exception e) {
            log.debug("Got an exception as expected: " + e.getMessage());
        }
        assertFalse("Failed keystore generation request never rolled back created user '" + username2 + "'.", endEntityManagementSession.existsUser(username2));
    }

    /**
     * Verify that a soft token can be generated in a single transaction.
     */
    @Test
    public void testCertificateRequestRollback() throws Exception {
        // First try a successful request and validate the returned KeyStore
        final String username = "certificateRequestTest-user1";
        final  String username2 = "certificateRequestTest-user2";
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);
        userdata.setPassword(PASSWORD);
        String pkcs10 = new String(Base64.encode(generatePKCS10Req(CN_IGNORED, PASSWORD)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        try {
            Certificate cert = CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            // Try again with a user that does not exist and use values that we will
            // break certificate generation
            // If the transaction really is rolled back successfully there will be
            // no trace of the user in the database
            // We can do this by relying on the Unique Public Key constraint

            userdata.setUsername(username2); // Still the same Subject DN
            userdata.setPassword(PASSWORD);
            try {
                certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
                fail("Certificate creation did not fail as expected.");
            } catch (Exception e) {
                log.debug("Got an exception as expected: " + e.getMessage());
            }
            assertFalse("Failed certificate generation request never rolled back user created '" + username2 + "'.",
                    endEntityManagementSession.existsUser(username2));
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
            //If the above test failed.
            if(endEntityManagementSession.existsUser(username2)) {
                endEntityManagementSession.deleteUser(admin, username2);
            }
        }
    }

    /**
     * Test what happens if we supply empty DN fields. Created in response to ECA-1767.
     */
    @Test
    public void testEmptyFields() throws Exception {
        // First try a successful request and validate the returned KeyStore
        String username = "certificateRequestTest-" + random.nextInt();
    	final String suppliedDn = "CN=" + username + ",Name=removed,SN=removed,GIVENNAME= ,GIVENNAME=,SURNAME= ,SURNAME=,O=removed,C=SE";
    	final String expectedDn = "CN=" + username + NAME_SN_O;
        EndEntityInformation userdata = new EndEntityInformation(username, suppliedDn, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);
        userdata.setPassword(PASSWORD);
        String pkcs10 = new String(Base64.encode(generatePKCS10Req(CN_IGNORED, PASSWORD)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        try {
            Certificate cert = CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " expectedDn: " + expectedDn, expectedDn,
                    CertTools.getSubjectDN(cert));
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
        }
    }

    @Test
    public void testPiiRedactionInSigning() throws Exception {
        final String eepName = "EEP_testPiiRedactionInSigning";
        final String username = "USER_testPiiRedactionInSigning";
        final String uniqueId = UUID.randomUUID().toString();
        final String suppliedDn = "CN=Test" + uniqueId;

        EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        profile.addField(DnComponents.COMMONNAME);
        profile.setDescription("redact");
        profile.setRedactPii(true);
        profile.setAutoGeneratedUsername(true);

        try {
            // Given an EEP with redaction flag
            endEntityProfileSession.addEndEntityProfile(admin, eepName, profile);
            final int profileId = endEntityProfileSession.getEndEntityProfileId(eepName);

            EndEntityInformation userdata = new EndEntityInformation(username, suppliedDn, getTestCAId(), null, null,
                                                                     new EndEntityType(EndEntityTypes.ENDUSER), profileId,
                                                                     CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                                                                     SecConst.TOKEN_SOFT_BROWSERGEN, null);
            userdata.setPassword(PASSWORD);

            String request = new String(Base64.encode(generatePKCS10Req(CN_IGNORED+uniqueId, PASSWORD)));

            // Then certificate signing with CERT_RES_TYPE_PKCS7 type
            final long startTime = System.currentTimeMillis();
            byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, request,
                                                                                 CertificateConstants.CERT_REQ_TYPE_PKCS10,
                                                                                 CertificateConstants.CERT_RES_TYPE_PKCS7);

            // SIGNCMS event should have SubjectDN redacted.
            final List<Object> params = new ArrayList<>();
            params.add(startTime);
            params.add(EjbcaEventTypes.CA_SIGNCMS.toString());
            List<? extends AuditLogEntry> auditLogsGenerated = ejbcaAuditorSession.selectAuditLog(
                    admin, DEVICE_NAME, 0, 100,
                    "a.timeStamp >= ?1 AND a.eventType = ?2", "a.timeStamp DESC", params);

            assertEquals("Only one AuditLog should be returned", 1, auditLogsGenerated.size());
            assertTrue("Should not contain subjectDN", !auditLogsGenerated.get(0).getMapAdditionalDetails().toString().contains(suppliedDn));
            assertNotNull("A certificate should have been created", encodedCertificate);

        } finally {
            endEntityProfileSession.removeEndEntityProfile(admin, eepName);
            endEntityManagementSession.deleteUser(admin, username);
        }
    }

    /**
     * Test if username is set to auto generated in EEP certificate should be
     * issued properly.
     *
     * @throws Exception
     */
    @Test
    public void testAutoGenerateUserName() throws Exception {
        EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.DNSERIALNUMBER);
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.NAME);
        profile.setAutoGeneratedUsername(true);
        // Profile will be removed in finally clause
        try {
            endEntityProfileSession.addEndEntityProfile(admin, EE_PROFILE_NAME, profile);
            int profileId = endEntityProfileSession.getEndEntityProfileId(EE_PROFILE_NAME);

            final String uniqueId = UUID.randomUUID().toString();

            final String suppliedDn = "CN=Test" + uniqueId + NAME_SN_O;
            final String expectedDn = "CN=Test" + uniqueId + NAME_SN_O;

            EndEntityInformation userdata = new EndEntityInformation(null, suppliedDn, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), profileId,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);

            userdata.setPassword(PASSWORD);

            String pkcs10 = new String(Base64.encode(generatePKCS10Req(CN_IGNORED, PASSWORD)));
            byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);

            final Certificate cert = CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " expectedDn: " + expectedDn, expectedDn,
                    CertTools.getSubjectDN(cert));
        } finally {
            endEntityProfileSession.removeEndEntityProfile(admin, EE_PROFILE_NAME);
        }
    }
    
    @Test
    public void testHybridCsrEnroll() throws Exception {
        final String eepName = "EEP_testHybridCsrEnroll";
        final String username = "USER_testHybridCsrEnroll";
        final String uniqueId = UUID.randomUUID().toString();
        final String suppliedDn = "CN=Test" + uniqueId;

        EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        profile.addField(DnComponents.COMMONNAME);
        profile.setAutoGeneratedUsername(true);
        
        // Profile will be removed in finally clause
        try {
            endEntityProfileSession.addEndEntityProfile(admin, eepName, profile);
            final int profileId = endEntityProfileSession.getEndEntityProfileId(eepName);

            EndEntityInformation userdata = new EndEntityInformation(username, suppliedDn, getTestCAId(), null, null,
                                                                     new EndEntityType(EndEntityTypes.ENDUSER), profileId,
                                                                     CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                                                                     SecConst.TOKEN_SOFT_BROWSERGEN, null);
            userdata.setPassword(PASSWORD);

            String request = new String(Base64.encode(generateHybridPKCS10Req(CN_IGNORED+uniqueId)));

            byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, request,
                                                                                 CertificateConstants.CERT_REQ_TYPE_PKCS10,
                                                                                 CertificateConstants.CERT_RES_TYPE_PKCS7);
            
            assertNotNull("Expected Hybrid Certificate is null", encodedCertificate);

        } finally {
            endEntityManagementSession.deleteUser(admin, username);
            endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        }
    }

    /**
     * Issues certificates in parallel. Earlier versions of EJBCA, would update some attributes
     * such as timeModified and status in UserData, but in order to support parallel requests,
     * this is now done only when there is an actual change to the end entity.
     */
    @Test
    public void testConcurrentRequests() throws Exception {
        final String username = "certificateRequestTest_concurrentRequests";
        try {
            // Create test end entity
            final String suppliedDn = "CN=" + username + ",GIVENNAME=test,SURNAME=test,O=CertificateRequestTest,C=SE";
            final EndEntityInformation endEntity = new EndEntityInformation(username, suppliedDn, getTestCAId(), null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);
            endEntity.setPassword(PASSWORD);
            endEntityManagementSession.addUser(admin, endEntity, false);
            endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_GENERATED); // concurrent requests are only supported if the status is GENERATED
            // Prepare CSRs
            final String[][] pkcs10s = new String[NUM_THREADS][NUM_REQUESTS];
            for (int threadIdx = 0; threadIdx < NUM_THREADS; threadIdx++) {
                for (int reqIdx = 0; reqIdx < NUM_REQUESTS; reqIdx++) {
                    pkcs10s[threadIdx][reqIdx] = new String(Base64.encode(generatePKCS10Req(CN_IGNORED, PASSWORD)));
                }
            }
            // Prepare threads
            final Thread threads[] = new Thread[NUM_THREADS];
            final Exception exceptions[] = new Exception[NUM_THREADS];
            for (int i = 0; i < NUM_THREADS; i++) {
                final int threadIdx = i;
                threads[i] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            for (int reqIdx = 0; reqIdx < NUM_REQUESTS; reqIdx++) {
                                final EndEntityInformation endEntityInRequest = new EndEntityInformation(endEntity);
                                endEntityInRequest.setStatus(EndEntityConstants.STATUS_NEW);
                                byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, endEntityInRequest, pkcs10s[threadIdx][reqIdx],
                                        CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
                                assertNotNull(encodedCertificate);
                            }
                        } catch (Exception e) {
                            log.error("Thread " + threadIdx + " encountered an exception: " + e.getMessage(), e);
                            exceptions[threadIdx] = e;
                            throw new IllegalStateException(e);
                        }
                    }
                });
            }
            // Run test
            for (int i = 0; i < NUM_THREADS; i++) {
                threads[i].start();
            }
            for (int i = 0; i < NUM_THREADS; i++) {
                threads[i].join();
                final Exception exc = exceptions[i];
                if (exc != null) {
                    throw new IllegalStateException("Thread threw exception: " + exc.getMessage(), exc);
                }
            }
            final EndEntityInformation userAfterIssuance = endEntityAccessSession.findUser(admin, username);
            assertNotNull("UserData disappeared", userAfterIssuance);
            assertEquals("End entity status should be GENERATED after issuance.", EndEntityConstants.STATUS_GENERATED, userAfterIssuance.getStatus());
        } finally {
            internalCertificateStoreSession.removeCertificate(username);
            try {
                endEntityManagementSession.deleteUser(admin, username);
            } catch (NoSuchEndEntityException e) {
                // NOMPD ignored
            }
        }
    }
    
    private static byte[] generatePKCS10Req(String dn, String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, InvalidAlgorithmParameterException, IOException, OperatorCreationException {
        // Generate keys
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);            

        // Create challenge password attribute for PKCS10
        // Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
        //
        // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        //    type    ATTRIBUTE.&id({IOSet}),
        //    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
        // }
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
        ASN1EncodableVector values = new ASN1EncodableVector();
        values.add(new DERUTF8String(password));
        vec.add(new DERSet(values));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(vec));
        DERSet set = new DERSet(v);
        // Create PKCS#10 certificate request
        PKCS10CertificationRequest p10request = CertTools.genPKCS10CertificationRequest("SHA1WithRSA",
                DnComponents.stringToBcX500Name(dn), keys.getPublic(), set, keys.getPrivate(), null);
        return p10request.toASN1Structure().getEncoded();        
    }
    
    private static byte[] generateHybridPKCS10Req(String dn) throws InvalidAlgorithmParameterException, IOException,
            OperatorCreationException {
        // Generate keys
        KeyPair primaryKeyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);    
        KeyPair alternativeKeyPair = KeyTools.genKeys(AlgorithmConstants.KEYALGORITHM_FALCON512, 
                AlgorithmConstants.KEYALGORITHM_FALCON512);  
        
        String signatureAlgorithm = "SHA256WithRSA";
        final ContentSigner contentSigner;
        try {
            contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(primaryKeyPair.getPrivate());
        } catch (OperatorCreationException e) {
            log.error("Could not create signer for " + signatureAlgorithm + ". Error message: " + e.getMessage());
            log.error("debug", e);
            throw e;
        }

        final PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(DnComponents.stringToBcX500Name(dn),
                primaryKeyPair.getPublic());
        PKCS10CertificationRequest pkcs10CertificationRequest;
        if(alternativeKeyPair != null) {

            String alternativeSignatureAlgorithm = AlgorithmConstants.KEYALGORITHM_FALCON512;
            ContentSigner altSigner;
            try {
                altSigner = new JcaContentSignerBuilder(alternativeSignatureAlgorithm)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(alternativeKeyPair.getPrivate());
            } catch (OperatorCreationException e) {
                log.error("Could not create signer for " + alternativeSignatureAlgorithm + ". Error message: " + e.getMessage());
                throw e;
            }

            pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner, SubjectPublicKeyInfo.getInstance(alternativeKeyPair.getPublic().getEncoded()), altSigner);
        } else {
            pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner);
        }

        return pkcs10CertificationRequest.toASN1Structure().getEncoded();        
    }

}
