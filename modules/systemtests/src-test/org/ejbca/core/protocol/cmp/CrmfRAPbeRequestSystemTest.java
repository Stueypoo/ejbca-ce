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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.string.StringConfigurationCache;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionProxyRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalSystemTest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * These tests test RA functionality with the CMP protocol, i.e. a "trusted" RA sends CMP messages authenticated using PBE (password based encryption)
 * and these requests are handled by EJBCA without further authentication, end entities are created automatically in EJBCA.
 */
public class CrmfRAPbeRequestSystemTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRAPbeRequestSystemTest.class);

    private static final String P12_FOLDER_NAME = "p12";

    private static final String PBEPASSWORD = "password";

    /** userDN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations */
    private static X500Name userDN;
    private static final String USERDN_ENTERPRISE = "C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,organizationIdentifier=VATAT-U12345678,CN=cmptest";
    private static final String USERDN_COMMUNITY = "C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,CN=cmptest";
    private static String issuerDN;
    private static final String ISSUERDN_ENTERPRISE = "CN=TestCA,O=PrimeKey,OU=FoooUåäö,organizationIdentifier=VATAT-U87654321";
    private static final String ISSUERDN_COMMUNITY = "CN=TestCA,O=PrimeKey,OU=FoooUåäö";
    private final KeyPair keys;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    final static private String ALIAS = "CrmfRAPbeRequestTestConfigAlias";

    private final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private final ApprovalSessionProxyRemote approvalSessionProxyRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionProxyRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);


    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
        if (enterpriseEjbBridgeSession.isRunningEnterprise()) {
            log.debug("Testing WITH organizationIdentifier");
            userDN = new X500Name(USERDN_ENTERPRISE);
            issuerDN = ISSUERDN_ENTERPRISE;
        } else {
            log.debug("Testing WITHOUT organizationIdentifier");
            userDN = new X500Name(USERDN_COMMUNITY);
            issuerDN = ISSUERDN_COMMUNITY;
        }

        StringConfigurationCache.INSTANCE.setEncryptionKey("qhrnf.f8743;12%#75".toCharArray());
    }

    public CrmfRAPbeRequestSystemTest() throws Exception {
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        this.testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();

        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        this.keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        this.caSession.addCA(ADMIN, this.testx509ca);
        this.cmpConfiguration.addAlias(ALIAS);
        this.cmpConfiguration.setRAMode(ALIAS, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(ALIAS, true);
        this.cmpConfiguration.setResponseProtection(ALIAS, "pbe");
        this.cmpConfiguration.setRACertProfile(ALIAS, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRAEEProfile(ALIAS, String.valueOf(eepDnOverrideId));
        this.cmpConfiguration.setRACAName(ALIAS, this.testx509ca.getName());
        this.cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(ALIAS, "-;" + PBEPASSWORD);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        final CertificateProfile cp = this.certProfileSession.getCertificateProfile(CP_DN_OVERRIDE_NAME);
        cp.setAllowValidityOverride(true);
        cp.setAllowExtensionOverride(true);
        this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
        // Configure an EndEntity profile (CmpRA) with allow CN, O, C in DN
        // and rfc822Name (uncheck 'Use entity e-mail field' and check
        // 'Modifyable'), MS UPN in altNames in the end entity profile.
        final EndEntityProfile eep = this.endEntityProfileSession.getEndEntityProfile(EEP_DN_OVERRIDE_NAME);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data
        this.endEntityProfileSession.changeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME, eep);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        CaTestUtils.removeCa(ADMIN, testx509ca.getCAInfo());

        cmpConfiguration.removeAlias(ALIAS);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void testCrmfHttpOkUser() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // We should be able to back date the start time when allow validity
        // override is enabled in the certificate profile
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_WEEK, -1);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notBefore = cal.getTime();
        cal.add(Calendar.DAY_OF_WEEK, 3);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notAfter = cal.getTime();

        // In this we also test validity override using notBefore and notAfter
        // from above
        // In this test userDN contains special, escaped characters to verify
        // that that works with CMP RA as well
        final PKIMessage certRequest = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, notBefore, notAfter, null, null, null);
        runCrmfHttpOkUser(certRequest, nonce, transid, notAfter, false, null);
        // Verify that we can get extraCerts with PBE protection
        this.cmpConfiguration.setResponseExtraCertsCA(ALIAS, String.valueOf(this.testx509ca.getCAId()));
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        final CMPCertificate[] expectedExtraCerts = getCMPCert(this.testx509ca.getCACertificate());
        assertEquals("Should be one cert in expectedExtraCerts", 1, expectedExtraCerts.length);
        runCrmfHttpOkUser(certRequest, nonce, transid, notAfter, false, expectedExtraCerts);
    }

    @Test
    public void testCrmfHttpOkUserWithPQC() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // We need custom notBefore and after for the verifications of the test
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_WEEK, -1);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notBefore = cal.getTime();
        cal.add(Calendar.DAY_OF_WEEK, 3);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notAfter = cal.getTime();

        KeyPair falconKeyPair = KeyTools.genKeys("falcon-512", "falcon-512");
        final PKIMessage certRequestFalcon = genCertReq(issuerDN, userDN, falconKeyPair, this.cacert, nonce, transid, true, null, notBefore, notAfter, null, null, null);
        runCrmfHttpOkUser(certRequestFalcon, nonce, transid, notAfter, false, null);

    }

    @Test
    public void testCrmfHttpOkUserWithSAN() throws Exception {
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // We should be able to back date the start time when allow validity
        // override is enabled in the certificate profile
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_WEEK, -1);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notBefore = cal.getTime();
        cal.add(Calendar.DAY_OF_WEEK, 3);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notAfter = cal.getTime();

        // In this we also test validity override using notBefore and notAfter
        // from above
        // In this test userDN contains special, escaped characters to verify
        // that that works with CMP RA as well
        final PKIMessage certRequest = genCertReqWithSAN(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, notBefore, notAfter, null, null,
                null);
        runCrmfHttpOkUser(certRequest, nonce, transid, notAfter, true, null);
    }

    /** Tests issuance of certificates with multi-value RDN using CMP.
     * In order for this to success multi-value RDN must be enabled in the end entity profile and all DN components making up the RDN must be
     * added as fields in the profile
     */
    @Test
    public void testCrmfHttpOkUserWithMultiValueRDN() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // We should be able to back date the start time when allow validity
        // override is enabled in the certificate profile
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_WEEK, -1);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notBefore = cal.getTime();
        cal.add(Calendar.DAY_OF_WEEK, 3);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notAfter = cal.getTime();

        // Create our request message with multi-value RDN
        final String mvdn = "CN=Tomas+UID=12345,O=Test,C=SE";
        final X500Name user = new X500Name(mvdn);
        final PKIMessage certRequest = genCertReq(issuerDN, user, this.keys, this.cacert, nonce, transid, true, null, notBefore, notAfter, null, null, null);

        // In this test userDN contains multi-value RDN, which needs to be enabled in the EE profile
        EndEntityProfile eep = this.endEntityProfileSession.getEndEntityProfile(EEP_DN_OVERRIDE_NAME);
        eep.setAllowMultiValueRDNs(false);
        eep.removeField(DnComponents.UID, 0);
        this.endEntityProfileSession.changeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME, eep);

        PKIMessage req = protectPKIMessage(certRequest, false, PBEPASSWORD, 567);
        assertNotNull(req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, ALIAS);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        // We expect a response that is rejected
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, cacert, resp, reqId, ResponseStatus.FAILURE.getValue(), null);
        PKIMessage pkiMessage = PKIMessage.getInstance(resp);
        PKIBody pkiBody = pkiMessage.getBody();
        CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
        CertResponse certResponse = certRepMessage.getResponse()[0];
        PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
        assertEquals("Wrong error", "Subject DN has multi value RDNs, which is not allowed.", pkiStatusInfo.getStatusString().getStringAtUTF8(0).toString());

        // Enable multi-value RDNs in the EE profile and try again, should still fail due to no UID allowed in profile
        eep = this.endEntityProfileSession.getEndEntityProfile(EEP_DN_OVERRIDE_NAME);
        eep.setAllowMultiValueRDNs(true);
        this.endEntityProfileSession.changeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME, eep);

        resp = sendCmpHttp(ba, 200, ALIAS);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        // We expect a response that is rejected
        checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, cacert, resp, reqId, ResponseStatus.FAILURE.getValue(), null);
        pkiMessage = PKIMessage.getInstance(resp);
        pkiBody = pkiMessage.getBody();
        certRepMessage = (CertRepMessage) pkiBody.getContent();
        certResponse = certRepMessage.getResponse()[0];
        pkiStatusInfo = certResponse.getStatus();
        assertEquals("Wrong error", "Wrong number of UID fields in Subject DN.", pkiStatusInfo.getStatusString().getStringAtUTF8(0).toString());

        // Add UID to profile, so the request will succeed
        eep = this.endEntityProfileSession.getEndEntityProfile(EEP_DN_OVERRIDE_NAME);
        eep.addField(DnComponents.UID);
        this.endEntityProfileSession.changeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME, eep);

        resp = sendCmpHttp(ba, 200, ALIAS);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        // Should be an OK response
        checkCmpResponseGeneral(resp, issuerDN, user, this.cacert, nonce, transid, false, PBEPASSWORD,
                PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
        X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, ALIAS, user, this.cacert, resp, reqId);
        // Get the returned certificate and verify that it is multi-value
        assertEquals("DN should be with multi-value RDN", mvdn, cert.getSubjectDN().toString());
    }

    /** Tests a revocation without revocation reasons and without KeyId */
    @Test
    public void testCrmfHttpOkUser2NoRevocationReason() throws Exception {
        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            // In this test userDN contains special, escaped characters to verify
            // that that works with CMP RA as well
            PKIMessage one = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
            assertNotNull(req);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, this.cacert, resp, reqId);
            String altNames = DnComponents.getSubjectAlternativeName(cert);
            assertContains("Subject Alt Name", altNames, DnComponents.UPN + "=fooupn@bar.com");
            assertContains("Subject Alt Name", altNames, "rfc822name=fooemail@bar.com");

            // Ignore sending a confirm message to the CA, it will not care anyhow

            // Now revoke without any reason code extension, will result in revocation reason unspecified!
            // Also leave out (set it to null) the header.recipient field, as that can be empty according to RFC4210 section D.1
            // (we do that by leaving out cacert when calling genRevReq). We test in other places with a proper recipient.
            PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), null, nonce, transid, true, null, null);
            PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, null, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), this.cacert, resp, true);
            int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
            } catch (NoSuchEndEntityException e) {
                // NOPMD: ignore
            }
        }
    }

    /** Tests the cmp configuration settings:
     * cmp.ra.certificateprofile=KeyId
     * cmp.ra.certificateprofile=ProfileDefault
     *
     * KeyId means that the certificate profile used to issue the certificate is the same as the KeyId sent in the request.
     * ProfileDefault means that the certificate profile used is taken from the default certificate profile in the end entity profile.
     */
    @Test
    public void testKeyIdProfiles() throws Exception {
        final String keyId = "CmpTestKeyIdProfileName";
        final String keyIdDefault = "CmpTestKeyIdProfileNameDefault";

        this.cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_USE_KEYID);
        this.cmpConfiguration.setRAEEProfile(ALIAS, CmpConfiguration.PROFILE_USE_KEYID);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        try {
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();

            // Create one EE profile and 2 certificate profiles, one of the certificate profiles
            // (that does not have the same name as KeyId) will be the default in the EE profile.
            // First we will use "KeyId" for both profiles, and then we will use ProfileDefault for the cert profile
            CertificateProfile cp1 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp1.setUseSubjectAlternativeName(true);
            cp1.setAllowDNOverride(true);
            // Add a weird CDP, so we are sure this is the profile used
            final String cdp1 = "http://keyidtest/crl.crl";
            cp1.setCRLDistributionPointURI(cdp1);
            cp1.setUseCRLDistributionPoint(true);
            CertificateProfile cp2 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp2.setUseSubjectAlternativeName(false);
            cp2.setAllowDNOverride(true);
            final String cdp2 = "http://keyidtestDefault/crl.crl";
            cp2.setCRLDistributionPointURI(cdp2);
            cp2.setUseCRLDistributionPoint(true);
            try {
                this.certProfileSession.addCertificateProfile(ADMIN, keyId, cp1);
            } catch (CertificateProfileExistsException e) {
                log.error("Error adding certificate profile: ", e);
            }
            try {
                this.certProfileSession.addCertificateProfile(ADMIN, keyIdDefault, cp2);
            } catch (CertificateProfileExistsException e) {
                log.error("Error adding certificate profile: ", e);
            }

            int cpId1 = this.certProfileSession.getCertificateProfileId(keyId);
            int cpId2 = this.certProfileSession.getCertificateProfileId(keyIdDefault);
            // Configure an EndEntity profile with allow CN, O, C in DN
            // and rfc822Name (uncheck 'Use entity e-mail field' and check
            // 'Modifyable'), MS UPN in altNames in the end entity profile.
            EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId2);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId1+";"+cpId2);
            eep.setModifyable(DnComponents.RFC822NAME, 0, true);
            eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field
            // from "email" data
            try {
                this.endEntityProfileSession.addEndEntityProfile(ADMIN, keyId, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }

            // In this test userDN contains special, escaped characters to verify
            // that that works with CMP RA as well
            PKIMessage one = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, keyId, 567);
            assertNotNull(req);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, this.cacert, resp, reqId);
            String altNames = DnComponents.getSubjectAlternativeName(cert);
            assertContains("Subject Alt Name", altNames, DnComponents.UPN + "=fooupn@bar.com");
            assertContains("Subject Alt Name", altNames, "rfc822name=fooemail@bar.com");
            final String cdpfromcert1 = CertTools.getCrlDistributionPoint(cert);
            assertEquals("CDP is not correct, it probably means it was not the correct 'KeyId' certificate profile that was used", cdp1, cdpfromcert1);

            // Update property on server so that we use ProfileDefault as certificate profile, should give a little different result
            this.cmpConfiguration.setRACertProfile(ALIAS, "ProfileDefault");
            this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

            // Make new request, the certificate should now be produced with the other certificate profile
            PKIMessage two = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            PKIMessage req2 = protectPKIMessage(two, false, PBEPASSWORD, keyId, 567);
            assertNotNull(req2);

            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            cert = checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, this.cacert, resp, reqId);
            altNames = DnComponents.getSubjectAlternativeName(cert);
            assertNull(altNames);
            final String cdpfromcert2 = CertTools.getCrlDistributionPoint(cert);
            assertEquals("CDP is not correct, it probably means it was not the correct 'KeyId' certificate profile that was used", cdp2, cdpfromcert2);
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
            } catch (NoSuchEndEntityException e) {
                // NOPMD: ignore
            }
            this.endEntityProfileSession.removeEndEntityProfile(ADMIN, keyId);
            this.certProfileSession.removeCertificateProfile(ADMIN, keyId);
            this.certProfileSession.removeCertificateProfile(ADMIN, keyIdDefault);
        }
    }

    @Test
    public void testCrmfHttpTooManyIterations() throws Exception {
        log.trace(">test03CrmfHttpTooManyIterations");
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 10001);
        assertNotNull(req);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, ALIAS);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        // We expect a FailInfo.BAD_MESSAGE_CHECK
        checkCmpFailMessage(resp, "Iteration count can not exceed 10000", PKIBody.TYPE_ERROR, reqId, PKIFailureInfo.badRequest);
        log.trace("<test03CrmfHttpTooManyIterations");
    }

    @Test
    public void testRevocationApprovals() throws Exception {
        // Generate random username and CA name
        String randomPostfix = Integer.toString((new Random(new Date().getTime() + 4711)).nextInt(999999));
        String caname = "cmpRevocationCA" + randomPostfix;
        String username = "cmpRevocationUser" + randomPostfix;
        String approvalProfileName = this.getClass().getName() + "-NrOfApprovalsProfile";
        X509CAInfo cainfo = null;
        int cryptoTokenId = 0;
        List<File> fileHandles = new ArrayList<>();
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
        approvalProfile.setNumberOfApprovalsRequired(1);
        final int approvalProfileId = approvalProfileSession.addApprovalProfile(ADMIN, approvalProfile);
        try {


            // Generate CA with approvals for revocation enabled
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(ADMIN, caname, "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            int caID = RevocationApprovalSystemTest.createApprovalCA(ADMIN, caname, ApprovalRequestType.REVOCATION, approvalProfileId, this.caAdminSession, this.caSession, catoken);
            // Get CA cert
            cainfo = (X509CAInfo) this.caSession.getCAInfo(ADMIN, caID);
            assertNotNull(cainfo);
            X509Certificate newCACert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
            // Create a user and generate the cert
            EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, cainfo.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
            userdata.setPassword("foo123");
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            this.endEntityManagementSession.addUser(ADMIN, userdata, true);
            fileHandles.add(BatchCreateTool.createUser(ADMIN, new File(P12_FOLDER_NAME), username));
            Collection<Certificate> userCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
            assertEquals("Wrong number of certs returned", 1, userCerts.size());
            X509Certificate cert = (X509Certificate) userCerts.iterator().next();
            // revoke via CMP and verify response
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();
            PKIMessage rev = genRevReq(cainfo.getSubjectDN(), new X500Name(userdata.getDN()), cert.getSerialNumber(), newCACert, nonce, transid, false, null, null);
            PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(revReq);
            byte[] ba = bao.toByteArray();
            byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), new X500Name(userdata.getDN()), newCACert, nonce, transid, false,
                    PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpRevokeConfirmMessage(cainfo.getSubjectDN(), new X500Name(userdata.getDN()), cert.getSerialNumber(), newCACert, resp, true);
            int reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
            // try to revoke one more via CMP and verify error
            nonce = CmpMessageHelper.createSenderNonce();
            transid = CmpMessageHelper.createSenderNonce();
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            rev = genRevReq(cainfo.getSubjectDN(), new X500Name(userdata.getDN()), cert.getSerialNumber(), newCACert, nonce, transid, false, null, null);
            revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), new X500Name(userdata.getDN()), newCACert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpFailMessage(resp, "The request is already awaiting approval.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0, PKIFailureInfo.badRequest);
            reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
            // Approve revocation and verify success

            approveRevocation(ADMIN, ADMIN, username, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE,
                    ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, cainfo.getCAId(), approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID,
                    approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier());
            // try to revoke the now revoked cert via CMP and verify error
            nonce = CmpMessageHelper.createSenderNonce();
            transid = CmpMessageHelper.createSenderNonce();
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            rev = genRevReq(cainfo.getSubjectDN(), new X500Name(userdata.getDN()), cert.getSerialNumber(), newCACert, nonce, transid, false, null, null);
            revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), new X500Name(userdata.getDN()), newCACert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpFailMessage(resp, "Already revoked.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0, PKIFailureInfo.certRevoked);
        } finally {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileId);
            // Delete user
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {} // NOPMD
            // Nuke CA
            CaTestUtils.removeCa(ADMIN, cainfo);
            for(File file : fileHandles) {
                FileTools.delete(file);
            }

            CryptoTokenTestUtils.removeCryptoToken(ADMIN, cryptoTokenId);
        }
    } // test04RevocationApprovals


    @Test
    public void testCrmfEmptyDN() throws Exception {
        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            // Create a request with non-existing subjectDN
            PKIMessage one = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            assertNotNull(one);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
            assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, this.cacert, resp, reqId);
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
            } catch (NoSuchEndEntityException e) {
                // NOPMD: ignore
            }
        }
    }

    /**
     * Find all certificates for a user and approve any outstanding revocation.
     */
    @Override
    protected int approveRevocation(AuthenticationToken admin, AuthenticationToken approvingAdmin, String username, int reason,
            int approvalType,  int approvalCAID, final ApprovalProfile approvalProfile, final int sequenceId, final int partitionId) throws Exception {
        Collection<java.security.cert.Certificate> userCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
        Iterator<java.security.cert.Certificate> i = userCerts.iterator();
        int approvedRevocations = 0;
        while (i.hasNext()) {
            X509Certificate cert = (X509Certificate) i.next();
            final String issuer = cert.getIssuerDN().toString();
            BigInteger serialNumber = cert.getSerialNumber();
            boolean isRevoked = certificateStoreSession.isRevoked(issuer, serialNumber);
            if ((reason != RevokedCertInfo.NOT_REVOKED && !isRevoked) || (reason == RevokedCertInfo.NOT_REVOKED && isRevoked)) {
                int approvalID;
                if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuer,
                            approvalProfile.getProfileName(), null);
                } else {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null,
                            approvalProfile.getProfileName(), null);
                }
                Query q = new Query(Query.TYPE_APPROVALQUERY);
                q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
                final List<ApprovalDataVO> approvalRequests = approvalSessionProxyRemote.query(q, 0, 1, "cAId=" + approvalCAID,
                        "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
                assertEquals("Could not find approval by CA ID and EEP ID.", 1, approvalRequests.size());
                Approval approval = new Approval("Approved during testing.", sequenceId, partitionId);
                approvalExecutionSession.approve(approvingAdmin, approvalID, approval);
                ApprovalDataVO approvalData = approvalSession.findApprovalDataVO(approvalID).iterator().next();
                assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
                CertificateStatus status = certificateStoreSession.getStatus(issuer, serialNumber);
                assertEquals(status.revocationReason, reason);
                approvalSession.removeApprovalRequest(admin, approvalData.getId());
                approvedRevocations++;
            }
        }
        return approvedRevocations;
    } // approveRevocation

    private void runCrmfHttpOkUser(final PKIMessage one, final byte[] nonce, final byte[] transid, final Date notAfter, final boolean SANTest, final CMPCertificate[] expectedExtraCerts) throws Exception {
        try {
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
            assertNotNull(req);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Wait 1 ms so the notBefore time of the CA becomes different from the current time, so we can check that validity override works
            try {
                Thread.sleep(1);
            } catch (InterruptedException ie) {
                throw new IllegalStateException(ie);
            }
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, ALIAS, userDN, this.cacert, resp, reqId);
            // Check that validity override works
            assertEquals("'Not Before' should be limited by the CA not before date.", cacert.getNotBefore(), cert.getNotBefore());
            assertEquals("Wrong 'Not After' date.", notAfter, cert.getNotAfter());
            String altNames = DnComponents.getSubjectAlternativeName(cert);
            assertContains("Subject Alt Name", altNames, DnComponents.UPN + "=fooupn@bar.com");
            assertContains("Subject Alt Name", altNames, DnComponents.EMAIL + "=fooemail@bar.com");
            if (SANTest) {
                assertContains("Subject Alt Name", altNames, DnComponents.DIRECTORYNAME + "=c=SE\\,cn=foobar");
            }
            // check for extraCerts
            PKIMessage respObject = PKIMessage.getInstance(resp);
            CMPCertificate[] extraCerts = respObject.getExtraCerts();
            if (expectedExtraCerts == null) {
                assertNull("There should be no extraCerts", extraCerts);
            } else {
                assertCmpCertificateArrayEquals("Expected PKI response message 'extraCerts' field does not match after certificate issuance.", expectedExtraCerts, extraCerts);
            }

            // Send a confirm message to the CA
            String hash = "foo123";
            PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, reqId, null);
            assertNotNull(confirm);
            PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req1);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpPKIConfirmMessage(userDN, this.cacert, resp);
            // no extraCerts in Confirm Message
            respObject = PKIMessage.getInstance(resp);
            extraCerts = respObject.getExtraCerts();
            assertNull("We did not expect any extraCerts in CMP confirm message, but we got some", extraCerts);

            // Now revoke the bastard including the CMPv2 reason code extension!
            PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), this.cacert, nonce, transid, false, null, null);
            PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), this.cacert, resp, true);
            int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            // no extraCerts in Revoke Response Message
            respObject = PKIMessage.getInstance(resp);
            extraCerts = respObject.getExtraCerts();
            assertNull("We did not expect any extraCerts in CMP confirm message, but we got some", extraCerts);

            // Create a revocation request for a non existing cert, should fail (revocation response with status failure)!
            rev = genRevReq(issuerDN, userDN, new BigInteger("1"), this.cacert, nonce, transid, true, null, null);
            revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, ALIAS);
            checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
            checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), this.cacert, resp, false);
            // no extraCerts in Revoke Response Message
            respObject = PKIMessage.getInstance(resp);
            extraCerts = respObject.getExtraCerts();
            assertNull("We did not expect any extraCerts in CMP confirm message, but we got some", extraCerts);
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
            } catch (NoSuchEndEntityException e) {
                // NOPMD: ignore
            }
        }
    }

    private static void assertContains(final String description, final String stringToCheck, final String expectedToContain) {
        assertTrue(description + " did not contain '" + expectedToContain + "'. Was: '" + stringToCheck + "'", stringToCheck.contains(expectedToContain));
    }
}
