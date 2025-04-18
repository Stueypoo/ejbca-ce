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

package org.ejbca.core.ejb.ca.caadmin;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.KeyGenParams;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.RenewCAWorker;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import jakarta.ejb.EJBException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests related to renewing CAs
 */
public class RenewCASystemTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RenewCASystemTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RenewCASystemTest"));

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

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

    /** Test renewal of a CA. */
    @Test
    public void test01renewCA() throws Exception {
        log.trace(">test01renewCA()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        // Sleep at least for one second so we are not so fast that we create a new cert with the same time
        Thread.sleep(2000);
        caAdminSession.renewCA(internalAdmin, info.getCAId(), false, null, false);
        X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
        X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        byte[] orgkey = orgcert.getPublicKey().getEncoded();
        byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue(Arrays.equals(orgkey, samekey));
        // The new certificate must have a validity greater than the old cert
        assertTrue("newcertsamekeys.getNotAfter: " + newcertsamekeys.getNotAfter() + " orgcert.getNotAfter: " + orgcert.getNotAfter(),
                newcertsamekeys.getNotAfter().after(orgcert.getNotAfter()));
        caAdminSession.renewCA(internalAdmin, info.getCAId(), true, null, false);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
        X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
        byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse(Arrays.equals(orgkey, newkey));
        log.trace("<test01renewCA()");
    }


    /** Test renewal of a CA using a different key algorithm.
     */
    @Test
    public void testRenewCAChangeKeyAlg() throws Exception {
        log.trace(">testRenewCAChangeKeyAlg()");

        // Prepare to renew CA but with an EC key instead of RSA
        {
            final X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
            final CAToken caToken = info.getCAToken();
            // The current Signing Algorithm should be RSA based
            final X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
            final String previousSigAlg = AlgorithmTools.getSignatureAlgorithm(orgcert);
            assertEquals("Current CA's Signature Algorithm should be RSA", AlgorithmConstants.SIGALG_SHA1_WITH_RSA, previousSigAlg);
            // Create an EC key with a new alias
            final String nextKeyAlias = "signKeyRenewalEC";
            cryptoTokenManagementSession.createKeyPair(internalAdmin, caToken.getCryptoTokenId(), nextKeyAlias, KeyGenParams.builder("prime256v1").build());

            // To get EJBCA to renew a CA with a different key algorithm, we need to set the new signing algorithm in the CA's token,
            caToken.setSignatureAlgorithm( AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
            // Update the CA with the new CAToken signature algorithm
            caSession.editCA(internalAdmin, info);

            // We are all set and now ready to renew the CA
            caAdminSession.renewCA(internalAdmin, info.getCAId(), nextKeyAlias, null, /*CreateLinkCert*/true);
            // Check the CA's new certificate has the ECDSA based signing algorithm
            final X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
            final X509Certificate newcert = (X509Certificate) newinfo.getCertificateChain().iterator().next();
            final String newSigAlg = AlgorithmTools.getSignatureAlgorithm(newcert);
            assertEquals("New signature algorithm should be ECDSA", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, newSigAlg);

            // Check the Link certificate was signed using the previous Signing Algorithm
            final byte[] linkCertificateAfterRenewalBytes = caAdminSession.getLatestLinkCertificate(newinfo.getCAId());
            assertNotNull("There is no available link certificate after CA renewal with EC key", linkCertificateAfterRenewalBytes);
            final X509Certificate linkCertificateAfterRenewal = CertTools.getCertfromByteArray(linkCertificateAfterRenewalBytes, X509Certificate.class);
            assertEquals("The link certificate should be signed by the CA's previous signing algorithm", previousSigAlg.toUpperCase(), CertTools.getCertSignatureAlgorithmNameAsString(linkCertificateAfterRenewal).toUpperCase());

            // Check the SignatureAlgorithm on the CA's Token is still set correctly
            assertEquals("The signature algorithm on the CA's token was changed and should be ECDSA", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, caToken.getSignatureAlgorithm());

            // Check the link cert's IssuerDN matches the original CA's SubjectDN
            assertEquals("The IssuerDN of the link certificate does not match the SubjectDN of the old CA certificate.", orgcert.getSubjectDN(), linkCertificateAfterRenewal.getIssuerDN());

            // Check the link cert's SubjectDN matches the original CA's SubjectDN
            // Note: Because there was not a Name change occurring
            assertEquals("The SubjectDN of the link certificate does not match the SubjectDN of the old CA certificate.", orgcert.getSubjectDN(), linkCertificateAfterRenewal.getSubjectDN());

            // Check validity period, notAfter in the link certificate should be same as notAfter in the old CA certificate
            assertEquals("notAfter in the link certificate should be the same as notAfter in the old CA certificate.", orgcert.getNotAfter(), linkCertificateAfterRenewal.getNotAfter());
            // notBefore in the link certificate should be same as notBefore in the new CA certificate
            assertEquals("notBefore in the link certificate should be the same as notBefore in the new CA certificate.", newcert.getNotBefore(), linkCertificateAfterRenewal.getNotBefore());
        }

        // Prepare to renew CA but with a ML-DSA key instead of EC
        final byte[] linkCertificateAfterRenewalBytes;
        {
            final X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
            final CAToken caToken = info.getCAToken();
            // The current Signing Algorithm should be EC based
            final X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
            final String previousSigAlg = AlgorithmTools.getSignatureAlgorithm(orgcert);
            assertEquals("Current CA's Signature Algorithm should be EC", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, previousSigAlg);
            // Create a ML-DSA-44 key with a new alias
            final String nextKeyAlias = "signKeyRenewalMLDSA44";
            cryptoTokenManagementSession.createKeyPair(internalAdmin, caToken.getCryptoTokenId(), nextKeyAlias, KeyGenParams.builder(AlgorithmConstants.KEYALGORITHM_MLDSA44).build());

            // To get EJBCA to renew a CA with a different key algorithm, we need to set the new signing algorithm in the CA's token,
            caToken.setSignatureAlgorithm( AlgorithmConstants.SIGALG_MLDSA44);
            // Update the CA with the new CAToken signature algorithm
            caSession.editCA(internalAdmin, info);

            // We are all set and now ready to renew the CA
            caAdminSession.renewCA(internalAdmin, info.getCAId(), nextKeyAlias, null, /*CreateLinkCert*/true);
            // Check the CA's new certificate has the ML-DSA based signing algorithm
            final X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
            final X509Certificate newcert = (X509Certificate) newinfo.getCertificateChain().iterator().next();
            final String newSigAlg = AlgorithmTools.getSignatureAlgorithm(newcert);
            assertEquals("New signature algorithm should be ML-DSA-44", AlgorithmConstants.SIGALG_MLDSA44, newSigAlg);

            // Check the Link certificate was signed using the previous Signing Algorithm
            linkCertificateAfterRenewalBytes = caAdminSession.getLatestLinkCertificate(newinfo.getCAId());
            assertNotNull("There is no available link certificate after CA renewal with ML-DSA key", linkCertificateAfterRenewalBytes);
            final X509Certificate linkCertificateAfterRenewal = CertTools.getCertfromByteArray(linkCertificateAfterRenewalBytes, X509Certificate.class);
            assertEquals("The link certificate should be signed by the CA's previous signing algorithm", previousSigAlg.toUpperCase(), CertTools.getCertSignatureAlgorithmNameAsString(linkCertificateAfterRenewal).toUpperCase());

            // Check the SignatureAlgorithm on the CA's Token is still set correctly
            assertEquals("The signature algorithm on the CA's token was changed and should be ECDSA", AlgorithmConstants.SIGALG_MLDSA44, caToken.getSignatureAlgorithm());

            // Check the link cert's IssuerDN matches the original CA's SubjectDN
            assertEquals("The IssuerDN of the link certificate does not match the SubjectDN of the old CA certificate.", orgcert.getSubjectDN(), linkCertificateAfterRenewal.getIssuerDN());

            // Check the link cert's SubjectDN matches the original CA's SubjectDN
            // Note: Because there was not a Name change occurring
            assertEquals("The SubjectDN of the link certificate does not match the SubjectDN of the old CA certificate.", orgcert.getSubjectDN(), linkCertificateAfterRenewal.getSubjectDN());

            // Check validity period, notAfter in the link certificate should be same as notAfter in the old CA certificate
            assertEquals("notAfter in the link certificate should be the same as notAfter in the old CA certificate.", orgcert.getNotAfter(), linkCertificateAfterRenewal.getNotAfter());
            // notBefore in the link certificate should be same as notBefore in the new CA certificate
            assertEquals("notBefore in the link certificate should be the same as notBefore in the new CA certificate.", newcert.getNotBefore(), linkCertificateAfterRenewal.getNotBefore());
        }

        // Try to renew CA but with an invalid algorithm not matching the signing key, it should fail and nothing should be done
        {
            final X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
            final CAToken caToken = info.getCAToken();
            // The current Signing Algorithm should be ML-DSA based
            final X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
            final String previousSigAlg = AlgorithmTools.getSignatureAlgorithm(orgcert);
            assertEquals("Current CA's Signature Algorithm should be EC", AlgorithmConstants.SIGALG_MLDSA44, previousSigAlg);
            // Re-use the already existing EC key
            final String nextKeyAlias = "signKeyRenewalEC";
            // Set a signature algorithm that doesn't match the nextKeyAlias
            caToken.setSignatureAlgorithm( AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
            // Update the CA with the new CAToken signature algorithm
            caSession.editCA(internalAdmin, info);

            // We are all set and now ready to renew the CA, which should fail
            try {
                caAdminSession.renewCA(internalAdmin, info.getCAId(), nextKeyAlias, null, /*CreateLinkCert*/true);
            } catch (EJBException e) {
                assertTrue(e.getMessage(), e.getMessage().contains("Supplied key (org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey) is not a RSAPrivateKey instance"));
            }
            // Check the CA's certificate still have has ML-DSA signing algorithm
            final X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
            final X509Certificate newcert = (X509Certificate) newinfo.getCertificateChain().iterator().next();
            final String newSigAlg = AlgorithmTools.getSignatureAlgorithm(newcert);
            assertEquals("Signature algorithm should still be ML-DSA-44", AlgorithmConstants.SIGALG_MLDSA44, newSigAlg);

            // Check the Link certificate is still the old one
            byte[] oldLinkCert = caAdminSession.getLatestLinkCertificate(newinfo.getCAId());
            // java.util.Objects.deepEquals(Object, Object
            assertTrue("Link certificate bytes should be the same, as it should be the old link certificate.", Objects.deepEquals(oldLinkCert, linkCertificateAfterRenewalBytes));
        }

        log.trace("<testRenewCAChangeKeyAlg()");
    }


    /** Test renewal of a CA using a different key algorithm and a different SubjectDN.
     */
    @Test
    public void testRenewCAChangeKeyAlgWithNameChange() throws Exception {
        log.trace(">testRenewCAChangeKeyAlgWithNameChange()");

        // Prepare to renew CA but with an EC key
        final X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
        final CAToken caToken = info.getCAToken();
        // The current Signing Algorithm should be RSA based
        final X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        final String previousSigAlg = AlgorithmTools.getSignatureAlgorithm(orgcert);
        assertEquals("Current CA's Signature Algorithm should be RSA", AlgorithmConstants.SIGALG_SHA1_WITH_RSA, previousSigAlg);
        // Create an EC key with a new alias
        final String nextKeyAlias = "signKeyRenewalEC";
        cryptoTokenManagementSession.createKeyPair(internalAdmin, caToken.getCryptoTokenId(), nextKeyAlias, com.keyfactor.util.keys.token.KeyGenParams.builder("prime256v1").build());

        // To get EJBCA to renew a CA with a different key algorithm, we need to set the new signing algorithm in the CA's token,
        caToken.setSignatureAlgorithm( AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        // Update the CA with the new CAToken signature algorithm
        caSession.editCA(internalAdmin, info);

        // We are all set and now ready to renew the CA
        // Lets do a name change too
        final String newSubjectDN = "CN=NewName,o=Test";
        final String newCAName = "NewName";

        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean backupEnableIcaoCANameChangeValue = globalConfiguration.getEnableIcaoCANameChange();
        try {
            // Ensure the NameChange setting is true
            globalConfiguration.setEnableIcaoCANameChange(true);
            globalConfigSession.saveConfiguration(internalAdmin, globalConfiguration);

            // We are all set and now ready to renew the CA with the name change
            caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), nextKeyAlias, null, /*CreateLinkCert*/true, newSubjectDN);

            // Check the CA's new certificate has the ECDSA based signing algorithm
            final X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
            final X509Certificate newcert = (X509Certificate) newinfo.getCertificateChain().iterator().next();
            final String newSigAlg = AlgorithmTools.getSignatureAlgorithm(newcert);
            assertEquals("New signature algorithm should be ECDSA", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, newSigAlg);

            // Check the Link certificate was signed using the previous Signing Algorithm
            byte[] linkCertificateAfterRenewalBytes = caAdminSession.getLatestLinkCertificate(newinfo.getCAId());
            assertNotNull("There is no available link certificate after CA renewal with EC key", linkCertificateAfterRenewalBytes);
            final X509Certificate linkCertificateAfterRenewal = CertTools.getCertfromByteArray(linkCertificateAfterRenewalBytes, X509Certificate.class);
            assertEquals("The link certificate should be signed by the CA's previous signing algorithm", previousSigAlg.toUpperCase(), CertTools.getCertSignatureAlgorithmNameAsString(linkCertificateAfterRenewal).toUpperCase());

            // Check the SignatureAlgorithm on the CA's Token is still set correctly
            assertEquals("The signature algorithm on the CA's token was changed and should be ECDSA", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, caToken.getSignatureAlgorithm());

            // Check the link certificates IssuerDN matches the original CA's SubjectDN
            assertEquals("The IssuerDN of the link certificate does not match the SubjectDN of the old CA certificate.", orgcert.getSubjectDN(), linkCertificateAfterRenewal.getIssuerDN());

            // Check the link certificates SubjectDN does not matches the original CA's SubjectDN
            assertNotEquals("The SubjectDN of the link certificate should not match the SubjectDN of the old CA certificate.", orgcert.getSubjectDN(), linkCertificateAfterRenewal.getSubjectDN());

            // Check the link cert's SubjectDN matches the renewed CA's SubjectDN
            // Note: There is a Name change occurring
            assertEquals("The SubjectDN of the link certificate should match the SubjectDN of the renewed CA certificate.", newcert.getSubjectDN(), linkCertificateAfterRenewal.getSubjectDN());

            // Check validity period, notAfter in the link certificate should be same as notAfter in the old CA certificate
            assertEquals("notAfter in the link certificate should be the same as notAfter in the old CA certificate.", orgcert.getNotAfter(), linkCertificateAfterRenewal.getNotAfter());
            // notBefore in the link certificate should be same as notBefore in the new CA certificate
            assertEquals("notBefore in the link certificate should be the same as notBefore in the new CA certificate.", newcert.getNotBefore(), linkCertificateAfterRenewal.getNotBefore());
        } finally {
            // Clean up the renewed CA with name change
            removeTestCA(newCAName);
            internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN);
            // Ensure the global configuration is reverted.
            globalConfiguration.setEnableIcaoCANameChange(backupEnableIcaoCANameChangeValue);
            globalConfigSession.saveConfiguration(internalAdmin, globalConfiguration);
        }
        log.trace("<testRenewCAChangeKeyAlgWithNameChange()");
    }


    /** Test renewal of a subCA, using Renew CA Worker. */
    @Test
    public void testRenewSubCAWithRenewCAWorker() throws Exception {
        log.trace(">testRenewSubCAWithRenewCAWorker()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, getTestCAName());
        final int cryptoTokenIdSubCa = CryptoTokenTestUtils.createCryptoTokenForCA(null, "foo123".toCharArray(), true, false, "TestSubCaRenew", "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken subCaToken = CaTestUtils.createCaToken(cryptoTokenIdSubCa, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        try {
            // Create sub CA to test renewal using Renew CA Worker
            X509CAInfo subCaInfo =  new X509CAInfo.X509CAInfoBuilder()
                    .setCaToken(subCaToken)
                    .setSubjectDn("CN=RenewSubCA")
                    .setName("TestSubCaRenew")
                    .setStatus(CAConstants.CA_ACTIVE)
                    .setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA)
                    .setEncodedValidity("20s")
                    .setSignedBy(info.getCAId())
                    .setCertificateChain(null)
                    .setUseUserStorage(false)
                    .setUseCertificateStorage(false)
                    .setCaSerialNumberOctetSize(20)
                    .build();
            if (caSession.existsCa("TestSubCaRenew")) {
                caSession.removeCA(internalAdmin, caSession.getCAInfo(internalAdmin, "TestSubCaRenew").getCAId());
            }
            caAdminSession.createCA(internalAdmin, subCaInfo);
            // Given
            X509CAInfo originaSubCalinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TestSubCaRenew");
            X509Certificate orgSubCacert = (X509Certificate) originaSubCalinfo.getCertificateChain().iterator().next();
            // Wait a little to get new expire time on new cert...
            Thread.sleep(2000);

            Map<Class<?>, Object> ejbs = new HashMap<>();
            ejbs.put(ServiceSessionLocal.class, serviceSession);
            final Integer subCaId = subCaInfo.getCAId();
            ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
            Properties properties = new Properties();
            Properties intervalProperties = new Properties();
            properties.setProperty(BaseWorker.PROP_CAIDSTOCHECK, subCaId.toString());
            properties.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, "8");
            properties.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
            properties.setProperty(RenewCAWorker.PROP_RENEWKEYS, "TRUE");
            intervalProperties.setProperty(PeriodicalInterval.PROP_VALUE, "2");
            intervalProperties.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
            serviceConfiguration.setWorkerProperties(properties);
            serviceConfiguration.setWorkerClassPath(RenewCAWorker.class.getName());
            serviceConfiguration.setActive(true);
            serviceConfiguration.setIntervalClassPath(PeriodicalInterval.class.getName());
            serviceConfiguration.setIntervalProperties(intervalProperties);
            serviceConfiguration.setActionClassPath(NoAction.class.getName());
            serviceConfiguration.setActionProperties(null);
            serviceSession.addService(internalAdmin, "RenewCaServiceTestService", serviceConfiguration);
            serviceSession.activateServiceTimer(internalAdmin, "RenewCaServiceTestService");
            // Let service run for a while...
            Thread.sleep(12000);
            X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TestSubCaRenew");
            X509Certificate newcertnewkeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
            // Then
            assertTrue("newcertnewkeys.getNotAfter: " + newcertnewkeys.getNotAfter() + " orgSubCacert.getNotAfter: " + orgSubCacert.getNotAfter(),
                    newcertnewkeys.getNotAfter().after(orgSubCacert.getNotAfter()));
            assertTrue(!orgSubCacert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
            byte[] orgkey = orgSubCacert.getPublicKey().getEncoded();
            byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
            assertFalse(Arrays.equals(orgkey, newkey));
        // Remove CA:s and Service...
        } finally {
            serviceSession.removeService(internalAdmin, "RenewCaServiceTestService");
            X509CAInfo caInfoSubCa = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TestSubCaRenew");
            if (caInfoSubCa != null) {
                CaTestUtils.removeCa(internalAdmin, caInfoSubCa);
            }
        }
        log.trace("<testRenewSubCAWithRenewCAWorker()");
    }
}
