/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaMsCompatibilityIrreversibleException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.crl.CrlDataTestSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.cvc.AccessRightsIS;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Common class for test classes which need to create a CA.
 */
public abstract class CaTestUtils {

    private static final Logger log = Logger.getLogger(CaTestUtils.class);

    private static final String RSA_1024 = "RSA1024";
    private static final String EC_256 = "prime256v1";
    private static final String ML_DSA_44 = AlgorithmConstants.KEYALGORITHM_MLDSA44;
    private static final String FALCON_512 = AlgorithmConstants.KEYALGORITHM_FALCON512;


    /**
     * Creates and stores a simple X509 Root CA with an ACTIVE state
     *
     * @param authenticationToken Authentication token (usually an always allow token)
     * @param cryptoTokenName Name of new Crypto Token
     * @param caName Name of new CA
     * @param cadn Subject DN of new CA
     */
    public static X509CA createActiveX509Ca(final AuthenticationToken authenticationToken, final String cryptoTokenName, final String caName, final String cadn)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException, CertificateException, InvalidAlgorithmException,
            IllegalStateException, OperatorCreationException, CAExistsException {
        return createX509Ca(authenticationToken, cryptoTokenName, caName, cadn, CAConstants.CA_ACTIVE);
    }

	/**
     * Creates and stores a simple X509 Root CA (allows the caller to say with which state the CA should be created - CAConstants.CA_ACTIVE, etc)
     *
     * @param authenticationToken Authentication token (usually an always allow token)
     * @param cryptoTokenName Name of new Crypto Token
     * @param caName Name of new CA
     * @param cadn Subject DN of new CA
     */
    public static X509CA createX509Ca(final AuthenticationToken authenticationToken, final String cryptoTokenName, final String caName, final String cadn, int caStatus)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException, CertificateException, InvalidAlgorithmException,
            IllegalStateException, OperatorCreationException, CAExistsException {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final int cryptoTokenId = initCryptoTokenId(cryptoTokenManagementProxySession, authenticationToken, cryptoTokenName);
        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        final X509CA x509Ca = createX509Ca(cryptoToken, caName, cadn, caStatus);
        caSession.addCA(authenticationToken, x509Ca);
        // Now our CA should be operational
        return x509Ca;
    }

    public static X509CA createX509CaWithApprovals(final AuthenticationToken authenticationToken, final String cryptoTokenName, final String caName, final String cadn,
            int caStatus, Map<ApprovalRequestType, Integer> approvals) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
                AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException, CertificateException, InvalidAlgorithmException,
                IllegalStateException, OperatorCreationException, CAExistsException {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final int cryptoTokenId = initCryptoTokenId(cryptoTokenManagementProxySession, authenticationToken, cryptoTokenName);
        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        final X509CA x509Ca = createX509Ca(cryptoToken, caName, cadn, caStatus);
        x509Ca.setApprovals(approvals);

        caSession.addCA(authenticationToken, x509Ca);

        return x509Ca;
    }

    private static X509CA createX509Ca(final CryptoToken cryptoToken, String caName, String cadn, int caStatus) throws CertificateException,
            CryptoTokenOfflineException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException {
        CAToken catoken = createCaToken(cryptoToken.getId(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        // No extended services
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, caName, caStatus,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                "SHA256WithRSA", true);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        return x509ca;
    }

    /** Removes a CA, and it's associated certificate and Crypto Token. */
    public static void removeCa(AuthenticationToken authenticationToken, String cryptoTokenName, String caName) throws AuthorizationDeniedException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        CAInfo caInfo = caSession.getCAInfo(authenticationToken, caName);
        Integer cryptoTokenId = null;
        if (caInfo != null) {
            if (caInfo.getCAToken() != null) {
                // We want to delete this CAs crypto token
                cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
            }
            caSession.removeCA(authenticationToken, caInfo.getCAId());
            internalCertificateStoreSession.removeCertificatesBySubject(caInfo.getSubjectDN());
        }
        if (cryptoTokenId == null) {
            // If we didn't find on in CAToken, make sure we don't have one with the same name as the CA
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        }
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
    }

    public static int getCaIdByName(AuthenticationToken authenticationToken, String caName) throws CADoesntExistsException, AuthorizationDeniedException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo caInfo = caSession.getCAInfo(authenticationToken, caName);
        if (caInfo != null) {
            int caId = caInfo.getCAId();
            return caId;
        } else {
            throw new CADoesntExistsException();
        }
    }

    /**
     * Removes a CA, and it's associated certificate and Crypto Token.
     * See {@link #removeCa(AuthenticationToken, String, String)}, which is more robust, in case the test got aborted for some reason.
     */
    public static void removeCa(AuthenticationToken authenticationToken, CAInfo caInfo) throws AuthorizationDeniedException {
        if (caInfo != null) {
            CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.
                    getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
            caSession.removeCA(authenticationToken, caInfo.getCAId());
            if (caInfo.getCAToken() != null) {
                cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caInfo.getCAToken().getCryptoTokenId());
            }
            internalCertificateStoreSession.removeCertificatesByIssuer(caInfo.getSubjectDN());
            internalCertificateStoreSession.removeCertificatesBySubject(caInfo.getSubjectDN());
            internalCertificateStoreSession.removeCRLs(authenticationToken, caInfo.getSubjectDN());
        }
    }

    /**
     * Removes certificate revocation lists by issuer's distinguished name
     * @param issuerDn Issuer DN
     */
    public static void removeCrlByIssuerDn(final String issuerDn) {
        final CrlDataTestSessionRemote crlDataTestSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CrlDataTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        crlDataTestSession.deleteCrlDataByIssuerDn(issuerDn);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11)
            throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, CertIOException {
        return CaTestUtils.createTestX509CAOptionalGenKeys(cadn, tokenpin, genKeys, pkcs11, RSA_1024, -1, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11, final String keyspec,
            int keyusage, String caSignAlg) throws CryptoTokenOfflineException, CertificateParsingException, OperatorCreationException, CertIOException {
        final String cryptoTokenImplementation;
        if (pkcs11) {
            cryptoTokenImplementation = PKCS11CryptoToken.class.getName();
        } else {

            cryptoTokenImplementation = SoftCryptoToken.class.getName();
        }
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, genKeys, cryptoTokenImplementation, CAInfo.SELFSIGNED, keyspec, keyusage, caSignAlg);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, final String cryptoTokenImplementation, final String keyspec,
            int keyusage) throws CryptoTokenOfflineException, CertificateParsingException, OperatorCreationException, CertIOException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, genKeys, cryptoTokenImplementation, CAInfo.SELFSIGNED, keyspec, keyusage, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }
    
    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, String cryptoTokenImplementation, int signedBy, final String keyspec,
            int keyusage, String caSignatureAlg) throws CryptoTokenOfflineException, CertificateParsingException, OperatorCreationException, CertIOException {
        // Create catoken
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        String signingKeyName = cadn + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS;
        String encryptionKeyName = cadn + "_" + CAToken.SOFTPRIVATEDECKEYALIAS;
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, tokenpin, genKeys, cryptoTokenImplementation, cadn, keyspec, keyspec, signingKeyName, encryptionKeyName);
        final CAToken catoken = createCaToken(cryptoTokenId, caSignatureAlg, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, signingKeyName, encryptionKeyName);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = DnComponents.getPartFromDN(cadn, "CN");
        boolean ldapOrder = !DnComponents.isDNReversed(cadn);
        int certificateProfile = (signedBy == CAInfo.SELFSIGNED ? CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA : CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, caname, CAConstants.CA_ACTIVE, certificateProfile, "3650d",
                signedBy, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        cainfo.setDeltaCRLPeriod(10 * SimpleTime.MILLISECONDS_PER_HOUR); // In order to be able to create deltaCRLs
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        try {
            x509ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // A CA certificate
        List<Certificate> cachain = new ArrayList<>();
        if (genKeys) {
            final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId,
                    signingKeyName).getPublicKey();
            final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId,
                    signingKeyName);
            final String keyalg = AlgorithmTools.getKeyAlgorithm(publicKey);
            X509Certificate cacert;
            if (keyusage == -1) {
                cacert = SimpleCertGenerator.forTESTCaCert()
                            .setSubjectDn(cadn)
                            .setIssuerDn(cadn)
                            .setPolicyId("1.1.1.1")
                            .setValidityDays(10)
                            .setIssuerPrivKey(privateKey)
                            .setEntityPubKey(publicKey)
                            .setSignatureAlgorithm(caSignatureAlg)
                            .setProvider(cryptoTokenManagementProxySession.getSignProviderName(cryptoTokenId))
                            .setLdapOrder(ldapOrder)
                            .generateCertificate();                        
            } else {
                cacert = SimpleCertGenerator.forTESTCaCert()
                            .setSubjectDn(cadn)
                            .setIssuerDn(cadn)
                            .setPolicyId("1.1.1.1")
                            .setValidityDays(10)
                            .setIssuerPrivKey(privateKey)
                            .setEntityPubKey(publicKey)
                            .setSignatureAlgorithm(caSignatureAlg)
                            .setKeyUsage(keyusage)
                            .setLdapOrder(ldapOrder)
                            .generateCertificate();      
            }
            cachain.add(cacert);
        }
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational, if we generated keys, otherwise we will have to generate it, and a CA certificate later.
        return x509ca;
    }

    /** Creates and adds a Sub CA to EJBCA. */
    public static CAInfo createTestX509SubCAGenKeys(AuthenticationToken admin, String cadn, char[] tokenpin, int signedBy, final String signKeySpec,
            String encKeySpec, final String signingKeyName, final String encryptionKeyName)
            throws CryptoTokenOfflineException, CAExistsException, InvalidAlgorithmException, AuthorizationDeniedException {
        // Create catoken
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, tokenpin, true, false, cadn, signKeySpec, encKeySpec, signingKeyName, encryptionKeyName);
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                signingKeyName, encryptionKeyName);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = DnComponents.getPartFromDN(cadn, "CN");
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d",
                signedBy, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        boolean ldapOrder = !DnComponents.isDNReversed(cadn);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        try {
            x509ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // Create the SubCA, signed by Root designated by "signedby"
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        caAdminSession.createCA(admin, cainfo);
        CAInfo newinfo = caSession.getCAInfo(admin, caname);
        Collection<Certificate> newcerts = newinfo.getCertificateChain();
        assertNotNull(newcerts);
        assertEquals("A subCA should have two certificates in the certificate chain", 2, newcerts.size());
        // Now our CA should be operational
        return newinfo;
    }

    /** @return a CAToken for referencing the specified CryptoToken. */
    public static CAToken createCaToken(final int cryptoTokenId, String sigAlg, String encAlg, final String signingKeyAlias, final String encryptionKeyAlias) {
        // Create CAToken (what key in the CryptoToken should be used for what)
        final Properties caTokenProperties = new Properties();

        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT , signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, encryptionKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, signingKeyAlias);

        final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
        catoken.setSignatureAlgorithm(sigAlg);
        catoken.setEncryptionAlgorithm(encAlg);
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        return catoken;
    }

    public static CvcCA createTestCVCCA(String cadn, char[] tokenpin, boolean pkcs11) throws Exception {
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        // Create catoken
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, tokenpin, true, pkcs11, cadn, RSA_1024, RSA_1024, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        // No extended services
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>(0);
        CVCCAInfo cainfo = new CVCCAInfo(cadn, "TESTCVC", CAConstants.CA_ACTIVE,
            CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CVC CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CvcCA cvcca = (CvcCA) CAFactory.INSTANCE.getCvcCaImpl(cainfo);
        cvcca.setCAToken(catoken);
        // A CA certificate
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CAREF001", "00000");
        final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getPublicKey();
        final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        CVCertificate cv = CaTestUtils.createTestCvcCertificate(publicKey, privateKey, caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.CVCA,
                cryptoTokenManagementProxySession.getSignProviderName(cryptoTokenId));
        Certificate cacert = new CardVerifiableCertificate(cv);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        cvcca.setCertificateChain(cachain);
        // Now our CA should be operational
        return cvcca;
    }

    public static CVCertificate createTestCvcCertificate(PublicKey publicKey, PrivateKey privateKey, CAReferenceField caRef,
            HolderReferenceField holderRef, String algorithm, AuthorizationRoleEnum role, String provider) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {
        // Skapa default-datum
        Calendar cal1 = Calendar.getInstance();
        Date validFrom = cal1.getTime();

        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.MONTH, 3);
        Date validTo = cal2.getTime();
        return CertificateGenerator.createCertificate(publicKey, privateKey, algorithm, caRef, holderRef, role,
                AccessRightsIS.DG3_AND_DG4(), validFrom, validTo, provider);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException, CertIOException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA.  */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, int keyusage) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException, CertIOException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, RSA_1024, keyusage, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }
    /** Creates a CA object, but does not actually add the CA to EJBCA.
     * @throws InvalidAlgorithmException if caSignAlg is not supported
     */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, int keyusage, String caSignAlg) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException, InvalidAlgorithmException, CertIOException {
        final String keyspec;
        if (StringUtils.contains(caSignAlg, "RSA")) {
            keyspec = RSA_1024;
        } else if (StringUtils.contains(caSignAlg, "ECDSA")) {
            keyspec = EC_256;
        } else if (StringUtils.containsIgnoreCase(caSignAlg, "ML-DSA-44")) {
            keyspec = ML_DSA_44;
        } else if (StringUtils.containsIgnoreCase(caSignAlg, "FALCON-512")) {
            keyspec = FALCON_512;
        } else {
            throw new InvalidAlgorithmException("Trying to create testCA with invalid signature algorithm: " + caSignAlg);
        }
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, keyspec, keyusage, caSignAlg);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, final String cryptoTokenImplementation, int signedBy, int keyusage) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException, CertIOException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, cryptoTokenImplementation, signedBy, RSA_1024, keyusage, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, int signedBy, char[] tokenpin, boolean pkcs11, int keyusage) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException, CertIOException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, RSA_1024, keyusage, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, final String keyspec) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException, CertIOException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, keyspec, -1, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }

    /**
     * Creates and stores a simple X509 Root Throw-away CA
     *
     * @param authenticationToken Authentication token (usually an always allow token)
     * @param cryptoTokenName Name of new Crypto Token
     * @param caName Name of new CA
     * @param cadn Subject DN of new CA
     * @param defaultCertificateProfileId Default CA profile id
     */
    public static CA createX509ThrowAwayCa(final AuthenticationToken authenticationToken, final String cryptoTokenName, final String caName, final String cadn, final int defaultCertificateProfileId) throws Exception {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final int cryptoTokenId = initCryptoTokenId(cryptoTokenManagementProxySession, authenticationToken, cryptoTokenName);
        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        CAToken caToken = createCaToken(cryptoToken.getId(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        // Set useNoConflictCertificateData, defaultCertprofileId, _useUserStorage and _useCertificateStorage to false
        X509CAInfo cainfo =  new X509CAInfo.X509CAInfoBuilder()
                .setSubjectDn(cadn)
                .setName(caName)
                .setStatus(CAConstants.CA_ACTIVE)
                .setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA)
                .setDefaultCertProfileId(defaultCertificateProfileId)
                .setUseNoConflictCertificateData(true)
                .setEncodedValidity("3650d")
                .setSignedBy(CAInfo.SELFSIGNED)
                .setCertificateChain(null)
                .setCaToken(caToken)
                .setCrlIssueInterval(0L)
                .setUseUserStorage(false)
                .setUseCertificateStorage(false)
                .setAcceptRevocationNonExistingEntry(true)
                .setCaSerialNumberOctetSize(20)
                .build();
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        x509ca.setCAToken(caToken);
        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), "SHA256WithRSA", true);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);

        caSession.addCA(authenticationToken, x509ca);
        // Now our CA should be operational
        return x509ca;
    }


    private static int initCryptoTokenId(final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession,
            final AuthenticationToken authenticationToken, final String cryptoTokenName)
            throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, CryptoTokenNameInUseException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        cryptoTokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
        int cryptoTokenId;
        if (!cryptoTokenManagementProxySession.isCryptoTokenNameUsed(cryptoTokenName)) {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(
                        authenticationToken,
                        cryptoTokenName,
                        SoftCryptoToken.class.getName(),
                        cryptoTokenProperties,
                        null,
                        null);
            } catch (NoSuchSlotException e) {
                throw new RuntimeException("Attempted to find a slot for a soft crypto token. This should not happen.");
            }
        } else {
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, KeyGenParams.builder("RSA1024").build());
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, KeyGenParams.builder("RSA1024").build());
        }
        return cryptoTokenId;
    }

    /**
     * Returns the CA that was used to issue the server TLS certificate.
     * By default, this method looks for "ManagementCA" and "AdminCA1", but this may
     * be overridden in systemtests.properties using 'target.servercert.ca'.
     * <p>
     * This CA can be an external CA, so don't assume you can issue certificates from it!
     */
    public static CAInfo getServerCertCaInfo(final AuthenticationToken authenticationToken) {
        return getCaInfo(authenticationToken, SystemTestsConfiguration.getServerCertificateCaNames());
    }

    /**
     * Returns a CA that is trusted by the application server.
     * By default, this method looks for "ManagementCA" and "AdminCA1", but this may
     * be overridden in systemtests.properties using 'target.clientcert.ca'.
     * <p>
     * This CA should be an active CA, that we can issue certificates from.
     *
     * @return CAInfo of ManagementCA or other trusted CA, never null.
     */
    public static CAInfo getClientCertCaInfo(final AuthenticationToken authenticationToken) {
        final CAInfo caInfo = getCaInfo(authenticationToken, SystemTestsConfiguration.getClientCertificateCaNames());
        if (caInfo.getStatus() != CAConstants.CA_ACTIVE) {
            log.warn("CA for issuing client certificates is not active. Please check the following CAs or change '" + SystemTestsConfiguration.TARGET_CLIENTCERT_CA +
                    "': '" + StringUtils.join(SystemTestsConfiguration.getClientCertificateCaNames(), "', '") + "'");
        }
        return caInfo;
    }

    /**
     * Returns the first available CA in the list.
     * @return CAInfo. Never null
     * @throws IllegalStateException if none exist or if access was denied.
     */
    private static CAInfo getCaInfo(final AuthenticationToken authenticationToken, final String[] cas) {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        for (final String ca : cas) {
            try {
                final CAInfo caInfo = caSession.getCAInfo(authenticationToken, ca);
                if (caInfo != null) {
                    return caInfo;
                }
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Unable to access CA '" + ca + "': "+ e.getMessage(), e);
            }
        }
        throw new IllegalStateException("Cannot find the required CA. Looked for: '" + StringUtils.join(cas, "', '") +
                "'. Use '" + SystemTestsConfiguration.TARGET_SERVERCERT_CA + "' and '" + SystemTestsConfiguration.TARGET_CLIENTCERT_CA +
                "' in systemtests.properties to override.");
    }

    /**
     * Like {@link #getClientCertCaInfo} but returns the name of the CA instead.
     * I.e. it returns the name of an active CA that is trusted by the application server.
     *
     * @param authenticationToken Authentication token
     * @return Name of the CA, never null.
     * @throws IllegalStateException if none exist or if access was denied.
     */
    public static String getClientCertCaName(final AuthenticationToken authenticationToken) {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final List<String> allCaNames = caSession.getActiveCANames(authenticationToken);
        final List<String> clientCertCaNames = Arrays.asList(SystemTestsConfiguration.getClientCertificateCaNames());
        allCaNames.retainAll(clientCertCaNames);
        if (allCaNames.isEmpty()) {
            throw new IllegalStateException("No active CA for issuing client certificates was found. Searched for: " + String.join(", ", clientCertCaNames));
        }
        return allCaNames.iterator().next();
    }

    public static PrivateKey getCaPrivateKey(final CA ca) {
        final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

        final int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        try {
            return cryptoToken.getPrivateKey(ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        } catch (CryptoTokenOfflineException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Enables/Disables the "Allow Invalidity Date" setting for a CA
     *
     * @param authenticationToken Authentication token
     * @param caName              Name of the CA
     * @param allowInvalidityDate True if invalidity date usage should be allowed
     */
    public static void setAllowInvalidityDate(final AuthenticationToken authenticationToken, final String caName, final boolean allowInvalidityDate)
            throws AuthorizationDeniedException, CaMsCompatibilityIrreversibleException,
            InternalKeyBindingNonceConflictException, CADoesntExistsException {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CAInfo caInfo = caSession.getCAInfo(authenticationToken, caName);
        caInfo.setAllowInvalidityDate(allowInvalidityDate);
        caSession.editCA(authenticationToken, caInfo);
    }
}
