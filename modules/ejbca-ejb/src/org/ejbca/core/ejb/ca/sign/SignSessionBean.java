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

package org.ejbca.core.ejb.ca.sign;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;
import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatus;
import org.bouncycastle.asn1.cmc.CMCStatusInfoBuilder;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.its.ETSISignedData;
import org.bouncycastle.its.ETSISignedDataBuilder;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.jcajce.JcaITSContentSigner;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate.Builder;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificate.ca.its.ECA;
import org.cesecore.certificate.ca.its.ITSApplicationIds;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.MsKeyArchivalRequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTLogException;
import org.cesecore.certificates.certificatetransparency.CTSubmissionConfigParams;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.util.CvcKeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.ECAUtils;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;
import org.ejbca.core.ejb.ocsp.PresignResponseValidity;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.ejb.EJBException;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

/**
 * Creates and signs certificates.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SignSessionBean implements SignSessionLocal, SignSessionRemote {

    private static final Logger log = Logger.getLogger(SignSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertReqHistorySessionLocal certreqHistorySession;
    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private RevocationSessionLocal revocationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;


    // Re-factor: Remove Cyclic module dependency.
    @EJB
    private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;

    /**
     * Internal localization of logs and errors
     */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /**
     * Default create for SessionBean without any creation Arguments.
     */
    @PostConstruct
    public void ejbCreate() {
        if (log.isTraceEnabled()) {
            log.trace(">ejbCreate()");
        }
        try {
            // Install BouncyCastle provider
            CryptoProviderTools.installBCProviderIfNotAvailable();
        } catch (Exception e) {
            log.debug("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<ejbCreate()");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Certificate> getCertificateChain(int caid) {
        final CAInfo cainfo = caSession.getCAInfoInternal(caid);
        if (cainfo != null) {
            return cainfo.getCertificateChain();
        } else {
            return new ArrayList<>();
        }
    }

    @Override
    public byte[] createPKCS7(AuthenticationToken admin, X509Certificate cert, boolean includeChain)
            throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException {
        Integer caid = Integer.valueOf(CertTools.getIssuerDN(cert).hashCode());
        return createPKCS7(admin, caid.intValue(), cert, includeChain, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
    }

    @Override
    public byte[] createPKCS7(AuthenticationToken admin, X509Certificate cert, boolean includeChain, final int eepId)
            throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException {
        Integer caid = Integer.valueOf(CertTools.getIssuerDN(cert).hashCode());
        return createPKCS7(admin, caid.intValue(), cert, includeChain, eepId);
    }

    @Override
    public byte[] createPKCS7(AuthenticationToken admin, int caId, boolean includeChain)
            throws CADoesntExistsException, AuthorizationDeniedException {
        try {
            return createPKCS7(admin, caId, null, includeChain, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
        } catch (SignRequestSignatureException e) {
            String msg = intres.getLocalizedMessage("error.unknown");
            log.error(msg, e);
            throw new EJBException(e);
        }
    }

    /**
     * Internal helper method
     *
     * @param admin Information about the administrator or admin performing the event.
     * @param caId  CA for which we want a PKCS7 certificate chain.
     * @param cert  client certificate which we want encapsulated in a PKCS7 together with
     *              certificate chain, or null
     * @param eepId used for accurate redaction. If EEP is unknown, pass {@link EndEntityConstants.EMPTY_END_ENTITY_PROFILE} to use default setting.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException       if the CA does not exist or is expired, or has an invalid certificate
     * @throws AuthorizationDeniedException  if the authentication token wasn't authorized to the CA
     * @throws SignRequestSignatureException if the certificate wasn't issued by the CA defined by caid
     */
    private byte[] createPKCS7(AuthenticationToken admin, int caId, X509Certificate cert, boolean includeChain, final int eepId)
            throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN(cert) + ")");
        }
        final CA ca = (CA) caSession.getCA(admin, caId);
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        final byte[] returnval = ca.createPKCS7(cryptoToken, cert, includeChain);
        if (returnval != null) {
            // Audit log that we used the CA's signing key to create a CMS signature
            final String detailsMsg = intres.getLocalizedMessage("caadmin.signedcms", ca.getName());
            final Map<String, Object> details = new LinkedHashMap<>();
            if (cert != null) {
                details.put("leafSubject", LogRedactionUtils.getSubjectDnLogSafe(cert, eepId));
                details.put("leafFingerprint", CertTools.getFingerprintAsString(cert));
            }
            details.put("includeChain", Boolean.toString(includeChain));
            details.put("msg", detailsMsg);
            securityEventsLoggerSession.log(EjbcaEventTypes.CA_SIGNCMS, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caId), null, null, details);
        }
        if (log.isTraceEnabled()) {
            log.trace("<createPKCS7()");
        }
        return returnval;
    }

    @Override
    public byte[] createPKCS7Rollover(AuthenticationToken admin, int caId) throws CADoesntExistsException, AuthorizationDeniedException {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">createPKCS7Rollover(" + caId + ")");
            }
            CA ca = (CA) caSession.getCA(admin, caId);
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            byte[] returnval = ca.createPKCS7Rollover(cryptoToken);
            log.trace("<createPKCS7Rollover()");
            return returnval;
        } catch (SignRequestSignatureException e) {
            String msg = intres.getLocalizedMessage("error.unknown");
            log.error(msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk)
            throws NoSuchEndEntityException, AuthorizationDeniedException, CADoesntExistsException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, -1, null, null, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk, final PublicKey altPK)
            throws NoSuchEndEntityException, AuthorizationDeniedException, CADoesntExistsException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, altPK, -1, null, null, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKeyWrapper pk)
            throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException, IllegalKeyException, CertificateCreateException,
            IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException,
            CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException {
        return createCertificate(admin, username, password, pk.getPublicKey(), pk.getAltPublicKey());
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
                                         final int keyusage, final Date notBefore, final Date notAfter) throws NoSuchEndEntityException, AuthorizationDeniedException,
            CADoesntExistsException, AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk, keyusage, notBefore, notAfter, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKeyWrapper pk,
                                         final int keyusage, final Date notBefore, final Date notAfter) throws NoSuchEndEntityException, AuthorizationDeniedException,
            CADoesntExistsException, AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk.getPublicKey(), pk.getAltPublicKey(), keyusage, notBefore, notAfter,
                CertificateProfileConstants.CERTPROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final Certificate incert)
            throws NoSuchEndEntityException, AuthorizationDeniedException, SignRequestSignatureException, CADoesntExistsException,
            AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {

        // Convert the certificate to a BC certificate. SUN does not handle verifying RSASha256WithMGF1 for example
        Certificate bccert;
        try {
            bccert = CertTools.getCertfromByteArray(incert.getEncoded(), Certificate.class);
            bccert.verify(incert.getPublicKey());
        } catch (CertificateParsingException e) {
            log.debug("CertificateParsingException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg, e);
        } catch (CertificateEncodingException e) {
            log.debug("CertificateEncodingException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg);
        } catch (InvalidKeyException e) {
            log.debug("InvalidKeyException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg, e);
        } catch (CertificateException e) {
            log.debug("CertificateException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg, e);
        } catch (NoSuchAlgorithmException e) {
            log.debug("NoSuchAlgorithmException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg, e);
        } catch (NoSuchProviderException e) {
            log.debug("NoSuchProviderException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg, e);
        } catch (SignatureException e) {
            log.debug("SignatureException verify POPO: ", e);
            final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg, e);
        }

        return createCertificate(admin, username, password, incert.getPublicKey(),
                CertTools.sunKeyUsageToBC(((X509Certificate) incert).getKeyUsage()), null, null);
    }

    @Override
    public ResponseMessage createCertificateIgnoreStatus(final AuthenticationToken admin, final RequestMessage req,
                                                         Class<? extends CertificateResponseMessage> responseClass, boolean ignorePassword)
            throws AuthorizationDeniedException, NoSuchEndEntityException, CertificateCreateException, CertificateRevokeException,
            InvalidAlgorithmException, ApprovalException, WaitingForApprovalException {
        final String username = req.getUsername();
        final EndEntityInformation retrievedUser = endEntityAccessSession.findUser(admin, username);
        endEntityManagementSession.initializeEndEntityTransaction(username);
        if (retrievedUser.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
        }
        if (ignorePassword) {

            try {
                endEntityManagementSession.setPassword(admin, username, req.getPassword());
            } catch (EndEntityProfileValidationException e) {
                //Can be ignored in this case, shouldn't happen.
                throw new IllegalStateException(e);
            }
        }

        try {
            return createCertificate(admin, req, responseClass, null);
        } catch (CryptoTokenOfflineException | IllegalKeyException | CADoesntExistsException | SignRequestException |
                 SignRequestSignatureException
                 | AuthStatusException | AuthLoginException | CertificateExtensionException |
                 CustomCertificateSerialNumberException
                 | IllegalNameException | CertificateSerialNumberException | IllegalValidityException |
                 CAOfflineException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        }

    }

    @Override
    public ResponseMessage createCertificate(final AuthenticationToken admin, final RequestMessage req,
                                             Class<? extends CertificateResponseMessage> responseClass, final EndEntityInformation suppliedUserData)
            throws AuthorizationDeniedException, CertificateExtensionException, NoSuchEndEntityException, CustomCertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException,
            AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(RequestMessage)");
        }
        // Get CA that will receive request
        EndEntityInformation endEntityInformation = null;
        CertificateResponseMessage ret = null;
        // Get CA object and make sure it is active
        // Do not log access control to the CA here, that is logged later on when we use the CA to issue a certificate (if we get that far).
        final CA ca;
        if (suppliedUserData == null) {
            ca = getCAFromRequest(admin, req, false);
        } else {
            ca = (CA) caSession.getCANoLog(admin, suppliedUserData.getCAId(), null); // Take the CAId from the supplied userdata, if any
        }
        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            final String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
            throw new CAOfflineException(msg);
        }
        try {
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            setDecryptInfo(cryptoToken, req, ca);
            if (ca.isUseUserStorage() && req.getUsername() == null) {
                String msg = intres.getLocalizedMessage("signsession.nouserinrequest", req.getRequestDN());
                throw new SignRequestException(msg);
            } else if (ca.isUseUserStorage() && req.getPassword() == null) {
                String msg = intres.getLocalizedMessage("signsession.nopasswordinrequest");
                throw new SignRequestException(msg);
            } else {
                try {
                    // If we haven't done so yet, authenticate user. (Only if we store UserData for this CA.)
                    if (ca.isUseUserStorage() || (suppliedUserData == null && req.getUsername() != null && req.getPassword() != null)) {
                        endEntityInformation = authUser(admin, req.getUsername(), req.getPassword());
                        if (endEntityInformation != null && endEntityInformation.getExtendedInformation() != null
                                && suppliedUserData != null && suppliedUserData.getExtendedInformation() != null) {
                            endEntityInformation.getExtendedInformation().setAccountBindingId(suppliedUserData.getExtendedInformation().getAccountBindingId());
                        }
                    } else {
                        endEntityInformation = suppliedUserData;
                    }

                    // We need to make sure we use the users registered CA here
                    if (endEntityInformation.getCAId() != ca.getCAId()) {
                        final String failText = intres.getLocalizedMessage("signsession.wrongauthority", Integer.valueOf(ca.getCAId()),
                                Integer.valueOf(endEntityInformation.getCAId()));
                        log.info(failText);
                        ret = createRequestFailedResponse(admin, req, responseClass, FailInfo.WRONG_AUTHORITY, failText);
                    } else {
                        final long updateTime = System.currentTimeMillis();
                        //Specifically check for the Single Active Certificate Constraint property, which requires that revocation happen in conjunction with renewal.
                        //We have to perform this check here, in addition to the true check in CertificateCreateSession, in order to be able to perform publishing.
                        singleActiveCertificateConstraint(admin, endEntityInformation);
                        // Issue the certificate from the request
                        final CertificateGenerationParams certGenParams = fetchCertGenParams();
                        try {
                            ret = certificateCreateSession.createCertificate(admin, endEntityInformation, ca, req, responseClass, certGenParams, updateTime);
                        } catch (CTLogException e) {
                            if (e.getPreCertificate() != null) {
                                CertificateDataWrapper certWrapper = (CertificateDataWrapper) e.getPreCertificate();
                                // Publish pre-certificate and abort issuance
                                postCreateCertificate(admin, endEntityInformation, ca,
                                        new CertificateDataWrapper(certWrapper.getCertificate(), certWrapper.getCertificateData(), certWrapper.getBase64CertData()), true, certGenParams);
                            }
                            throw new CertificateCreateException(e);
                        }
                        postCreateCertificate(admin, endEntityInformation, ca,
                                new CertificateDataWrapper(ret.getCertificate(), ret.getCertificateData(), ret.getBase64CertData()), false, certGenParams);
                        // Call authentication session and tell that we are finished with this user. (Only if we store UserData for this CA.)
                        if (ca.isUseUserStorage()) {
                            finishUser(ca, endEntityInformation);
                        }
                    }
                } catch (NoSuchEndEntityException e) {
                    // If we didn't find the entity return error message
                    final String failText = intres.getLocalizedMessage("signsession.nosuchuser", req.getUsername());
                    log.info(failText, LogRedactionUtils.getRedactedException(e));
                    throw new NoSuchEndEntityException(failText, e);
                }
            }
            ret.create();
        } catch (CustomCertificateSerialNumberException e) {
            cleanUserCertDataSN(endEntityInformation);
            throw e;
        } catch (IllegalKeyException ke) {
            log.info("Request key is of unknown type: " + ke.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Key is of unknown type: ", ke);
            }
            throw ke;
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            CryptoTokenOfflineException ex = new CryptoTokenOfflineException(msg);
            ex.initCause(ctoe);
            throw ex;
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
            throw new IllegalStateException(e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key creating certificate response: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CertificateEncodingException e) {
            log.error("There was a problem extracting the certificate information.", e);
        } catch (CRLException e) {
            log.error("There was a problem extracting the CRL information.", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(IRequestMessage)");
        }
        return ret;
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKeyWrapper pk,
                                         final int keyusage, final Date notBefore, final Date notAfter, final int certificateprofileid, final int caid)
            throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk.getPublicKey(), pk.getAltPublicKey(), keyusage, notBefore, notAfter, certificateprofileid, caid);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
                                         final int keyusage, final Date notBefore, final Date notAfter, final int certificateprofileid, final int caid)
            throws CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, NoSuchEndEntityException {
        return createCertificate(admin, username, password, pk, null, keyusage, notBefore, notAfter, certificateprofileid, caid);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
            final PublicKey altPK, final int keyusage, final Date notBefore, final Date notAfter, final int certificateprofileid, final int caid)
            throws CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(pk, " + (altPK != null ? ", altPK" : "") + ", ku, date)");
        }
        // Authorize user and get DN
        final EndEntityInformation data = authUser(admin, username, password);
        if (log.isDebugEnabled()) {
            log.debug("Authorized user " + username + " with DN='" + LogRedactionUtils.getSubjectDnLogSafe(data.getDN()) + "'." + " with CA=" + data.getCAId());
        }
        if (certificateprofileid != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
            if (log.isDebugEnabled()) {
                log.debug("Overriding user certificate profile with :" + certificateprofileid);
            }
            data.setCertificateProfileId(certificateprofileid);
        }
        // Check if we should override the CAId
        if (caid != SecConst.CAID_USEUSERDEFINED) {
            if (log.isDebugEnabled()) {
                log.debug("Overriding user caid with :" + caid);
            }
            data.setCAId(caid);
        }
        if (log.isDebugEnabled()) {
            log.debug("User type (EndEntityType) = " + data.getType().getHexValue());
        }
        // Get CA object and make sure it is active
        // Do not log access control to the CA here, that is logged later on when we use the CA to issue a certificate (if we get that far).
        final CA ca = (CA) caSession.getCANoLog(admin, data.getCAId(), null);
        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            final String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
            throw new EJBException(msg);
        }
        final Certificate cert;
        try {
            // Now finally after all these checks, get the certificate, we don't have any sequence number or extensions available here
            cert = createCertificate(admin, data, ca, pk, altPK, keyusage, notBefore, notAfter, null, null);
            // Call authentication session and tell that we are finished with this user
            finishUser(ca, data);
        } catch (CustomCertificateSerialNumberException e) {
            cleanUserCertDataSN(data);
            throw e;
        } catch (CertificateExtensionException e) {
            throw new IllegalStateException("CertificateExtensionException was thrown, even though no extensions were supplied.", e);
        }
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(pk, " + (altPK != null ? ", altPK" : "") + ", ku, date)");
        }
        return cert;
    }

    @SuppressWarnings("deprecation")
    @Override
    public Collection<CertificateWrapper> createCardVerifiableCertificateWS(final AuthenticationToken authenticationToken, final String username,
                                                                            String password, final String cvcreq)
            throws AuthorizationDeniedException, CADoesntExistsException, UserDoesntFullfillEndEntityProfile, NotFoundException, ApprovalException,
            EjbcaException, WaitingForApprovalException, SignRequestException, CertificateExpiredException, CesecoreException {
        // If password is empty we can generate a big random one to use instead.
        if (StringUtils.isEmpty(password)) {
            password = new AllPrintableCharPasswordGenerator().getNewPassword(15, 20);
            log.debug("Using a long random password.");
        }
        // See if this user already exists.
        // We allow renewal of certificates for IS's that are not revoked
        // In that case look for it's last old certificate and try to authenticate the request using an outer signature.
        // If this verification is correct, set status to NEW and continue process the request.
        int oldUserStatus = EndEntityConstants.STATUS_GENERATED;
        final EndEntityInformation user = endEntityAccessSession.findUser(authenticationToken, username);
        try {
            if (user != null) {
                oldUserStatus = user.getStatus();
                // If user is revoked, we can not proceed
                if ((oldUserStatus == EndEntityConstants.STATUS_REVOKED) || (oldUserStatus == EndEntityConstants.STATUS_HISTORICAL)) {
                    throw new AuthorizationDeniedException("User '" + username + "' is revoked.");
                }
                final CVCObject parsedObject = CertificateParser.parseCVCObject(Base64.decode(cvcreq.getBytes()));
                if (parsedObject instanceof CVCAuthenticatedRequest) {
                    if (log.isDebugEnabled()) {
                        log.debug("Received an authenticated request, could be an initial DV request signed by CVCA or a renewal for DV or IS.");
                    }
                    final CVCAuthenticatedRequest request = (CVCAuthenticatedRequest) parsedObject;
                    final CVCPublicKey publicKey = request.getRequest().getCertificateBody().getPublicKey();
                    final String algorithm = AlgorithmUtil.getAlgorithmName(publicKey.getObjectIdentifier());
                    if (log.isDebugEnabled()) {
                        log.debug("Received request has a public key with algorithm: " + algorithm);
                    }
                    final HolderReferenceField holderReference = request.getRequest().getCertificateBody().getHolderReference();
                    final CAReferenceField caReferenceField = request.getAuthorityReference();

                    // Check to see that the inner signature does not also verify using an old certificate
                    // because that means the same keys were used, and that is not allowed according to the EU policy
                    // This must be done whether it is signed by CVCA or a renewal request
                    final Collection<Certificate> oldCertificates = EJBTools
                            .unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
                    if (oldCertificates != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Found " + oldCertificates.size() + " old certificates for user " + username);
                        }
                        PublicKey oldPublicKey;
                        CVCertificate innerRequest;
                        for (Certificate certificate : oldCertificates) {
                            oldPublicKey = getCVPublicKey(authenticationToken, certificate);
                            innerRequest = request.getRequest();
                            // Throws AuthorizationDeniedException
                            checkInnerCollision(oldPublicKey, innerRequest, holderReference.getConcatenated());
                        }
                    }
                    boolean verifiedOuter = false; // So we can throw an error if we could not verify
                    if (StringUtils.equals(holderReference.getMnemonic(), caReferenceField.getMnemonic())
                            && StringUtils.equals(holderReference.getCountry(), caReferenceField.getCountry())) {
                        if (log.isDebugEnabled()) {
                            log.debug("Authenticated request is self signed, we will try to verify it using user's old certificate.");
                        }
                        final Collection<Certificate> userCertificates = EJBTools
                                .unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
                        // userCertificates contains certificates ordered with last expire date first. Last expire date should be last issued cert
                        // We have to iterate over available user certificates, because we don't know which on signed the old one
                        // and cv certificates have very coarse grained validity periods so we can't really know which one is the latest one
                        // if 2 certificates are issued the same day.
                        if (userCertificates != null) {
                            if (log.isDebugEnabled()) {
                                log.debug("Found " + userCertificates.size() + " old certificates for user " + username);
                            }
                            for (java.security.cert.Certificate certificate : userCertificates) {
                                try {
                                    // Only allow renewal if the old certificate is valid
                                    final PublicKey pk = getCVPublicKey(authenticationToken, certificate);
                                    if (log.isDebugEnabled()) {
                                        log.debug("Trying to verify the outer signature with an old certificate, fp: "
                                                + CertTools.getFingerprintAsString(certificate));
                                    }
                                    request.verify(pk);
                                    if (log.isDebugEnabled()) {
                                        log.debug("Verified outer signature.");
                                    }
                                    // Yes we did it, we can move on to the next step because the outer signature was actually created with some old certificate
                                    verifiedOuter = true;
                                    try {
                                        // Check certificate validity and set end entity status/password.
                                        // This will throw one of several exceptions if the certificate is invalid.
                                        ejbcaWSHelperSession.checkValidityAndSetUserPassword(authenticationToken, certificate, username, password);
                                        break;
                                    } catch (EndEntityProfileValidationException e) {
                                        throw new UserDoesntFullfillEndEntityProfile(e);
                                    }
                                    // If verification of outer signature fails because the signature is invalid we will break and deny the request...with a message
                                } catch (InvalidKeyException e) {
                                    String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(),
                                            e.getMessage());
                                    log.warn(msg, e);
                                } catch (CertificateExpiredException e) { // thrown by checkValidityAndSetUserPassword
                                    // Only log this with DEBUG since it will be a common case that happens, nothing that should cause any alerts.
                                    if (log.isDebugEnabled()) {
                                        log.debug(intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(),
                                                e.getMessage()));
                                    }
                                    // This exception we want to throw on, because we want to give this error if there was a certificate suitable for
                                    // verification, but it had expired. This is thrown by checkValidityAndSetUserPassword after the request has already been
                                    // verified using the public key of the certificate.
                                    throw e;
                                } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
                                    String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(),
                                            e.getMessage());
                                    log.warn(msg, e);
                                } catch (SignatureException e) {
                                    // Failing to verify the outer signature will be normal, since we must try all old certificates
                                    if (log.isDebugEnabled()) {
                                        log.debug(intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(),
                                                e.getMessage()));
                                    }
                                }
                            }
                            // If verification failed because the old certificte was not yet valid, continue processing as usual, using the sent in username/password hoping the
                            // status is NEW and password is correct. If old certificate was expired a CertificateExpiredException is thrown above.
                        }
                        // If there are no old certificates, continue processing as usual, using the sent in username/password hoping the
                        // status is NEW and password is correct.
                    } else { // if (StringUtils.equals(holderRef, caRef))
                        // Subject and issuerDN is CN=Mnemonic,C=Country
                        final String dn = "CN=" + caReferenceField.getMnemonic() + ",C=" + caReferenceField.getCountry();
                        if (log.isDebugEnabled()) {
                            log.debug("Authenticated request is not self signed, we will try to verify it using a CVCA certificate: " + dn);
                        }
                        final CAInfo info = caSession.getCAInfo(authenticationToken, DnComponents.stringToBCDNString(dn).hashCode());
                        if (info == null) {
                            log.info("No CA found to authenticate request: " + dn);
                            throw new CADoesntExistsException("CA with id " + DnComponents.stringToBCDNString(dn).hashCode() + " doesn't exist.");
                        } else {
                            final Collection<Certificate> certificateChain = info.getCertificateChain();
                            if (certificateChain != null) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Found " + certificateChain.size() + " certificates in chain for CA with DN: " + dn);
                                }
                                Iterator<Certificate> iterator = certificateChain.iterator();
                                if (iterator.hasNext()) {
                                    // The CA certificate is first in chain.
                                    final Certificate caCertificate = iterator.next();
                                    if (log.isDebugEnabled()) {
                                        log.debug("Trying to verify the outer signature with a CVCA certificate, fp: "
                                                + CertTools.getFingerprintAsString(caCertificate));
                                    }
                                    try {
                                        // The CVCA certificate always contains the full key parameters, no need to do any EC curve parameter magic here
                                        request.verify(caCertificate.getPublicKey());
                                        if (log.isDebugEnabled()) {
                                            log.debug("Verified outer signature");
                                        }
                                        verifiedOuter = true;
                                        // Yes we did it, we can move on to the next step because the outer signature was actually created with some old certificate
                                        try {
                                            // Check certificate validity and set end entity status/password.
                                            // This will throw one of several exceptions if the certificate is invalid.
                                            ejbcaWSHelperSession.checkValidityAndSetUserPassword(authenticationToken, caCertificate, username,
                                                    password);
                                        } catch (EndEntityProfileValidationException e) {
                                            throw new UserDoesntFullfillEndEntityProfile(e);
                                        }
                                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException |
                                             NoSuchProviderException
                                             | SignatureException e) {
                                        log.warn(intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(),
                                                e.getMessage()), e);
                                    }
                                }
                            } else {
                                log.info("No CA certificate found to authenticate request: " + dn);
                            }
                        }
                    }
                    // If verification failed because we could not verify the outer signature at all it is an error.
                    if (!verifiedOuter) {
                        final String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(),
                                "No certificate found that could authenticate request");
                        log.info(msg);
                        throw new AuthorizationDeniedException(msg);
                    }
                } // if (parsedObject instanceof CVCAuthenticatedRequest)
                // If it is not an authenticated request, with an outer signature, continue processing as usual,
                // using the sent in username/password hoping the status is NEW and password is correct.
            } else {
                // If there are no old user, continue processing as usual... it will fail
                log.debug("No existing user with username: " + username);
            }
        } catch (ParseException | ConstructionException | NoSuchFieldException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(authenticationToken, username, oldUserStatus);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }

        // Finally generate the certificate (assuming user status is NEW and the password is correct.
        try {
            final byte[] response = createCertificateWS(authenticationToken, username, password, cvcreq, CertificateConstants.CERT_REQ_TYPE_CVC,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            final CertificateResponse certificateResponse = new CertificateResponse(CertificateHelper.RESPONSETYPE_CERTIFICATE, response);
            final byte[] b64cert = certificateResponse.getData();
            final CVCertificate certObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
            final ArrayList<Certificate> result = new ArrayList<>();
            result.add(new CardVerifiableCertificate(certObject));
            // Get the certificate chain.
            if (user != null) {
                final int caid = user.getCAId();
                caSession.verifyExistenceOfCA(caid);
                result.addAll(getCertificateChain(caid));
            }
            log.trace("<cvcRequest");
            return EJBTools.wrapCertCollection(result);
        } catch (NoSuchEndEntityException | ParseException | ConstructionException | NoSuchFieldException
                 | InvalidKeyException | CertificateException // | CertificateEncodingException
                 | CertificateExtensionException | NoSuchAlgorithmException | NoSuchProviderException |
                 SignatureException
                 | IOException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(authenticationToken, username, oldUserStatus);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }

    /**
     * Method that gets the public key from a CV certificate, possibly enriching it with domain parameters
     * from the CVCA certificate if it is an EC public key.
     *
     * @param admin       the authentication token.
     * @param certificate the certificate to get the public ket from.
     * @return the certificates public key.
     * @throws CADoesntExistsException      if the CA of the certificate does not exist.
     * @throws AuthorizationDeniedException if authorization was denied.
     * @throws NoSuchAlgorithmException     if the key algorithm is unknown.
     * @throws NoSuchProviderException      if the crypto provider could not be found.
     * @throws InvalidKeySpecException      if the keys specification is unknown.
     */
    private PublicKey getCVPublicKey(final AuthenticationToken admin, final Certificate certificate)
            throws CADoesntExistsException, AuthorizationDeniedException {
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey instanceof PublicKeyEC) {
            // The public key of IS and DV certificate do not have any EC parameters so we have to do some magic to get a complete EC public key
            // First get to the CVCA certificate that has the parameters
            final CAInfo caInfo = caSession.getCAInfo(admin, CertTools.getIssuerDN(certificate).hashCode());
            if (caInfo == null) {
                throw new CADoesntExistsException("CA with id " + CertTools.getIssuerDN(certificate).hashCode() + " doesn't exist.");
            }
            final List<Certificate> caCertificates = caInfo.getCertificateChain();
            if (caCertificates != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found CA certificate chain of length: " + caCertificates.size());
                }
                // Get the last certificate in the chain, it is the CVCA certificate.
                if (CollectionUtils.isNotEmpty(caCertificates)) {
                    // Do the magic adding of parameters, if they don't exist in the public key.
                    final Certificate cvcaCertificate = caCertificates.get(caCertificates.size() - 1);
                    try {
                        publicKey = CvcKeyTools.getECPublicKeyWithParams(publicKey, cvcaCertificate.getPublicKey());
                    } catch (InvalidKeySpecException e) {
                        String msg = intres.getLocalizedMessage("cvc.error.outersignature", LogRedactionUtils.getSubjectDnLogSafe(certificate),
                                LogRedactionUtils.getRedactedMessage(e.getMessage()));
                        log.warn(msg, LogRedactionUtils.getRedactedException(e));
                    }
                }
            }
        }
        return publicKey;
    }

    /**
     * Method called from cvcRequest that simply verifies a CVCertificate with a public key
     * and throws AuthorizationDeniedException if the verification succeeds.
     * <p>
     * The method is used to check if a request is sent containing the same public key.
     * this could be replaced by enforcing unique public key on the CA (from EJBCA 3.10) actually...
     *
     * @param publicKey       the public key.
     * @param innerRequest    the nested request.
     * @param holderReference the holders reference.
     * @throws AuthorizationDeniedException if the authorization was denied.
     */
    private void checkInnerCollision(final PublicKey publicKey, final CVCertificate innerRequest, final String holderReference)
            throws AuthorizationDeniedException {
        // Check to see that the inner signature does not verify using an old certificate (public key)
        // because that means the same keys were used, and that is not allowed according to the EU policy.
        final CardVerifiableCertificate innerCertificate = new CardVerifiableCertificate(innerRequest);
        try {
            innerCertificate.verify(publicKey);
            String msg = intres.getLocalizedMessage("cvc.error.renewsamekeys", holderReference);
            log.info(msg);
            throw new AuthorizationDeniedException(msg);
        } catch (SignatureException e) {
            // It was good if the verification failed
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException | CertificateException e) {
            String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference, e.getMessage());
            log.warn(msg, e);
            throw new AuthorizationDeniedException(msg); // Re-factor.
        }
    }

    @Override
    public byte[] createCertificateWS(final AuthenticationToken authenticationToken, final String username, final String password, final String req,
                                      final int reqType, final String responseType)
            throws AuthorizationDeniedException, EjbcaException, CesecoreException, CADoesntExistsException, CertificateExtensionException,
            InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException,
            IOException, ParseException, ConstructionException, NoSuchFieldException, AuthStatusException, AuthLoginException {
        byte[] result = null;
        // Check user exists.
        final EndEntityInformation endEntity = endEntityAccessSession.findUser(authenticationToken, username);
        if (endEntity == null) {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword"); // Don't leak whether it was the username or the password.
            throw new NotFoundException(msg);
        }
        // Check CA exists and user is authorized to access it.
        final int caId = endEntity.getCAId();
        caSession.verifyExistenceOfCA(caId);
        // Check token type.
        if (endEntity.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
            throw new EjbcaException(ErrorCode.BAD_USER_TOKEN_TYPE,
                    "Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
        }
        // Authorization for {StandardRules.CAACCESS.resource() + caid, StandardRules.CREATECERT.resource()} is done in the
        // CertificateCreateSessionBean.createCertificate call which is called in the end
        final RequestMessage requestMessage = RequestMessageUtils.getRequestMessageFromType(username, password, req, reqType);
        if (requestMessage != null) {
            result = getCertResponseFromPublicKeyWS(authenticationToken, requestMessage, responseType, endEntity.getEndEntityProfileId());
        }
        return result;
    }

    // Tbd re-factor: CertificateHelper from WS package causes cyclic module dependency.
    private byte[] getCertResponseFromPublicKeyWS(final AuthenticationToken admin, final RequestMessage msg, final String responseType,
                                                  final int eepId) throws AuthorizationDeniedException, CertificateEncodingException, EjbcaException, CesecoreException,
            CertificateExtensionException, CertificateParsingException {
        byte[] result = null;
        final ResponseMessage response = createCertificate(admin, msg, X509ResponseMessage.class, null);
        final Certificate certificate = CertTools.getCertfromByteArray(response.getResponseMessage(), java.security.cert.Certificate.class);
        if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)) {
            result = certificate.getEncoded();
        } else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)) {
            result = createPKCS7(admin, (X509Certificate) certificate, false, eepId);
        } else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)) {
            result = createPKCS7(admin, (X509Certificate) certificate, true, eepId);
        }
        return result;
    }

    @Override
    public CertificateResponseMessage createRequestFailedResponse(final AuthenticationToken admin, final RequestMessage req,
                                                                  final Class<? extends ResponseMessage> responseClass, final FailInfo failInfo, final String failText)
            throws CADoesntExistsException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">createRequestFailedResponse(IRequestMessage)");
        }
        CertificateResponseMessage ret = null;
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            final CAToken catoken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
            setDecryptInfo(cryptoToken, req, ca);
            //Create the response message with all nonces and checks etc
            ret = ResponseMessageUtils.createResponseMessage(responseClass, req, ca.getCertificateChain(),
                    cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                    ca.getCAToken().getSignatureAlgorithm(),
                    cryptoToken.getSignProviderName());
            ret.setStatus(ResponseStatus.FAILURE);
            ret.setFailInfo(failInfo);
            ret.setFailText(failText);
            ret.create();
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key creating error response: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.warn(msg, ctoe);
            throw ctoe;
        } catch (CertificateEncodingException e) {
            log.error("There was a problem extracting the certificate information.", LogRedactionUtils.getRedactedException(e));
        } catch (CRLException e) {
            log.error("There was a problem extracting the CRL information.", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<createRequestFailedResponse(IRequestMessage)");
        }
        return ret;
    }

    @Override
    public RequestMessage decryptAndVerifyRequest(final AuthenticationToken admin, final RequestMessage req)
            throws CADoesntExistsException, SignRequestSignatureException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">decryptAndVerifyRequest(IRequestMessage)");
        }
        // Get CA that will receive request
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            setDecryptInfo(cryptoToken, req, ca);
            // Verify the request
            if (req.verify() == false) {
                String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg);
            }
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.info("Invalid key in request: " + e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Invalid key in request: ", e);
            }
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            throw ctoe;
        }
        if (log.isTraceEnabled()) {
            log.trace("<decryptAndVerifyRequest(IRequestMessage)");
        }
        return req;
    }

    /**
     * Sets information needed to decrypt a message, if such information is needed(i.e. CA private key for SCEP messages)
     *
     * @param cryptoToken
     * @param req
     * @param ca
     * @throws CryptoTokenOfflineException if the cryptotoken was unavailable.
     * @throws NoSuchAlgorithmException    if the signature on the request is done with an unhandled algorithm
     * @throws NoSuchProviderException     if there is an error with the Provider defined in the request
     */
    private void setDecryptInfo(final CryptoToken cryptoToken, final RequestMessage req, final CA ca)
            throws CryptoTokenOfflineException, NoSuchAlgorithmException, NoSuchProviderException {
        final CAToken catoken = ca.getCAToken();
        if (req.requireKeyInfo()) {
            // You go figure...scep encrypts message with the public CA-cert
            if (ca.getUseNextCACert(req)) {
                req.setKeyInfo(ca.getRolloverCertificateChain().get(0),
                        cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT)),
                        cryptoToken.getSignProviderName());
            } else {
                req.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                        cryptoToken.getSignProviderName());
            }
        }
    }

    @Override
    public ResponseMessage getCRL(final AuthenticationToken admin, final RequestMessage req, final Class<? extends ResponseMessage> responseClass)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">getCRL(IRequestMessage)");
        }
        ResponseMessage ret = null;
        // Get CA that will receive request
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            final CAToken catoken = ca.getCAToken();
            if (ca.getStatus() != CAConstants.CA_ACTIVE) {
                String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
                throw new EJBException(msg);
            }
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
            final String aliasCertSign = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(aliasCertSign), cryptoToken.getSignProviderName());
            }
            //Create the response message with all nonces and checks etc
            ret = ResponseMessageUtils.createResponseMessage(responseClass, req, ca.getCertificateChain(), cryptoToken.getPrivateKey(aliasCertSign),
                    ca.getCAToken().getSignatureAlgorithm(), cryptoToken.getSignProviderName());

            // Get the Full CRL, don't even bother digging into the encrypted CRLIssuerDN...since we already
            // know that we are the CA (SCEP is soooo stupid!).
            // It is not possible to use Partitioned CRLs via SCEP.
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            byte[] crl = crlStoreSession.getLastCRL(certSubjectDN, CertificateConstants.NO_CRL_PARTITION, false);
            if (crl != null) {
                ret.setCrl(CertTools.getCRLfromByteArray(crl));
                ret.setStatus(ResponseStatus.SUCCESS);
            } else {
                ret.setStatus(ResponseStatus.FAILURE);
                ret.setFailInfo(FailInfo.BAD_REQUEST);
            }
            ret.create();
            // TODO: handle returning errors as response message,
            // jakarta.ejb.ObjectNotFoundException and the others thrown...
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key creating CRL response: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CRLException e) {
            log.error("Cannot create response message: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            throw ctoe;
        } catch (CertificateEncodingException e) {
            log.error("There was a problem extracting the certificate information.", LogRedactionUtils.getRedactedException(e));
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCRL(IRequestMessage)");
        }
        return ret;
    }

    @Override
    public CA getCAFromRequest(final AuthenticationToken admin, final RequestMessage req, final boolean doLog)
            throws CADoesntExistsException, AuthorizationDeniedException {
        CA ca = null;
        // See if we can get issuerDN directly from request
        if (req.getIssuerDN() != null) {
            final String dn = certificateStoreSession.getCADnFromRequest(req);
            final String keySequence;

            if (req instanceof ScepRequestMessage) {
                keySequence = new BigInteger(req.getCASequence()).toString(16).toUpperCase(); // BigInteger string to uppercase for scep case
            } else {
                keySequence = req.getCASequence(); // key sequence from CVC requests, null from most other types
            }

            if (log.isDebugEnabled()) {
                log.debug(">getCAFromRequest, dn: " + dn + ": " + keySequence);
            }
            if (doLog) {
                ca = (CA) caSession.getCA(admin, dn.hashCode(), keySequence);
                if (log.isDebugEnabled()) {
                    log.debug(">getCAFromRequest, CA from hash: " + dn.hashCode() + ": " + (ca == null
                            ? "null"
                            : ca.getCAId()));
                }
            } else {
                ca = (CA) caSession.getCANoLog(admin, dn.hashCode(), keySequence);
                if (log.isDebugEnabled()) {
                    log.debug(">getCAFromRequest, CA (nolog) from hash: " + dn.hashCode() + ": " + (ca == null
                            ? "null"
                            : ca.getCAId()));
                }
            }
            if (ca == null) {
                // We could not find a CA from that DN, so it might not be a CA. Try to get from username instead
                if (req.getUsername() != null) {
                    ca = getCAFromUsername(admin, req, doLog);
                    if (log.isDebugEnabled()) {
                        log.debug("Using CA from username: " + req.getUsername());
                    }
                } else {
                    String msg = intres.getLocalizedMessage("createcert.canotfoundissuerusername", dn, "null");
                    throw new CADoesntExistsException(msg);
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Using CA (from issuerDN) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
            }

        } else if (req.getUsername() != null) {
            ca = getCAFromUsername(admin, req, doLog);
            if (log.isDebugEnabled()) {
                log.debug("Using CA from username: " + req.getUsername());
            }
        } else {
            throw new CADoesntExistsException(
                    intres.getLocalizedMessage("createcert.canotfoundissuerusername", req.getIssuerDN(), req.getUsername()));
        }

        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
            throw new EJBException(msg);
        }
        return ca;
    }

    /**
     * @param admin
     * @param req
     * @param doLog
     * @return
     * @throws CADoesntExistsException      if no end entity could be found, and hence no CA which could have created that end entity
     * @throws AuthorizationDeniedException if the authentication token wasn't authorized to the CA in question
     */
    private CA getCAFromUsername(final AuthenticationToken admin, final RequestMessage req, final boolean doLog)
            throws CADoesntExistsException, AuthorizationDeniedException {
        // See if we can get username and password directly from request
        final String username = req.getUsername();
        final EndEntityInformation data = endEntityAccessSession.findUserWithoutViewEndEntityAccessRule(admin, username);
        if (data == null) {
            throw new CADoesntExistsException("Could not find username, and hence no CA for user '" + username + "'.");
        }
        final CA ca;
        if (doLog) {
            ca = (CA) caSession.getCA(admin, data.getCAId());
        } else {
            ca = (CA) caSession.getCANoLog(admin, data.getCAId(), null);
        }
        if (log.isDebugEnabled()) {
            log.debug("Using CA (from username) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
        }
        return ca;
    }

    private EndEntityInformation authUser(final AuthenticationToken admin, final String username, final String password)
            throws NoSuchEndEntityException, AuthStatusException, AuthLoginException {
        // Authorize user and get DN
        return endEntityAuthenticationSession.authenticateUser(admin, username, password);
    }

    /**
     * Finishes user, i.e. set status to generated, if it should do so.
     * The authentication session is responsible for determining if this should be done or not
     */
    private void finishUser(final CA ca, final EndEntityInformation data) {
        if (data == null) {
            return;
        }

        if (!ca.getCAInfo().getFinishUser()) {
            cleanSerialnumberAndCsrFromUserData(data);
            endEntityManagementSession.suppressUnwantedUserDataChanges(data.getUsername());
            return;
        }

        try {
            // clean CSR
            if (data.getExtendedInformation() != null && data.getExtendedInformation().getCertificateRequest() != null) {
                data.getExtendedInformation().setCertificateRequest(null);
            }

            endEntityManagementSession.finishUser(data);
        } catch (NoSuchEndEntityException e) {
            final String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
            log.info(msg);
        }
    }

    /**
     * Clean the custom certificate serial number of user from database
     *
     * @param data of user
     */
    private void cleanUserCertDataSN(final EndEntityInformation data) {
        if (data == null || data.getExtendedInformation() == null || data.getExtendedInformation().certificateSerialNumber() == null) {
            return;
        }
        try {
            endEntityManagementSession.cleanUserCertDataSN(data.getUsername());
        } catch (NoSuchEndEntityException e) {
            final String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
            log.info(msg);
        }
    }

    /**
     * Clean the custom certificate serial number and CSR from database userData table
     *
     * @param data of user
     */
    private void cleanSerialnumberAndCsrFromUserData(final EndEntityInformation data) {
        boolean serialNumberEmpty = data == null || data.getExtendedInformation() == null || data.getExtendedInformation().certificateSerialNumber() == null;
        boolean csrEmpty = data.getExtendedInformation() == null || data.getExtendedInformation().getCertificateRequest() == null;

        if (serialNumberEmpty && csrEmpty) {
            return;
        }

        try {
            endEntityManagementSession.cleanSerialnumberAndCsrFromUserData(data.getUsername());
        } catch (NoSuchEndEntityException e) {
            final String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
            log.info(msg);
        }
    }

    /**
     * Creates the certificate, uses the cesecore method with the same signature but in addition to that calls certreqsession and publishers, and fetches the CT configuration
     *
     * @throws AuthorizationDeniedException           (rollback) if admin is not authorized to issue this certificate
     * @throws CertificateCreateException             (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException                    if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CertificateExtensionException          if any of the extensions were invalid
     * @throws InvalidAlgorithmException              if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException                     if the CA was offline
     * @throws IllegalValidityException               if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException            if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException       if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException             (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *                                                missing unique index in database, or certificate profile does not allow it
     * @throws IllegalNameException                   if the certificate request contained an illegal name
     */
    private Certificate createCertificate(final AuthenticationToken admin, final EndEntityInformation endEntityInformation, final CA ca,
            final PublicKey pk, final PublicKey altPK, final int keyusage, final Date notBefore, final Date notAfter, final Extensions extensions, final String sequence)
            throws IllegalKeyException, CertificateCreateException, AuthorizationDeniedException, CertificateExtensionException, IllegalNameException,
            CustomCertificateSerialNumberException, CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(pk, " + (altPK != null ? ", altPK" : "") + ", ku, notAfter)");
        }
        final long updateTime = System.currentTimeMillis();
        //Specifically check for the Single Active Certificate Constraint property, which requires that revocation happen in conjunction with renewal.
        //We have to perform this check here, in addition to the true check in CertificateCreateSession, in order to be able to perform publishing.
        singleActiveCertificateConstraint(admin, endEntityInformation);
        // Create the certificate. Does access control checks (with audit log) on the CA and create_certificate.
        CertificateDataWrapper certWrapper;
        final CertificateGenerationParams certGenParams = fetchCertGenParams();
        try {
            certWrapper = certificateCreateSession.createCertificate(admin, endEntityInformation, ca, null, pk, altPK, keyusage, notBefore, notAfter,
                    extensions, sequence, certGenParams, updateTime);

        } catch (CTLogException e) {
            if (e.getPreCertificate() != null) {
                certWrapper = (CertificateDataWrapper) e.getPreCertificate();
                // Publish pre-certificate and abort issuance
                postCreateCertificate(admin, endEntityInformation, ca, certWrapper, true, certGenParams);
            }
            throw new CertificateCreateException(LogRedactionUtils.getRedactedException(e));
        }
        postCreateCertificate(admin, endEntityInformation, ca, certWrapper, false, certGenParams);
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(pk, " + (altPK != null ? ", altPK" : "") + ", ku, notAfter)");
        }
        return certWrapper.getCertificate();
    }

    /**
     * Specifically check for the Single Active Certificate Constraint property, which requires that revocation happen in conjunction with renewal.
     * We have to perform this check here, in addition to the true check in CertificateCreateSession, in order to be able to perform publishing.
     *
     * @param admin                AuthenticationToken used for revoking the certificate
     * @param endEntityInformation EndEntityInformation containing username, DN and certificate profile id
     */
    private void singleActiveCertificateConstraint(final AuthenticationToken admin, final EndEntityInformation endEntityInformation)
            throws CertificateRevokeException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">singleActiveCertificateConstraint()");
        }
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
        if (certProfile.isSingleActiveCertificateConstraint()) {
            // Only get not yet expired certificates with status CERT_ACTIVE, CERT_NOTIFIEDABOUTEXPIRATION, CERT_REVOKED
            final List<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(endEntityInformation.getUsername(), true,
                    Arrays.asList(CertificateConstants.CERT_ARCHIVED, CertificateConstants.CERT_INACTIVE, CertificateConstants.CERT_ROLLOVERPENDING,
                            CertificateConstants.CERT_UNASSIGNED));
            List<Integer> publishers = certProfile.getPublisherList();
            if (log.isDebugEnabled()) {
                log.debug("SingleActiveCertificateConstraint, found " + cdws.size() + " old (non expired, active) certificates and "
                        + publishers.size() + " publishers.");
            }
            // Set the revocation dates
            for (CertificateDataWrapper cdw : cdws) {
                if (cdw.getCertificateData().getRevocationDate() == -1) {
                    cdw.getCertificateData().setRevocationDate(new Date());
                }
            }
            // Go directly to RevocationSession and not via EndEntityManagementSession because we don't care about approval checks and so forth,
            // the certificate must be revoked nonetheless.
            revocationSession.revokeCertificates(admin, cdws, publishers, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
        }
        if (log.isTraceEnabled()) {
            log.trace("<singleActiveCertificateConstraint()");
        }
    }

    @Override
    public CertificateGenerationParams fetchCertGenParams() {
        // Supply extra info to X509CA for Certificate Transparency
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);

        final CertificateGenerationParams certGenParams = new CertificateGenerationParams();
        final CTSubmissionConfigParams ctConfig = new CTSubmissionConfigParams();
        ctConfig.setConfiguredCTLogs(globalConfiguration.getCTLogs());
        ctConfig.setValidityPolicy(globalConfiguration.getGoogleCtPolicy());
        certGenParams.setCTSubmissionConfigParams(ctConfig);
        return certGenParams;
    }

    /**
     * Perform a set of actions post certificate creation
     *
     * @param authenticationToken the authentication token being used
     * @param endEntity           the end entity involved
     * @param ca                  the relevant CA
     * @param certificateWrapper  the newly created Certificate
     * @param certGenParams       Used to add certificate to IncompleteIssuanceJournalData
     * @throws AuthorizationDeniedException if access is denied to the CA issuing certificate
     */
    private void postCreateCertificate(final AuthenticationToken authenticationToken, final EndEntityInformation endEntity, final CA ca,
                                       final CertificateDataWrapper certificateWrapper, final boolean storePreCert, final CertificateGenerationParams certGenParams) throws AuthorizationDeniedException {
        // Store the request data in history table.
        if (ca.isUseCertReqHistory()) {
            certreqHistorySession.addCertReqHistoryData(certificateWrapper.getCertificate(), endEntity);
        }
        final BaseCertificateData certData = certificateWrapper.getBaseCertificateData();
        final int certProfileId = endEntity.getCertificateProfileId();
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);
        final Collection<Integer> publishers = certProfile.getPublisherList();
        if (!publishers.isEmpty()) {
            if (storePreCert) {
                // CTLogException occurred store pre-cert in new transaction to avoid rollback.
                publisherSession.storeCertificateNewTransaction(authenticationToken, publishers, certificateWrapper, endEntity.getPassword(),
                        endEntity.getCertificateDN(), endEntity.getExtendedInformation());
            } else {
                publisherSession.storeCertificate(authenticationToken, publishers, certificateWrapper, endEntity.getPassword(),
                        endEntity.getCertificateDN(), endEntity.getExtendedInformation());
            }
        }
        // At this point, it is safe to remove the certificate from "incomplete issuance journal". This runs in the same transaction as the certificate creation
        if (certData != null) {
            certGenParams.removeFromIncompleteIssuanceJournal(ca.getCAId(), new BigInteger(certData.getSerialNumber()), storePreCert);
            //If it's an X509 CA, we have the option to pre-compute the OCSP response directly upon issuance
            if (ca.getCAType() == X509CAInfo.CATYPE_X509) {
                final X509CA x509ca = (X509CA) ca;
                final X509Certificate x509Certificate = (X509Certificate) certificateWrapper.getCertificate();

                if ((x509ca.isDoPreProduceOcspResponses() && x509ca.isDoPreProduceOcspResponseUponIssuanceAndRevocation())
                        && (x509Certificate != null && !x509ca.getCertificateChain().isEmpty())) {
                    ocspResponseGeneratorSession.preSignOcspResponse((X509Certificate) x509ca.getCertificateChain().get(0),
                            CertTools.getSerialNumber(x509Certificate), PresignResponseValidity.CONFIGURATION_BASED, true, CertificateConstants.DEFAULT_CERTID_HASH_ALGORITHM);
                }
            }

        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] signPayload(final byte[] data, final int signingCaId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CADoesntExistsException, SignRequestSignatureException {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to sign payload from CA with ID " + signingCaId);
        }
        final CA ca = (CA) caSession.getCA(new AlwaysAllowLocalAuthenticationToken("Called from SignSessionBean.signPayload"), signingCaId);
        if (ca == null) {
            log.debug("CA with ID " + signingCaId + " does not exist.");
            throw new CADoesntExistsException("CA with ID " + signingCaId + " does not exist.");
        }
        final CAToken catoken = ca.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
        final PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        if (privateKey == null) {
            throw new CryptoTokenOfflineException("Could not retrieve private certSignKey from CA with ID " + signingCaId);
        }
        final PublicKey publicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        if (publicKey == null) {
            throw new CryptoTokenOfflineException("Could not retrieve public certSignKey from CA with ID " + signingCaId);
        }
        final X509Certificate signerCert;
        try {
            signerCert = (X509Certificate) ca.getCACertificate();
        } catch (ClassCastException e) {
            throw new IllegalStateException("Not possible to sign a payload using a CV CA", e);
        }
        final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        // Find the signature algorithm from the public key, because it is more granular, i.e. can differnetiate between ML-DSA-44 and ML-DSA-65
        final String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(catoken.getSignatureAlgorithm(),
                publicKey.getAlgorithm());
        try {
            final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(cryptoToken.getSignProviderName()).build(privateKey);
            final JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            final JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
            gen.addSignerInfoGenerator(builder.build(contentSigner, signerCert));
            gen.addCertificates(new CollectionStore<>(CertTools.convertToX509CertificateHolder(Arrays.asList(signerCert))));
            final CMSSignedData sigData = gen.generate(new CMSProcessableByteArray(data), true);
            return sigData.getEncoded();
        } catch (CMSException | CertificateEncodingException | IOException | OperatorCreationException e) {
            log.debug("Given payload could not be signed.", e);
            throw new SignRequestSignatureException("Given payload could not be signed.", e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] signItsPayload(final byte[] data, final ECA eca)
            throws CryptoTokenOfflineException, SignRequestSignatureException {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to sign ITS payload from CA with ID " + eca.getCAId());
        }

        final CAToken catoken = eca.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
        final PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        if (privateKey == null) {
            throw new CryptoTokenOfflineException("Could not retrieve private certSignKey from CA with ID " + eca.getCAId());
        }

        final ITSCertificate ecaCertificate = eca.getItsCACertificate();
        if (ecaCertificate == null) {
            throw new IllegalStateException("ECA is not initialized i.e. no certificate.");
        }

        try {
            // Psid is same for EC enroll and authorization validation
            ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder.builder(
                    new Psid(ITSApplicationIds.SECURED_CERT_REQUEST_SERVICE.getPsId()));
            signedDataBuilder.setUnsecuredData(data);
            JcaITSContentSigner dataSigner = new JcaITSContentSigner.Builder()
                    .setProvider(cryptoToken.getSignProviderName()).build(privateKey, ecaCertificate);
            HashedId8 hashedCurrentEnrollCredential = ECAUtils.generateHashedId8(ecaCertificate);
            ETSISignedData etsiSignedData = signedDataBuilder.build(dataSigner, hashedCurrentEnrollCredential);

            return etsiSignedData.getEncoded();
        } catch (Exception e) {
            // high level catch block
            log.debug("ITS payload could not be signed.", e);
            throw new SignRequestSignatureException("ITS payload could not be signed.", e);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public ITSCertificate createEnrollCredential(AuthenticationToken admin, Builder certificateBuilder,
                                                 CertificateId certifcateId, PublicVerificationKey verificationKey,
                                                 ECA eca, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateCreateException {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to generate EC from CA with ID " + eca.getCAId());
        }

        return certificateCreateSession.createItsCertificate(admin, endEntity, eca, certificateBuilder, certifcateId, verificationKey);
    }

    @Override
    public byte[] signItsPayload(ETSISignedDataBuilder signedDataBuilder, ECA eca)
            throws CryptoTokenOfflineException, SignRequestSignatureException {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to sign ITS payload from CA with ID " + eca.getCAId());
        }

        final CAToken catoken = eca.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
        final PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        if (privateKey == null) {
            throw new CryptoTokenOfflineException("Could not retrieve private certSignKey from CA with ID " + eca.getCAId());
        }

        final ITSCertificate ecaCertificate = eca.getItsCACertificate();
        if (ecaCertificate == null) {
            throw new IllegalStateException("ECA is not initialized i.e. no certificate.");
        }

        try {
            // Psid is same for EC enroll and authorization validation
            ITSContentSigner dataSigner = eca.getITSContentSigner(privateKey, ecaCertificate);

            HashedId8 hashedCurrentEnrollCredential = ECAUtils.generateHashedId8(ecaCertificate);
            ETSISignedData etsiSignedData = signedDataBuilder.build(dataSigner, hashedCurrentEnrollCredential);

            return etsiSignedData.getEncoded();
        } catch (Exception e) {
            // high level catch block
            log.debug("ITS payload could not be signed.", e);
            throw new SignRequestSignatureException("ITS payload could not be signed.", e);
        }
    }

    @Override
    public byte[] createCmcFullPkiResponse(AuthenticationToken admin, int caId, X509Certificate cert, MsKeyArchivalRequestMessage request)
            throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/2524682a-9587-4ac1-8adf-7e8094baa321
        if (log.isTraceEnabled()) {
            log.trace(">createCmcFullPkiResponse");
        }
        final X509CA ca = (X509CA) caSession.getCA(admin, caId);
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        final byte[] returnval = createCmcFullPkiResponse(ca, cryptoToken, cert, request);

        // Audit log that we used the CA's signing key to create a CMS signature
        final String detailsMsg = intres.getLocalizedMessage("caadmin.signedcms", ca.getName());
        final Map<String, Object> details = new LinkedHashMap<>();
        if (cert != null) {
            details.put("leafSubject", LogRedactionUtils.getSubjectDnLogSafe(cert));
            details.put("leafFingerprint", CertTools.getFingerprintAsString(cert));
        }
        details.put("msg", detailsMsg);
        securityEventsLoggerSession.log(EjbcaEventTypes.CA_SIGNCMS, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                String.valueOf(caId), null, null, details);

        if (log.isTraceEnabled()) {
            log.trace("<createCmcFullPkiResponse()");
        }
        return returnval;
    }

    private byte[] createCmcFullPkiResponse(X509CA ca, CryptoToken cryptoToken, X509Certificate cert, MsKeyArchivalRequestMessage request) throws SignRequestSignatureException {
        // future add otherInfo when approval support is added over MSAE
        CMCStatusInfoBuilder cmcStatusInfoBuilder = null;
        if(cert!=null) {
            cmcStatusInfoBuilder = new CMCStatusInfoBuilder(CMCStatus.success, new BodyPartID(0x01));
            cmcStatusInfoBuilder.setStatusString("Issued"); // human readble string
        } else {
            cmcStatusInfoBuilder = new CMCStatusInfoBuilder(CMCStatus.failed, new BodyPartID(0x01));
            cmcStatusInfoBuilder.setStatusString("Failed");
        }

        TaggedAttribute taggedAttribute1 = new TaggedAttribute(new BodyPartID(0x01),
                CMCObjectIdentifiers.id_cmc_statusInfo,
                new DERSet(cmcStatusInfoBuilder.build()));

        Attribute certHash = null;
        try {
            certHash = new Attribute(MsKeyArchivalRequestMessage.szOID_ISSUED_CERT_HASH,
                                    new DERSet(new DEROctetString(CertTools.generateSHA1Fingerprint(cert.getEncoded()))));
        } catch (CertificateEncodingException e) {
            log.debug("Error during marshalling issued certificate hash", e);
            throw new IllegalStateException(e);
        }

        Attribute encryptedKeyHash = new Attribute(MsKeyArchivalRequestMessage.szOID_ENCRYPTED_KEY_HASH,
                new DERSet(new DEROctetString(request.getEnvelopedPrivKeyHash())));

        ASN1Encodable wrappedAttributes = new DERSequence(
                new ASN1Encodable[]{new ASN1Integer(0),
                        new DERSequence(new ASN1Integer(1)), new DERSet(new ASN1Encodable[]{certHash, encryptedKeyHash})});

        TaggedAttribute taggedAttribute2 = new TaggedAttribute(new BodyPartID(0x02),
                MsKeyArchivalRequestMessage.szOID_CMC_ADD_ATTRIBUTES,
                new DERSet(wrappedAttributes));

        DERSequence payload = new DERSequence(new ASN1Encodable[]{taggedAttribute1, taggedAttribute2});
        DERSequence pkiRespAsSequence = new DERSequence(
                        new ASN1Encodable[]{payload, new DERSequence(), new DERSequence()});
        PKIResponse pkiResponse = PKIResponse.getInstance(pkiRespAsSequence);
        try {
            String hashAlgorithm = AlgorithmTools.getHashAlgorithm(ca.getCAInfo().getCAToken().getSignatureAlgorithm());
            final MessageDigest md = MessageDigest.getInstance(hashAlgorithm); // may be sha256 always
            byte[] payloadHash = md.digest(pkiResponse.getEncoded());

            // signerInfo
            JcaSignerInfoGeneratorBuilder signerInfobuilder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());

            Attribute contentTypeAttribute = new Attribute(MsKeyArchivalRequestMessage.szOID_PKCS_9_CONTENT_TYPE,
                                                        new DERSet(CMCObjectIdentifiers.id_cct_PKIResponse));
            Attribute contentHashAttribute = new Attribute(MsKeyArchivalRequestMessage.szOID_PKCS_9_MESSAGE_DIGEST,
                    new DERSet(new DEROctetString(payloadHash)));

            AttributeTable attrTable = new AttributeTable(new DERSet(
                    new ASN1Encodable[]{ contentTypeAttribute.toASN1Primitive(),
                                                    contentHashAttribute.toASN1Primitive()}));
            signerInfobuilder.setSignedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));

            final PrivateKey caPrivateKey = cryptoToken.getPrivateKey(ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            ContentSigner caSigner = new JcaContentSignerBuilder(ca.getCAInfo().getCAToken().getSignatureAlgorithm())
                                                        .setProvider(cryptoToken.getSignProviderName())
                                                                                .build(caPrivateKey);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(signerInfobuilder.build(caSigner, (X509Certificate) ca.getCACertificate()));

            // add certificate chain
            List<X509CertificateHolder> certChain = new ArrayList<>();
            if (cert!=null) {
                certChain.add(new X509CertificateHolder(cert.getEncoded()));
            }
            ca.getCertificateChain().forEach(x -> {
                try {
                    certChain.add(new X509CertificateHolder(x.getEncoded()));
                } catch (CertificateEncodingException | IOException e) {
                    log.debug("Error during ca cert chain encoding", e);
                    throw new IllegalStateException(e);
                }
            });

            CollectionStore<X509CertificateHolder> store = new CollectionStore<>(certChain);
            gen.addCertificates(store);

            CMSTypedData data = new CMSProcessableByteArray(CMCObjectIdentifiers.id_cct_PKIResponse, pkiResponse.getEncoded());
            CMSSignedData cmsResponse = gen.generate(data, true);
            return cmsResponse.getEncoded();

        } catch (Exception e) {
            log.info("CMC signing failed: ", e);
            throw new SignRequestSignatureException("CMC signing failed: ", e);
        }
    }
}
