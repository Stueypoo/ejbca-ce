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
package org.cesecore.certificates.ca;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.ca.internal.RequestAndPublicKeySelector;
import org.cesecore.certificates.ca.internal.SernoGenerator;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.IncompletelyIssuedCertificateInfo;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificatetransparency.CTLogException;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.ValidationException;
import org.cesecore.util.LogRedactionUtils;
import org.cesecore.util.PrintableStringNameStyle;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ValidityDate;

/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation according to the X509 standard.
 */
public class X509CAImpl extends CABase implements Serializable, X509CA {

    private static final long serialVersionUID = -2882572653108530258L;

    private static final Logger log = Logger.getLogger(X509CAImpl.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    // protected fields for properties specific to this type of CA.
    protected static final String POLICIES = "policies";
    protected static final String USEAUTHORITYKEYIDENTIFIER = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String AUTHORITY_INFORMATION_ACCESS = "authorityinformationaccess";
    protected static final String CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI = "certificateaiadefaultcaissueruri";
    protected static final String USECRLNUMBER = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL = "crlnumbercritical";
    protected static final String DEFAULTCRLDISTPOINT = "defaultcrldistpoint";
    protected static final String DEFAULTCRLISSUER = "defaultcrlissuer";
    protected static final String DEFAULTOCSPSERVICELOCATOR = "defaultocspservicelocator";
    protected static final String CADEFINEDFRESHESTCRL = "cadefinedfreshestcrl";
    protected static final String USEUTF8POLICYTEXT = "useutf8policytext";
    protected static final String USEPRINTABLESTRINGSUBJECTDN = "useprintablestringsubjectdn";
    protected static final String USELDAPDNORDER = "useldapdnorder";
    protected static final String USECRLDISTRIBUTIONPOINTONCRL = "usecrldistributionpointoncrl";
    protected static final String CRLDISTRIBUTIONPOINTONCRLCRITICAL = "crldistributionpointoncrlcritical";
    protected static final String CMPRAAUTHSECRET = "cmpraauthsecret";
    protected static final String NAMECONSTRAINTSPERMITTED = "nameconstraintspermitted";
    protected static final String NAMECONSTRAINTSEXCLUDED = "nameconstraintsexcluded";
    protected static final String USEPARTITIONEDCRL = "usepartitionedcrl";
    protected static final String CRLPARTITIONS = "crlpartitions";
    protected static final String SUSPENDEDCRLPARTITIONS = "suspendedcrlpartitions";
    protected static final String REQUESTPREPROCESSOR = "requestpreprocessor";
    protected static final String ALTERNATECHAINS = "alternatechains";

    private static final CertificateTransparency ct = CertificateTransparencyFactory.getInstance();

    /** Buffer size used for BufferingContentSigner, this is the max buffer is collect before making a "sign" call.
     * This is important in order to not make several calls to a network attached HSM for example, as that slows signing down a lot
     * due to network round-trips. As long as the object to sign is smaller than this buffer a single round-trip is done.
     * Size is selected as certificates are almost never this big, and this is a reasonable size to do round-tripping on for CRLs.
     */
    private static final int SIGN_BUFFER_SIZE = 20480;

    /** Dummy constructor to allow ServiceLoader to instantiate the class */
    public X509CAImpl() {
    }

    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public X509CAImpl(final X509CAInfo cainfo) {
        super(cainfo);
        //Verify integrity if caInfo, either one SubjectDN or SubjectAltName needs to be filled in
        if(StringUtils.isEmpty(DNFieldsUtil.removeAllEmpties(cainfo.getSubjectDN())) && StringUtils.isEmpty(cainfo.getSubjectAltName())) {
            throw new IllegalArgumentException("Subject DN and Alt Name can't both be blank for an X509 CA.");
        }
        data.put(POLICIES, cainfo.getPolicies());
        data.put(SUBJECTALTNAME, cainfo.getSubjectAltName());
        data.put(CABase.CATYPE, CAInfo.CATYPE_X509);
        data.put(VERSION, LATEST_VERSION);
        setMsCaCompatible(cainfo.isMsCaCompatible());
        setUseAuthorityKeyIdentifier(cainfo.getUseAuthorityKeyIdentifier());
        setAuthorityKeyIdentifierCritical(cainfo.getAuthorityKeyIdentifierCritical());
        setUseCRLNumber(cainfo.getUseCRLNumber());
        setCRLNumberCritical(cainfo.getCRLNumberCritical());
        setDefaultCRLDistPoint(cainfo.getDefaultCRLDistPoint());
        setDefaultCRLIssuer(cainfo.getDefaultCRLIssuer());
        setCADefinedFreshestCRL(cainfo.getCADefinedFreshestCRL());
        setDefaultOCSPServiceLocator(cainfo.getDefaultOCSPServiceLocator());
        setUseUTF8PolicyText(cainfo.getUseUTF8PolicyText());
        setUsePrintableStringSubjectDN(cainfo.getUsePrintableStringSubjectDN());
        setUseLdapDNOrder(cainfo.getUseLdapDnOrder());
        setUseCrlDistributionPointOnCrl(cainfo.getUseCrlDistributionPointOnCrl());
        setCrlDistributionPointOnCrlCritical(cainfo.getCrlDistributionPointOnCrlCritical());
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL());
        setCmpRaAuthSecret(cainfo.getCmpRaAuthSecret());
        // CA Issuer URI to put in CRLs (RFC5280 section 5.2.7, not the URI to put in certs
        setAuthorityInformationAccess(cainfo.getAuthorityInformationAccess());
        setCertificateAiaDefaultCaIssuerUri(cainfo.getCertificateAiaDefaultCaIssuerUri());
        setNameConstraintsPermitted(cainfo.getNameConstraintsPermitted());
        setNameConstraintsExcluded(cainfo.getNameConstraintsExcluded());
        setCaSerialNumberOctetSize(cainfo.getCaSerialNumberOctetSize());
        setDoPreProduceOcspResponses(cainfo.isDoPreProduceOcspResponses());
        setDoStoreOcspResponsesOnDemand(cainfo.isDoStoreOcspResponsesOnDemand());
        setDoPreProduceOcspResponseUponIssuanceAndRevocation(cainfo.isDoPreProduceOcspResponseUponIssuanceAndRevocation());
        setUsePartitionedCrl(cainfo.getUsePartitionedCrl());
        setCrlPartitions(cainfo.getCrlPartitions());
        setSuspendedCrlPartitions(cainfo.getSuspendedCrlPartitions());
        setRequestPreProcessor(cainfo.getRequestPreProcessor());
    }

    /**
     * Constructor used when retrieving existing X509CA from database.
     */
    @SuppressWarnings("deprecation")
    public X509CAImpl(final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime) {
        super(data);
        setExpireTime(expireTime); // Make sure the internal state is synched with the database column. Required for upgrades from EJBCA 3.5.6 or
                                   // EJBCA 3.6.1 and earlier.
        final List<ExtendedCAServiceInfo> externalcaserviceinfos = new ArrayList<>();
        for (final Integer type : getExternalCAServiceTypes()) {
            // TYPE_OCSPEXTENDEDSERVICE type was removed in 6.0.0.
            // TYPE_HARDTOKENENCEXTENDEDSERVICE type was removed in 7.1.0.
            // They are removed from the database in the upgrade method in this class, but need to be ignored for instantiation.
            if (type != ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE && type != ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE) {
                ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(type);
                if (info != null) {
                    externalcaserviceinfos.add(info);
                }
            }
        }
        X509CAInfo info =  new X509CAInfo.X509CAInfoBuilder()
                .setSubjectDn(subjectDn)
                .setName(name)
                .setStatus(status)
                .setUpdateTime(updateTime)
                .setSubjectAltName(getSubjectAltName())
                .setCertificateProfileId(getCertificateProfileId())
                .setDefaultCertProfileId(getDefaultCertificateProfileId())
                .setUseNoConflictCertificateData(isUseNoConflictCertificateData())
                .setEncodedValidity(getEncodedValidity())
                .setExpireTime(getExpireTime())
                .setCaType(getCAType())
                .setSignedBy(getSignedBy())
                .setCertificateChain(getCertificateChain())
                .setCaToken(getCAToken())
                .setDescription(getDescription())
                .setCaSerialNumberOctetSize(getSerialNumberOctetSize())
                .setDoPreProduceOcspResponses(isDoPreProduceOcspResponses())
                .setDoStoreOcspResponsesOnDemand(isDoStoreOcspResponsesOnDemand())
                .setDoPreProduceIndividualOcspResponses(isDoPreProduceOcspResponseUponIssuanceAndRevocation())
                .setRevocationReason(getRevocationReason())
                .setRevocationDate(getRevocationDate())
                .setPolicies(getPolicies())
                .setCrlPeriod(getCRLPeriod())
                .setCrlIssueInterval(getCRLIssueInterval())
                .setCrlOverlapTime(getCRLOverlapTime())
                .setDeltaCrlPeriod(getDeltaCRLPeriod())
                .setGenerateCrlUponRevocation(getGenerateCrlUponRevocation())
                .setAllowChangingRevocationReason(getAllowChangingRevocationReason())
                .setAllowInvalidityDate(getAllowInvalidityDate())
                .setCrlPublishers(getCRLPublishers())
                .setValidators(getValidators())
                .setUseAuthorityKeyIdentifier(getUseAuthorityKeyIdentifier())
                .setAuthorityKeyIdentifierCritical(getAuthorityKeyIdentifierCritical())
                .setUseCrlNumber(getUseCRLNumber())
                .setCrlNumberCritical(getCRLNumberCritical())
                .setDefaultCrlDistPoint(getDefaultCRLDistPoint())
                .setDefaultCrlIssuer(getDefaultCRLIssuer())
                .setDefaultOcspCerviceLocator(getDefaultOCSPServiceLocator())
                .setAuthorityInformationAccess(getAuthorityInformationAccess())
                .setCertificateAiaDefaultCaIssuerUri(getCertificateAiaDefaultCaIssuerUri())
                .setNameConstraintsPermitted(getNameConstraintsPermitted())
                .setNameConstraintsExcluded(getNameConstraintsExcluded())
                .setCaDefinedFreshestCrl(getCADefinedFreshestCRL())
                .setFinishUser(getFinishUser())
                .setExtendedCaServiceInfos(externalcaserviceinfos)
                .setUseUtf8PolicyText(getUseUTF8PolicyText())
                .setApprovals(getApprovals())
                .setUsePrintableStringSubjectDN(getUsePrintableStringSubjectDN())
                .setUseLdapDnOrder(getUseLdapDNOrder())
                .setUseCrlDistributionPointOnCrl(getUseCrlDistributionPointOnCrl())
                .setCrlDistributionPointOnCrlCritical(getCrlDistributionPointOnCrlCritical())
                .setIncludeInHealthCheck(getIncludeInHealthCheck())
                .setDoEnforceUniquePublicKeys(isDoEnforceUniquePublicKeys())
                .setDoEnforceKeyRenewal(isDoEnforceKeyRenewal())
                .setDoEnforceUniqueDistinguishedName(isDoEnforceUniqueDistinguishedName())
                .setDoEnforceUniqueSubjectDNSerialnumber(isDoEnforceUniqueSubjectDNSerialnumber())
                .setUseCertReqHistory(isUseCertReqHistory())
                .setUseUserStorage(isUseUserStorage())
                .setUseCertificateStorage(isUseCertificateStorage())
                .setAcceptRevocationNonExistingEntry(isAcceptRevocationNonExistingEntry())
                .setCmpRaAuthSecret(getCmpRaAuthSecret())
                .setKeepExpiredCertsOnCRL(getKeepExpiredCertsOnCRL())
                .setUsePartitionedCrl(getUsePartitionedCrl())
                .setCrlPartitions(getCrlPartitions())
                .setSuspendedCrlPartitions(getSuspendedCrlPartitions())
                .setRequestPreProcessor(getRequestPreProcessor())
                .setMsCaCompatible(isMsCaCompatible())
                .setAlternateCertificateChains(getAlternateCertificateChains())
                .build();
        info.setExternalCdp(getExternalCdp());
        info.setNameChanged(getNameChanged());
        //These to settings were deprecated in 6.8.0, but are still set for upgrade reasons
        info.setApprovalProfile(getApprovalProfile());
        info.setApprovalSettings(getApprovalSettings());
        super.setCAInfo(info);
        setCAId(caId);
    }

    private boolean isUseNoConflictCertificateData() {
        return getBoolean(USENOCONFLICTCERTIFICATEDATA, false);
    }

    // Public Methods.
    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getPolicies()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<CertificatePolicy> getPolicies() {
        return (List<CertificatePolicy>) data.get(POLICIES);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setPolicies(java.util.List)
     */
    @Override
    public void setPolicies(List<CertificatePolicy> policies) {
        data.put(POLICIES, policies);
    }


    @Override
    public boolean isMsCaCompatible() {
        Object isMsCaCompatible = data.get(MSCACOMPATIBLE);
        if (isMsCaCompatible == null) {
            return false;
        }

        return (Boolean) isMsCaCompatible;
    }

    @Override
    public void setMsCaCompatible(boolean isMsCaCompatible) {
        data.put(MSCACOMPATIBLE, isMsCaCompatible);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUseAuthorityKeyIdentifier()
     */
    @Override
    public boolean getUseAuthorityKeyIdentifier() {
        return (Boolean) data.get(USEAUTHORITYKEYIDENTIFIER);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUseAuthorityKeyIdentifier(boolean)
     */
    @Override
    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) {
        data.put(USEAUTHORITYKEYIDENTIFIER, useauthoritykeyidentifier);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getAuthorityKeyIdentifierCritical()
     */
    @Override
    public boolean getAuthorityKeyIdentifierCritical() {
        return (Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setAuthorityKeyIdentifierCritical(boolean)
     */
    @Override
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) {
        data.put(AUTHORITYKEYIDENTIFIERCRITICAL, authoritykeyidentifiercritical);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getAuthorityInformationAccess()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<String> getAuthorityInformationAccess() {
        return (List<String>) data.get(AUTHORITY_INFORMATION_ACCESS);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setAuthorityInformationAccess(java.util.List)
     */
    @Override
    public void setAuthorityInformationAccess(List<String> authorityInformationAccess) {
        data.put(AUTHORITY_INFORMATION_ACCESS, authorityInformationAccess);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getCertificateAiaDefaultCaIssuerUri()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<String> getCertificateAiaDefaultCaIssuerUri() {
        return (List<String>) data.get(CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCertificateAiaDefaultCaIssuerUri(java.util.List)
     */
    @Override
    public void setCertificateAiaDefaultCaIssuerUri(List<String> uris) {
        data.put(CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI, uris);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUseCRLNumber()
     */
    @Override
    public boolean getUseCRLNumber() {
        return (Boolean) data.get(USECRLNUMBER);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUseCRLNumber(boolean)
     */
    @Override
    public void setUseCRLNumber(boolean usecrlnumber) {
        data.put(USECRLNUMBER, usecrlnumber);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getCRLNumberCritical()
     */
    @Override
    public boolean getCRLNumberCritical() {
        return (Boolean) data.get(CRLNUMBERCRITICAL);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCRLNumberCritical(boolean)
     */
    @Override
    public void setCRLNumberCritical(boolean crlnumbercritical) {
        data.put(CRLNUMBERCRITICAL, crlnumbercritical);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getDefaultCRLDistPoint()
     */
    @Override
    public String getDefaultCRLDistPoint() {
        return (String) data.get(DEFAULTCRLDISTPOINT);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setDefaultCRLDistPoint(java.lang.String)
     */
    @Override
    public void setDefaultCRLDistPoint(String defaultcrldistpoint) {
        if (defaultcrldistpoint == null) {
            data.put(DEFAULTCRLDISTPOINT, "");
        } else {
            data.put(DEFAULTCRLDISTPOINT, defaultcrldistpoint);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getDefaultCRLIssuer()
     */
    @Override
    public String getDefaultCRLIssuer() {
        return (String) data.get(DEFAULTCRLISSUER);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setDefaultCRLIssuer(java.lang.String)
     */
    @Override
    public void setDefaultCRLIssuer(String defaultcrlissuer) {
        if (defaultcrlissuer == null) {
            data.put(DEFAULTCRLISSUER, "");
        } else {
            data.put(DEFAULTCRLISSUER, defaultcrlissuer);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getCADefinedFreshestCRL()
     */
    @Override
    public String getCADefinedFreshestCRL() {
        return (String) data.get(CADEFINEDFRESHESTCRL);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCADefinedFreshestCRL(java.lang.String)
     */
    @Override
    public void setCADefinedFreshestCRL(String cadefinedfreshestcrl) {
        if (cadefinedfreshestcrl == null) {
            data.put(CADEFINEDFRESHESTCRL, "");
        } else {
            data.put(CADEFINEDFRESHESTCRL, cadefinedfreshestcrl);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getDefaultOCSPServiceLocator()
     */
    @Override
    public String getDefaultOCSPServiceLocator() {
        return (String) data.get(DEFAULTOCSPSERVICELOCATOR);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setDefaultOCSPServiceLocator(java.lang.String)
     */
    @Override
    public void setDefaultOCSPServiceLocator(String defaultocsplocator) {
        if (defaultocsplocator == null) {
            data.put(DEFAULTOCSPSERVICELOCATOR, "");
        } else {
            data.put(DEFAULTOCSPSERVICELOCATOR, defaultocsplocator);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUseUTF8PolicyText()
     */
    @Override
    public boolean getUseUTF8PolicyText() {
        return (Boolean) data.get(USEUTF8POLICYTEXT);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUseUTF8PolicyText(boolean)
     */
    @Override
    public void setUseUTF8PolicyText(boolean useutf8) {
        data.put(USEUTF8POLICYTEXT, useutf8);
    }

    @Override
    public boolean getUsePartitionedCrl() {
        if(data.containsKey(USEPARTITIONEDCRL)) {
            return (Boolean) data.get(USEPARTITIONEDCRL);
        }
        return false;
    }

    @Override
    public void setUsePartitionedCrl(boolean usePartitionedCrl) {
        data.put(USEPARTITIONEDCRL, usePartitionedCrl);
    }

    @Override
    public int getCrlPartitions() {
        if (data.containsKey(CRLPARTITIONS)) {
            return (Integer) data.get(CRLPARTITIONS);
        }
        return 0;
    }

    @Override
    public void setCrlPartitions(final int crlPartitions) {
        data.put(CRLPARTITIONS, crlPartitions);
    }

    @Override
    public int getSuspendedCrlPartitions() {
        if (data.containsKey(SUSPENDEDCRLPARTITIONS)) {
            return (Integer) data.get(SUSPENDEDCRLPARTITIONS);
        }
        return 0;
    }

    @Override
    public void setSuspendedCrlPartitions(final int suspendedCrlPartitions) {
        data.put(SUSPENDEDCRLPARTITIONS, suspendedCrlPartitions);
    }

    @Override
    public String getRequestPreProcessor() {
        return (String) data.get(REQUESTPREPROCESSOR);
    }

    @Override
    public void setRequestPreProcessor(final String preProcessorClass) {
        data.put(REQUESTPREPROCESSOR, preProcessorClass);
    }


    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUsePrintableStringSubjectDN()
     */
    @Override
    public boolean getUsePrintableStringSubjectDN() {
        return (Boolean) data.get(USEPRINTABLESTRINGSUBJECTDN);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUsePrintableStringSubjectDN(boolean)
     */
    @Override
    public void setUsePrintableStringSubjectDN(boolean useprintablestring) {
        data.put(USEPRINTABLESTRINGSUBJECTDN, useprintablestring);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUseLdapDNOrder()
     */
    @Override
    public boolean getUseLdapDNOrder() {
        return (Boolean) data.get(USELDAPDNORDER);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUseLdapDNOrder(boolean)
     */
    @Override
    public void setUseLdapDNOrder(boolean useldapdnorder) {
        data.put(USELDAPDNORDER, useldapdnorder);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUseCrlDistributionPointOnCrl()
     */
    @Override
    public boolean getUseCrlDistributionPointOnCrl() {
        return (Boolean) data.get(USECRLDISTRIBUTIONPOINTONCRL);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUseCrlDistributionPointOnCrl(boolean)
     */
    @Override
    public void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
        data.put(USECRLDISTRIBUTIONPOINTONCRL, useCrlDistributionPointOnCrl);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getCrlDistributionPointOnCrlCritical()
     */
    @Override
    public boolean getCrlDistributionPointOnCrlCritical() {
        return (Boolean) data.get(CRLDISTRIBUTIONPOINTONCRLCRITICAL);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCrlDistributionPointOnCrlCritical(boolean)
     */
    @Override
    public void setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical) {
        data.put(CRLDISTRIBUTIONPOINTONCRLCRITICAL, crlDistributionPointOnCrlCritical);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getNameConstraintsPermitted()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<String> getNameConstraintsPermitted() {
        return (List<String>) data.get(NAMECONSTRAINTSPERMITTED);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setNameConstraintsPermitted(java.util.List)
     */
    @Override
    public void setNameConstraintsPermitted(List<String> encodedNames) {
        data.put(NAMECONSTRAINTSPERMITTED, encodedNames);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getNameConstraintsExcluded()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<String> getNameConstraintsExcluded() {
        return (List<String>) data.get(NAMECONSTRAINTSEXCLUDED);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setNameConstraintsExcluded(java.util.List)
     */
    @Override
    public void setNameConstraintsExcluded(List<String> encodedNames) {
        data.put(NAMECONSTRAINTSEXCLUDED, encodedNames);
    }


    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getCmpRaAuthSecret()
     */
    @Override
    public String getCmpRaAuthSecret() {
        // Default to empty value if it is not set. An empty value will be denied by CRMFMessageHandler
        return (String) getMapValueWithDefault(CMPRAAUTHSECRET, "");
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCmpRaAuthSecret(java.lang.String)
     */
    @Override
    public void setCmpRaAuthSecret(String cmpRaAuthSecret) {
        data.put(CMPRAAUTHSECRET, cmpRaAuthSecret);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getSerialNumberOctetSize()
     */
    @Override
    public Integer getSerialNumberOctetSize() {
        return (Integer)getMapValueWithDefault(SERIALNUMBEROCTETSIZE, CesecoreConfiguration.getSerialNumberOctetSizeForNewCa());
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCaSerialNumberOctetSize(int)
     */
    @Override
    public void setCaSerialNumberOctetSize(int serialNumberOctetSize) {
        data.put(SERIALNUMBEROCTETSIZE, serialNumberOctetSize);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#isDoPreProduceOcspResponses()
     */
    @Override
    public boolean isDoPreProduceOcspResponses() {
        if (data.containsKey(DO_PRE_PRODUCE_OCSP_RESPONSES)) {
            return (Boolean) data.get(DO_PRE_PRODUCE_OCSP_RESPONSES);
        }
        return false;
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setDoPreProduceOcspResponses(boolean)
     */
    @Override
    public void setDoPreProduceOcspResponses(boolean doPreProduceOcspResponses) {
        data.put(DO_PRE_PRODUCE_OCSP_RESPONSES, doPreProduceOcspResponses);
    }

    @Override
    public boolean isDoStoreOcspResponsesOnDemand() {
        if (data.containsKey(DO_STORE_OCSP_ON_DEMAND)) {
            return (Boolean) data.get(DO_STORE_OCSP_ON_DEMAND);
        }
        return false;
    }

    @Override
    public void setDoStoreOcspResponsesOnDemand(boolean doStoreOcspResponsesOnDemand) {
        data.put(DO_STORE_OCSP_ON_DEMAND, doStoreOcspResponsesOnDemand);
    }

    @Override
    public boolean isDoPreProduceOcspResponseUponIssuanceAndRevocation() {
        if (data.containsKey(DO_PRE_PRODUCE_INDIVIDUAL_OCSP_RESPONSES)) {
            return (Boolean) data.get(DO_PRE_PRODUCE_INDIVIDUAL_OCSP_RESPONSES);
        }
        return false;
     }

    @Override
    public void setDoPreProduceOcspResponseUponIssuanceAndRevocation(boolean doPreProduceIndividualOcspResponses) {
        data.put(DO_PRE_PRODUCE_INDIVIDUAL_OCSP_RESPONSES, doPreProduceIndividualOcspResponses);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Map<String, List<String>> getAlternateCertificateChains() {
        if (data.containsKey(ALTERNATECHAINS)) {
            return (Map<String, List<String>>) data.get(ALTERNATECHAINS);
        }
        return null;
    }

    @Override
    public void setAlternateCertificateChains(Map<String, List<String>> alternateCertificateChains) {
        data.put(ALTERNATECHAINS, alternateCertificateChains);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#updateCA(com.keyfactor.util.keys.token.CryptoToken, org.cesecore.certificates.ca.CAInfo, org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration)
     */
    @Override
    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {
        super.updateCA(cryptoToken, cainfo, cceConfig);
        X509CAInfo info = (X509CAInfo) cainfo;
        setPolicies(info.getPolicies());
        setAuthorityInformationAccess(info.getAuthorityInformationAccess());
        setCertificateAiaDefaultCaIssuerUri(info.getCertificateAiaDefaultCaIssuerUri());
        setUseAuthorityKeyIdentifier(info.getUseAuthorityKeyIdentifier());
        setAuthorityKeyIdentifierCritical(info.getAuthorityKeyIdentifierCritical());
        setUseCRLNumber(info.getUseCRLNumber());
        setCRLNumberCritical(info.getCRLNumberCritical());
        setDefaultCRLDistPoint(info.getDefaultCRLDistPoint());
        setDefaultCRLIssuer(info.getDefaultCRLIssuer());
        setCADefinedFreshestCRL(info.getCADefinedFreshestCRL());
        setDefaultOCSPServiceLocator(info.getDefaultOCSPServiceLocator());
        setUseUTF8PolicyText(info.getUseUTF8PolicyText());
        setUsePrintableStringSubjectDN(info.getUsePrintableStringSubjectDN());
        setUseLdapDNOrder(info.getUseLdapDnOrder());
        setUseCrlDistributionPointOnCrl(info.getUseCrlDistributionPointOnCrl());
        setCrlDistributionPointOnCrlCritical(info.getCrlDistributionPointOnCrlCritical());
        setCmpRaAuthSecret(info.getCmpRaAuthSecret());
        setNameConstraintsPermitted(info.getNameConstraintsPermitted());
        setNameConstraintsExcluded(info.getNameConstraintsExcluded());
        setExternalCdp(info.getExternalCdp());
        setSubjectAltName(info.getSubjectAltName());
        setCaSerialNumberOctetSize(info.getCaSerialNumberOctetSize());
        setDoPreProduceOcspResponses(info.isDoPreProduceOcspResponses());
        setDoStoreOcspResponsesOnDemand(info.isDoStoreOcspResponsesOnDemand());
        setDoPreProduceOcspResponseUponIssuanceAndRevocation(info.isDoPreProduceOcspResponseUponIssuanceAndRevocation());
        setUsePartitionedCrl(info.getUsePartitionedCrl());
        setCrlPartitions(info.getCrlPartitions());
        setMsCaCompatible(info.isMsCaCompatible());
        setSuspendedCrlPartitions(info.getSuspendedCrlPartitions());
        setRequestPreProcessor(info.getRequestPreProcessor());
        setAlternateCertificateChains(info.getAlternateCertificateChains());
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#updateUninitializedCA(org.cesecore.certificates.ca.CAInfo)
     */
    @Override
    public void updateUninitializedCA(CAInfo cainfo) {
        super.updateUninitializedCA(cainfo);
        X509CAInfo info = (X509CAInfo) cainfo;
        data.put(SUBJECTALTNAME, info.getSubjectAltName());
        data.put(POLICIES, info.getPolicies());
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#createPKCS7(om.keyfactor.util.keys.token.CryptoToken, java.security.cert.X509Certificate, boolean)
     */
    @Override
    public byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // First verify that we signed this certificate
        final X509Certificate cacert = (X509Certificate) getCACertificate();
        if (cert!=null) {
            try {
                final PublicKey verifyKey;
                if (cacert != null) {
                    verifyKey = cacert.getPublicKey();
                } else {
                    verifyKey = cryptoToken.getPublicKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                }
                cert.verify(verifyKey);
            } catch (CryptoTokenOfflineException e) {
                throw new SignRequestSignatureException("The cryptotoken was not available, could not create a PKCS7", e);
            } catch (InvalidKeyException e) {
                throw new SignRequestSignatureException("The specified certificate contains the wrong public key.", e);
            } catch (CertificateException e) {
                throw new SignRequestSignatureException("An encoding error was encountered.", e);
            } catch (NoSuchAlgorithmException e) {
                throw new SignRequestSignatureException("The certificate provided was signed with an invalid algorithm.", e);
            } catch (NoSuchProviderException e) {
                throw new SignRequestSignatureException("The crypto provider was not found for verification of the certificate.", e);
            } catch (SignatureException e) {
                throw new SignRequestSignatureException("Cannot verify certificate in createPKCS7(), did I sign this?", e);
            }
        }
        final List<X509Certificate> x509Chain = new ArrayList<>();
        if (cert!=null) {
            x509Chain.add(cert);
        }
        if (includeChain) {
            x509Chain.addAll(CertTools.convertCertificateChainToX509Chain(getCertificateChain()));
        }
        List<JcaX509CertificateHolder> certList;
        try {
            certList = CertTools.convertToX509CertificateHolder(x509Chain);
        } catch (CertificateEncodingException e) {
            throw new SignRequestSignatureException("Could not encode certificate", e);
        }
        try {
            CMSTypedData msg = new CMSProcessableByteArray(new byte[0]);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            final PrivateKey privateKey = cryptoToken.getPrivateKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            if (privateKey == null) {
                final String msg1 = "createPKCS7: Private key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            final PublicKey publicKey = cryptoToken.getPublicKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            if (publicKey == null) {
                final String msg1 = "createPKCS7: Public key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            // Find the signature algorithm from the public key, because it is more granular, i.e. can differnetiate between ML-DSA-44 and ML-DSA-65
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA256, publicKey.getAlgorithm());
            try {
                final ContentSigner contentSigner = new BufferingContentSigner(new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(cryptoToken.getSignProviderName()).build(privateKey), 20480);
                final JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                final JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                gen.addSignerInfoGenerator(builder.build(contentSigner, cacert));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            }
            gen.addCertificates(new CollectionStore<>(certList));
            CMSSignedData s = null;
            CAToken catoken = getCAToken();
            if (catoken != null && !(cryptoToken instanceof NullCryptoToken)) {
                log.debug("createPKCS7: Provider=" + cryptoToken.getSignProviderName() + " using algorithm "
                        + privateKey.getAlgorithm());
                s = gen.generate(msg, true);
            } else {
                String msg1 = "CA Token does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            return s.getEncoded();
        } catch (CryptoTokenOfflineException | CertificateEncodingException | CMSException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#createPKCS7Rollover(om.keyfactor.util.keys.token.CryptoToken)
     */
    @Override
    public byte[] createPKCS7Rollover(CryptoToken cryptoToken) throws SignRequestSignatureException {
        List<Certificate> nextChain = getRolloverCertificateChain();
        if (nextChain == null) {
            log.debug("CA does not have a rollover chain, returning empty PKCS#7");
            nextChain = Collections.emptyList();
        } else if (nextChain.isEmpty()) {
            log.warn("next chain exists but is empty");
        }

        ArrayList<X509CertificateHolder> certList = new ArrayList<>();
        try {
            for (Certificate certificate : nextChain) {
                certList.add(new JcaX509CertificateHolder((X509Certificate) certificate));
            }
        } catch (CertificateEncodingException e) {
            throw new SignRequestSignatureException("Could not encode certificate", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("createPKCS7Rollover: Creating a rollover chain with "+certList.size()+" certificates.");
        }
        try {
            CMSTypedData msg = new CMSProcessableByteArray(new byte[0]);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            // We always sign with the current key, even during rollover, so the new key can be linked to the old key. SCEP draft 23, "4.6.1.  Get Next CA Response Message Format"
            final PrivateKey privateKey = cryptoToken.getPrivateKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            if (privateKey == null) {
                final String msg1 = "createPKCS7Rollover: Private key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            final PublicKey publicKey = cryptoToken.getPublicKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            if (publicKey == null) {
                String msg1 = "createPKCS7: Public key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            // Find the signature algorithm from the public key, because it is more granular, i.e. can differnetiate between ML-DSA-44 and ML-DSA-65
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA256, publicKey.getAlgorithm());
            try {
                final ContentSigner contentSigner = new BufferingContentSigner(new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(cryptoToken.getSignProviderName()).build(privateKey), 20480);
                final JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                final JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                gen.addSignerInfoGenerator(builder.build(contentSigner, (X509Certificate) getCACertificate()));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
            gen.addCertificates(new CollectionStore<>(certList));
            CMSSignedData s = null;
            CAToken catoken = getCAToken();
            if (catoken != null && !(cryptoToken instanceof NullCryptoToken)) {
                log.debug("createPKCS7Rollover: Provider=" + cryptoToken.getSignProviderName() + " using algorithm "
                        + privateKey.getAlgorithm());
                // Don't encapsulate any content, i.e. the bytes in the message. This makes data section of the PKCS#7 message completely empty.
                // BER Sequence
                //   ObjectIdentifier(1.2.840.113549.1.7.1)
                // Instead of
                // BER Sequence
                //   ObjectIdentifier(1.2.840.113549.1.7.1)
                //   BER Tagged [0]
                //     BER Constructed Octet String[0]
                s = gen.generate(msg, false);
            } else {
                String msg1 = "CA Token does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            return s.getEncoded();
        } catch (CryptoTokenOfflineException | CMSException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode CMS data", e);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#createRequest(om.keyfactor.util.keys.token.CryptoToken, java.util.Collection, java.lang.String, java.security.cert.Certificate, int, org.cesecore.certificates.certificateprofile.CertificateProfile, org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration)
     */
    @Override
    public byte[] createRequest(final CryptoToken cryptoToken, final Collection<ASN1Encodable> attributes, final String signAlg, final Certificate cacert,
            final int signatureKeyPurpose, final CertificateProfile certificateProfile, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
                    throws CryptoTokenOfflineException, CertificateExtensionException {
        log.trace(">createRequest: " + signAlg + ", " + CertTools.getSubjectDN(cacert) + ", " + signatureKeyPurpose);
        ASN1Set attrset = new DERSet();
        if (attributes != null) {
            log.debug("Adding attributes in the request");
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (final ASN1Encodable o : attributes) {
                vec.add(o);
            }
            attrset = new DERSet(vec);
        }
        final X500NameStyle nameStyle;
        if (getUsePrintableStringSubjectDN()) {
            nameStyle = PrintableStringNameStyle.INSTANCE;
        } else {
            nameStyle = CeSecoreNameStyle.INSTANCE;
        }
        X500Name x509dn = DnComponents.stringToBcX500Name(getSubjectDN(), nameStyle, getUseLdapDNOrder());
        PKCS10CertificationRequest req;
        try {
            final CAToken catoken = getCAToken();
            final String alias = catoken.getAliasFromPurpose(signatureKeyPurpose);
            final KeyPair keyPair = new KeyPair(cryptoToken.getPublicKey(alias), cryptoToken.getPrivateKey(alias));
            req = CertTools.genPKCS10CertificationRequest(signAlg, x509dn, keyPair.getPublic(), attrset, keyPair.getPrivate(), cryptoToken.getSignProviderName());
            log.trace("<createRequest");
            return req.getEncoded();
        } catch (CryptoTokenOfflineException e) { // NOPMD, since we catch wide below
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#createAuthCertSignRequest(om.keyfactor.util.keys.token.CryptoToken, byte[])
     */
    @Override
    public byte[] createAuthCertSignRequest(CryptoToken cryptoToken, final byte[] request) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Creation of authenticated CSRs is not supported for X509 CAs.");
    }

    /**
     * @param cryptoToken the CAs crypto token for old and new signature keys
     * @param createLinkCertificate if a new link certificate should be created, if false any existing old link certificate will be removed
     * @param certProfile the certificate profile used to create the link certificate
     * @param cceConfig custom extension configuration for the link certificate (if configured to be used in certProfile)
     * @param caNameChange if set to false, regular X509 link certificate will be created. Otherwise, created link certificates
     * will be modified as explained in the ICAO 9303 7th edition part 12. In addition to regular X509 link certificate format
     * this link certificate will have:
     *       SubjectDN as CA's SubjectDN/IssuerDN after CA Name Change
     *       IssuerDN as CA's SubjectDN/IssuerDN before CA Name Change
     *       the Name Change Extension
     * @param oldCaCert to get expire date info from the old CA certificate to put in the link certificate
     */
    private void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile,
            final AvailableCustomCertificateExtensionsConfiguration cceConfig, boolean caNameChange, final Certificate oldCaCert) throws CryptoTokenOfflineException {
        byte[] ret = null;
        if (createLinkCertificate) {
            try {
                final CAToken catoken = getCAToken();
                // Check if the input was a CA certificate, which is the same CA as this. If all is true we should create a NewWithOld link-certificate
                final X509Certificate currentCaCert = (X509Certificate) getCACertificate();
                if (log.isDebugEnabled()) {
                    log.debug("We will create a link certificate.");
                }
                final X509CAInfo info = (X509CAInfo) getCAInfo();
                final EndEntityInformation cadata = new EndEntityInformation("nobody", info.getSubjectDN(), info.getSubjectDN().hashCode(), info.getSubjectAltName(), null,
                        0, new EndEntityType(EndEntityTypes.INVALID), 0, info.getCertificateProfileId(), null, null, 0, null);
                final PublicKey previousCaPublicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
                final PrivateKey previousCaPrivateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
                final String provider = cryptoToken.getSignProviderName();
                SigningKeyContainer caSigningPackage = new SigningKeyContainer(previousCaPublicKey, previousCaPrivateKey, provider);
                final Certificate retcert = generateCertificate(cadata, null, currentCaCert.getPublicKey(), null, -1, currentCaCert.getNotBefore(), ((X509Certificate) oldCaCert).getNotAfter(),
                        certProfile, null, caSigningPackage, null, cceConfig, /*createLinkCertificate=*/true, caNameChange);
                log.info(intres.getLocalizedMessage("cvc.info.createlinkcert", cadata.getDN(), ((X509Certificate)retcert).getIssuerDN().getName()));
                ret = retcert.getEncoded();
            } catch (CryptoTokenOfflineException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("Error when creating or removing link certificate.", e);
            }
        }
        updateLatestLinkCertificate(ret);
    }


    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#createOrRemoveLinkCertificateDuringCANameChange(om.keyfactor.util.keys.token.CryptoToken, boolean, org.cesecore.certificates.certificateprofile.CertificateProfile, org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration, java.security.cert.Certificate)
     */
    @Override
    public void createOrRemoveLinkCertificateDuringCANameChange(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile,
            final AvailableCustomCertificateExtensionsConfiguration cceConfig, final Certificate oldCaCert) throws CryptoTokenOfflineException {
        createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate, certProfile, cceConfig, /*caNameChange*/true, oldCaCert);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#createOrRemoveLinkCertificate(om.keyfactor.util.keys.token.CryptoToken, boolean, org.cesecore.certificates.certificateprofile.CertificateProfile, org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration, java.security.cert.Certificate)
     */
    @Override
    public void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile,
            final AvailableCustomCertificateExtensionsConfiguration cceConfig, final Certificate oldCaCert) throws CryptoTokenOfflineException {
        createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate, certProfile, cceConfig, /*caNameChange*/false, oldCaCert);
    }

    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, PublicKey publicKey, PublicKey alternativePublicKey,
            int keyusage, Date notBefore, String encodedValidity, CertificateProfile certProfile, String sequence,
            AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException {
        // Calculate the notAfter date
        if (notBefore == null) {
            notBefore = new Date();
        }
        final Date notAfter;
        if (StringUtils.isNotBlank(encodedValidity)) {
            notAfter = ValidityDate.getDate(encodedValidity, notBefore, getCAInfo().isExpirationInclusive());
        } else {
            notAfter = null;
        }
        return generateCertificate(cryptoToken, subject, null, publicKey, alternativePublicKey, keyusage, notBefore, notAfter, certProfile, null, sequence, null,
                cceConfig);
    }

    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken,  EndEntityInformation subject,
            RequestMessage request, PublicKey publicKey, int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile,
            Extensions extensions, String sequence, CertificateGenerationParams certGenParams,
            AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        return generateCertificate(cryptoToken, subject, request, publicKey, null, keyusage, notBefore, notAfter, certProfile, extensions, sequence, certGenParams, cceConfig);
    }

    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken,  EndEntityInformation subject,
            RequestMessage request, PublicKey publicKey, final PublicKey alternativePublicKey, int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile,
            Extensions extensions, String sequence, CertificateGenerationParams certGenParams,
            AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {

        // Before we start, check if the CA is off-line, we don't have to waste time
        // one the stuff below of we are off-line. The line below will throw CryptoTokenOfflineException of CA is offline
        final CAToken catoken = getCAToken();
        final int purpose = getUseNextCACert(request) ? CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT : CATokenConstants.CAKEYPURPOSE_CERTSIGN;
        final PublicKey caPublicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(purpose));
        final PrivateKey caPrivateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(purpose));
        final String provider = cryptoToken.getSignProviderName();
        final SigningKeyContainer caSigningPackage;

        if(StringUtils.isEmpty(catoken.getAlternativeSignatureAlgorithm())) {
            caSigningPackage = new SigningKeyContainer(caPublicKey, caPrivateKey, provider);
        } else {
            final int alternativeKeyPurpose = getUseNextCACert(request) ? CATokenConstants.CAKEYPUPROSE_ALTERNATIVE_CERTSIGN_NEXT : CATokenConstants.CAKEYPUPROSE_ALTERNATIVE_CERTSIGN;
            final PublicKey alternativeCaPublicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(alternativeKeyPurpose));
            final PrivateKey alternativeCaPrivateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(alternativeKeyPurpose));
            final String alternativeProvider = cryptoToken.getSignProviderName();
            caSigningPackage = new SigningKeyContainer(caPublicKey, caPrivateKey, provider, alternativeCaPublicKey, alternativeCaPrivateKey, alternativeProvider);
        }

        return generateCertificate(subject, request, publicKey, alternativePublicKey, keyusage, notBefore, notAfter, certProfile, extensions, caSigningPackage,
                certGenParams, cceConfig, /*linkCertificate=*/false, /*caNameChange=*/false);
    }


    /**
     * Sequence is ignored by X509CA. The ctParams argument will NOT be kept after the function call returns,
     * and is allowed to contain references to session beans.
     * @param providedRequestMessage provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
     * providedPublicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param providedPublicKey provided public key which will have precedence over public key from providedRequestMessage but not over subject.extendedInformation.certificateRequest
     * @param providedAlternativePublicKey alternative key, if the intention is to create a hybrid certificate
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of providedRequestMessage and providedPublicKey
     * Otherwise, providedRequestMessage will be used.
     * @param caSigningPackage a holder class containing the CA's public and private keys, and signing algorithm(s)
     *
     * @throws CAOfflineException if the CA wasn't active
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws IllegalValidityException if validity was invalid
     * @throws IllegalNameException if the name specified in the certificate request was invalid
     * @throws CertificateExtensionException if any of the certificate extensions were invalid
     * @throws OperatorCreationException if CA's private key contained an unknown algorithm or provider
     * @throws CertificateCreateException if an error occurred when trying to create a certificate.
     * @throws SignatureException if the CA's certificate's and request's certificate's and signature algorithms differ
     * @throws IllegalKeyException if selected public key (check providedRequestMessage, providedPublicKey, subject) is not allowed with certProfile
     */
    protected Certificate generateCertificate(final EndEntityInformation subject, final RequestMessage providedRequestMessage,
            final PublicKey providedPublicKey, final PublicKey providedAlternativePublicKey, final int keyusage, final Date notBefore,
            final Date notAfter, final CertificateProfile certProfile, final Extensions extensions, final SigningKeyContainer caSigningPackage,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig, boolean linkCertificate, boolean caNameChange)
            throws CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException, CertificateExtensionException,
             OperatorCreationException, CertificateCreateException, SignatureException, IllegalKeyException {

        // We must only allow signing to take place if the CA itself is on line, even if the token is on-line.
        // We have to allow expired as well though, so we can renew expired CAs
        if ((getStatus() != CAConstants.CA_ACTIVE) && (getStatus() != CAConstants.CA_EXPIRED)) {
            final String msg = intres.getLocalizedMessage("error.caoffline", getName(), getStatus());
            if (log.isDebugEnabled()) {
                log.debug(msg); // This is something we handle so no need to log with higher priority
            }
            throw new CAOfflineException(msg);
        }
        // Which public key and request shall we use?
        final ExtendedInformation ei = subject.getExtendedInformation();
        final RequestAndPublicKeySelector pkSelector = new RequestAndPublicKeySelector(providedRequestMessage, providedPublicKey, providedAlternativePublicKey, ei);
        final PublicKey publicKey = pkSelector.getPublicKey();
        final RequestMessage request = pkSelector.getRequestMessage();
        final PublicKey alternativePublicKey = pkSelector.getAlternativePublicKey();

        // ECA-11391 and "Forbid encryption usage for ECC keys" flag in Certificate Profile allow creating certificates
        // using the same Certificate Profile (relevant key usages) where for example both RSA and ECDSA key algorithms are selected in the profile.
        if (publicKey.getAlgorithm().equals(AlgorithmConstants.KEYALGORITHM_ECDSA) && certProfile.getKeyUsageForbidEncryptionUsageForECC()) {
            certProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
            certProfile.setKeyUsage(CertificateConstants.DATAENCIPHERMENT, false);
        }

        certProfile.verifyKey(publicKey);

        final String sigAlg;
        if (certProfile.getSignatureAlgorithm() == null) {
            sigAlg = getCAToken().getSignatureAlgorithm();
        } else {
            sigAlg = certProfile.getSignatureAlgorithm();
        }
        // Check that the signature algorithm is one of the allowed ones
        if (!StringTools.containsCaseInsensitive(AlgorithmConstants.AVAILABLE_SIGALGS, sigAlg)) {
            final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", sigAlg, ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
            throw new InvalidAlgorithmException(msg);
        }
        // Check if this is a root CA we are creating
        final boolean isRootCA = certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA;

        final boolean useNextCACert = getUseNextCACert(request);
        final X509Certificate cacert = (X509Certificate) (useNextCACert ? getRolloverCertificateChain().get(0) : getCACertificate());
        final Date now = new Date();
        final Date checkDate = useNextCACert && cacert.getNotBefore().after(now) ? cacert.getNotBefore() : now;
        // Check CA certificate PrivateKeyUsagePeriod if it exists (throws CAOfflineException if it exists and is not within this time)
        CertificateValidity.checkPrivateKeyUsagePeriod(cacert, checkDate);
        // Get certificate validity time notBefore and notAfter
        final CertificateValidity val = new CertificateValidity(subject, getCAInfo(), certProfile, notBefore, notAfter, cacert, isRootCA, linkCertificate);

        // Serialnumber is either random bits, where random generator is initialized by the serno generator.
        // Or a custom serial number defined in the end entity object
        final BigInteger serno;
        {

            if (certProfile.getAllowCertSerialNumberOverride()) {
                if (ei != null && ei.certificateSerialNumber()!=null) {
                    serno = ei.certificateSerialNumber();
                } else {
                    SernoGenerator instance = SernoGeneratorRandom.instance(getSerialNumberOctetSize());
                    serno = instance.getSerno();
                }
            } else {
                SernoGenerator instance = SernoGeneratorRandom.instance(getSerialNumberOctetSize());
                serno = instance.getSerno();
                if ((ei != null) && (ei.certificateSerialNumber() != null)) {
                    final String msg = intres.getLocalizedMessage("createcert.certprof_not_allowing_cert_sn_override_using_normal", ei.certificateSerialNumber().toString(16));
                    log.info(msg);
                }
            }
        }

        // Make DNs
        final X500NameStyle nameStyle;
        if (getUsePrintableStringSubjectDN()) {
            nameStyle = PrintableStringNameStyle.INSTANCE;
        } else {
            nameStyle = CeSecoreNameStyle.INSTANCE;
        }

        // Make sure no forbidden characters exist in the DN, see ECA-9984 for more info.
        String dn = StringTools.strip(subject.getCertificateDN());
        if (certProfile.getUseSubjectDNSubSet()) {
            dn = certProfile.createSubjectDNSubSet(dn);
        }
        if (certProfile.getUseCNPostfix()) {
            dn = CertTools.insertCNPostfix(dn, certProfile.getCNPostfix(), nameStyle);
        }

        // Will we use LDAP DN order (CN first) or X500 DN order (CN last) for the subject DN
        final boolean ldapdnorder;
        if ((!getUseLdapDNOrder()) || (!certProfile.getUseLdapDnOrder())) {
            ldapdnorder = false;
        } else {
            ldapdnorder = true;
        }
        // If we have a custom order defined in the certificate profile, take this. If this is null or empty it will be ignored
        String[] customDNOrder = null;
        if (certProfile.getUseCustomDnOrder()) {
            final ArrayList<String> order = certProfile.getCustomDnOrder();
            if (order != null && !order.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("Using Custom DN order: "+order);
                }
                customDNOrder = order.toArray(new String[0]);
            }
        }
        final boolean applyLdapToCustomOrder = certProfile.getUseCustomDnOrderWithLdap();

        final X500Name subjectDNName;
        if (certProfile.getAllowDNOverride() && (request != null) && (request.getRequestX500Name() != null)) {
            subjectDNName = request.getRequestX500Name();
            if (log.isDebugEnabled()) {
                log.debug("Using X509Name from request instead of user's registered.");
            }
        } else {
            if (certProfile.getAllowDNOverrideByEndEntityInformation() && ei!=null && ei.getRawSubjectDn()!=null) {
                final String stripped = StringTools.strip(ei.getRawSubjectDn());
                // Since support for multi-value RDNs in EJBCA 7.0.0, see ECA-3934, we don't automatically escape + signs anymore
                final String emptiesRemoved = DNFieldsUtil.removeAllEmpties(stripped);
                final X500Name subjectDNNameFromEei = DnComponents.stringToUnorderedX500Name(emptiesRemoved, CeSecoreNameStyle.INSTANCE);
                if (subjectDNNameFromEei.toString().length()>0) {
                    subjectDNName = subjectDNNameFromEei;
                    if (log.isDebugEnabled()) {
                        log.debug("Using X500Name from end entity information instead of user's registered subject DN fields.");
                        log.debug("ExtendedInformation.getRawSubjectDn(): " + LogRedactionUtils.getSubjectDnLogSafe(ei.getRawSubjectDn(), subject.getEndEntityProfileId()) + " will use: " + LogRedactionUtils.getSubjectDnLogSafe(CeSecoreNameStyle.INSTANCE.toString(subjectDNName), subject.getEndEntityProfileId()));
                    }
                } else {
                    subjectDNName = DnComponents.stringToBcX500Name(dn, nameStyle, ldapdnorder, customDNOrder, applyLdapToCustomOrder);
                }
            } else {
                subjectDNName = DnComponents.stringToBcX500Name(dn, nameStyle, ldapdnorder, customDNOrder, applyLdapToCustomOrder);
            }
        }
        // Make sure the DN does not contain dangerous characters
        if (!StringTools.hasStripChars(subjectDNName.toString()).isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("DN with illegal name: " + LogRedactionUtils.getSubjectDnLogSafe(subjectDNName.toString(), subject.getEndEntityProfileId()));
            }
            final String msg = intres.getLocalizedMessage("createcert.illegalname");
            throw new IllegalNameException(msg);
        }
        if (log.isDebugEnabled()) {
            log.debug("Using subjectDN: " + LogRedactionUtils.getSubjectDnLogSafe(subjectDNName.toString(), subject.getEndEntityProfileId()));
        }

        // We must take the issuer DN directly from the CA-certificate otherwise we risk re-ordering the DN
        // which many applications do not like.
        X500Name issuerDNName;
        if (isRootCA) {
            // This will be an initial root CA, since no CA-certificate exists
            // Or it is a root CA, since the cert is self signed. If it is a root CA we want to use the same encoding for subject and issuer,
            // it might have changed over the years.
            if (log.isDebugEnabled()) {
                log.debug("Using subject DN also as issuer DN, because it is a root CA");
            }
            if (linkCertificate && caNameChange){
                List<Certificate> renewedCertificateChain = getRenewedCertificateChain();
                if(renewedCertificateChain == null || renewedCertificateChain.isEmpty()){
                    //"Should not happen" error
                    log.error("CA name change is in process but renewed (old) certificates chain is empty");
                    throw new CertificateCreateException("CA name change is in process but renewed (old) certificates chain is empty");
                }
                issuerDNName = X500Name.getInstance(((X509Certificate)renewedCertificateChain.get(renewedCertificateChain.size()-1)).getSubjectX500Principal().getEncoded());
            } else{
                issuerDNName = subjectDNName;
            }
        } else {
            issuerDNName = X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded());
            if (log.isDebugEnabled()) {
                log.debug("Using issuer DN directly from the CA certificate: " + issuerDNName.toString());
            }
        }

        SubjectPublicKeyInfo pkinfo = verifyAndCorrectSubjectPublicKeyInfo(publicKey, providedRequestMessage);
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(issuerDNName, serno, val.getNotBefore(), val.getNotAfter(), subjectDNName, pkinfo);

        // Only created and used if Certificate Transparency is enabled
        final X509v3CertificateBuilder precertbuilder = certProfile.isUseCertificateTransparencyInCerts() ?
            new X509v3CertificateBuilder(issuerDNName, serno, val.getNotBefore(), val.getNotAfter(), subjectDNName, pkinfo) : null;


        // Check that the certificate fulfills name constraints, as a service to the CA, so they don't issue certificates that
        // later fail verification in clients (browsers)
        if (cacert != null) {
            GeneralNames altNameGNs = null;
            String altName = subject.getSubjectAltName();
            if(certProfile.getUseSubjectAltNameSubSet()){
                altName = certProfile.createSubjectAltNameSubSet(altName);
            }
            if (altName != null && altName.length() > 0) {
                altNameGNs = DnComponents.getGeneralNamesFromAltName(altName);
            }
            CABase.checkNameConstraints(cacert, subjectDNName, altNameGNs);
        }

        // If the subject has Name Constraints, then name constraints must be enabled in the certificate profile!
        if (ei != null) {
            final List<String> permittedNC = ei.getNameConstraintsPermitted();
            final List<String> excludedNC = ei.getNameConstraintsExcluded();
            if (!certProfile.getUseNameConstraints()
                    && ((permittedNC != null && !permittedNC.isEmpty()) || (excludedNC != null && !excludedNC.isEmpty()))) {
                throw new CertificateCreateException(
                        "Tried to issue a certificate with Name Constraints without having enabled NC in the certificate profile.");
            }
        }

        //
        // X509 Certificate Extensions
        //

        // Extensions we will add to the certificate later, when we have filled the structure with everything we want.
        final ExtensionsGenerator extgen = new ExtensionsGenerator();
        // First we check if there is general extension override, and add all extensions from
        // the request in that case
        if (certProfile.getAllowExtensionOverride() && extensions != null) {
            Set<String> overridableExtensionOIDs = certProfile.getOverridableExtensionOIDs();
            Set<String> nonOverridableExtensionOIDs = certProfile.getNonOverridableExtensionOIDs();
            if (!overridableExtensionOIDs.isEmpty() && !nonOverridableExtensionOIDs.isEmpty()) {
                // If user have set both of these lists, user may not know what he/she has done as it doesn't make sense
                // hence the result may not be the desired. To get attention to this, log an error
                log.error("Both overridableExtensionOIDs and nonOverridableExtensionOIDs are set in certificate profile which "
                        + "does not make sense. NonOverridableExtensionOIDs will take precedence, is this the desired behavior?");
            }
            ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
            for (ASN1ObjectIdentifier oid : oids) {
                // Start by excluding non overridable extensions
                // If there are no nonOverridableExtensionOIDs set, or if the set does not contain our OID, we allow it so move on
                if (!nonOverridableExtensionOIDs.contains(oid.getId())) { // nonOverridableExtensionOIDs can never by null
                    // Now check if we have specified which ones are allowed, if this is not set we allow everything
                    if (overridableExtensionOIDs.isEmpty() || overridableExtensionOIDs.contains(oid.getId())) {
                        final Extension ext = extensions.getExtension(oid);
                        if (log.isDebugEnabled()) {
                            log.debug("Overriding extension with OID: " + oid.getId());
                        }
                        try {
                            extgen.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                        } catch (IOException e) {
                            throw new IllegalStateException("IOException adding overridden extension with OID " + oid.getId() + ": ", e);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Extension is not among overridable extensions, not adding extension with OID " + oid.getId() + " from request.");
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Extension is among non-overridable extensions, not adding extension with OID " + oid.getId() + " from request.");
                    }
                }
            }
        }



        // Second we see if there is Key usage override
        if (certProfile.getAllowKeyUsageOverride() && (keyusage >= 0)) {
            if (log.isDebugEnabled()) {
                log.debug("AllowKeyUsageOverride=true. Using KeyUsage from parameter: " + keyusage);
            }
            if (certProfile.getUseKeyUsage() && (keyusage >= 0)) {
                final KeyUsage ku = new KeyUsage(keyusage);
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (!extgen.hasExtension(Extension.keyUsage)) {
                    try {
                        extgen.addExtension(Extension.keyUsage, certProfile.getKeyUsageCritical(), ku);
                    } catch (IOException e) {
                        throw new IllegalStateException("Caught unexpected IOException.", e);
                    }
                }
            }
        }

        // Third, check for standard Certificate Extensions that should be added.
        // Standard certificate extensions are defined in CertificateProfile and CertificateExtensionFactory
        // and implemented in package org.ejbca.core.model.certextensions.standard
        final CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance();
        for (String oid : certProfile.getUsedStandardCertificateExtensions()) {
            // We don't want to try to add standard extensions with the same oid if we have already added them
            // from the request, if AllowExtensionOverride is enabled.
            // Two extensions with the same oid is not allowed in the standard.
            if (!extgen.hasExtension(new ASN1ObjectIdentifier(oid))) {
                final CertificateExtension certExt = fact.getStandardCertificateExtension(oid, certProfile);
                if (certExt != null) {
                    final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caSigningPackage.getPrimaryPublicKey(), val);
                    if (value != null) {
                        extgen.addExtension(new ASN1ObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                    }
                }
            }
        }


        // Fourth, ICAO standard extensions. Only Name Change extension is used and added only for link certificates
        if (caNameChange) {
            try {
                extgen.addExtension(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover, false, DERNull.INSTANCE);
            } catch (IOException e) {
                /*IOException with DERNull.INSTANCE will never happen*/}
        }

        // Fifth, check for custom Certificate Extensions that should be added.
        // Custom certificate extensions is defined in AdminGUI -> SystemConfiguration -> Custom Certificate Extensions
        final List<Integer> wildcardExt = new ArrayList<>();
        Set<String> requestOids = new HashSet<>();
        if (subject.getExtendedInformation() != null) {
            requestOids = subject.getExtendedInformation().getExtensionDataOids();
        }
        for (int id : certProfile.getUsedCertificateExtensions()) {
            final CustomCertificateExtension certExt = cceConfig.getCustomCertificateExtension(id);
            if (certExt != null) {
                if (certExt.getOID().contains("*")) {
                    // Match wildcards later
                    wildcardExt.add(id);
                    continue;
                }
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (!extgen.hasExtension(new ASN1ObjectIdentifier(certExt.getOID()))) {
                    final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caSigningPackage.getPrimaryPublicKey(),
                            val);
                    if (value != null) {
                        extgen.addExtension(new ASN1ObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                        requestOids.remove(certExt.getOID());
                    }
                }
            }
        }
        // Match remaining extensions (wild cards)
        for (int id : wildcardExt) {
            final int remainingOidsToMatch = requestOids.size();
            final CustomCertificateExtension certExt = cceConfig.getCustomCertificateExtension(id);
            if (certExt != null) {
                for (final String oid : requestOids) {
                    // Match requested OID with wildcard in CCE configuration
                    if (oid.matches(CertTools.getOidWildcardPattern(certExt.getOID()))) {
                        if (!extgen.hasExtension(new ASN1ObjectIdentifier(oid))) {
                            final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey,
                                    caSigningPackage.getPrimaryPublicKey(), val, oid);
                            if (value != null) {
                                extgen.addExtension(new ASN1ObjectIdentifier(oid), certExt.isCriticalFlag(), value);
                                requestOids.remove(oid);
                                // Each wildcard CCE configuration may only be matched once.
                                break;
                            }
                        }
                    }
                }
                if ((remainingOidsToMatch == requestOids.size()) && certExt.isRequiredFlag()) {
                    // Required wildcard extension didn't match any OIDs in the request
                    throw new CertificateExtensionException(
                            intres.getLocalizedMessage("certext.basic.incorrectvalue", certExt.getId(), certExt.getOID())
                                    + "\nNo requested OID matched wildcard");
                }
            }
        }

        if (!requestOids.isEmpty()) {
            log.debug("No match found for requested OIDs: " + requestOids);
            // All requested OIDs must match a CCE configuration
            throw new CertificateCreateException(ErrorCode.CUSTOM_CERTIFICATE_EXTENSION_ERROR,
                    "Request contained custom certificate extensions which couldn't match any configuration");
        }

        // Finally add extensions to certificate generator
        Extensions exts = null;
        if(!extgen.isEmpty()) {
            exts = extgen.generate();
        }
        try {
            if (exts != null) {
                for (ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
                    final Extension extension = exts.getExtension(oid);
                    if (oid.equals(Extension.subjectAlternativeName)) { // subjectAlternativeName extension value needs special handling
                        ExtensionsGenerator sanExtGen = getSubjectAltNameExtensionForCert(extension, precertbuilder != null);
                        Extensions sanExts = sanExtGen.generate();
                        Extension eext = sanExts.getExtension(oid);
                        certbuilder.addExtension(oid, eext.isCritical(), eext.getParsedValue()); // adding subjetAlternativeName extension to certbuilder
                        if (precertbuilder != null) { // if a pre-certificate is to be published to a CTLog
                            eext = getSubjectAltNameExtensionForCTCert(extension).generate().getExtension(oid);
                            precertbuilder.addExtension(oid, eext.isCritical(), eext.getParsedValue()); // adding subjectAlternativeName extension to precertbuilder

                            eext = sanExts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
                            if (eext != null) {
                                certbuilder.addExtension(eext.getExtnId(), eext.isCritical(), eext.getParsedValue()); // adding nrOfRedactedLabels extension to certbuilder
                            }
                        }
                    } else { // if not a subjectAlternativeName extension, just add it to both certbuilder and precertbuilder
                        final boolean isCritical = extension.isCritical();
                        // We must get the raw octets here in order to be able to create invalid extensions that is not constructed from proper ASN.1
                        final byte[] value = extension.getExtnValue().getOctets();
                        certbuilder.addExtension(extension.getExtnId(), isCritical, value);
                        if (precertbuilder != null) {
                            precertbuilder.addExtension(extension.getExtnId(), isCritical, value);
                        }
                    }
                }
            }
            // Sign the certificate with a dummy key for presign validation.
            // Do not call this if no validation will occur in the PRESIGN_CERTIFICATE_VALIDATION, because this code takes some time, signing a certificate
            if (certGenParams != null && certGenParams.getAuthenticationToken() != null
                    && certGenParams.getCertificateValidationDomainService() != null && certGenParams.getCertificateValidationDomainService()
                            .willValidateInPhase(IssuancePhase.PRESIGN_CERTIFICATE_VALIDATION, this)) {
                try {
                    PrivateKey presignKey = CAConstants.getPreSignPrivateKey(sigAlg, caSigningPackage.getPrimaryPublicKey());
                    if (presignKey == null) {
                        throw new CertificateCreateException("No pre-sign key exist usable with algorithm " + sigAlg
                                + ", PRESIGN_CERTIFICATE_VALIDATION is not possible with this CA.");
                    }
                    ContentSigner presignSigner = new BufferingContentSigner(
                            new JcaContentSignerBuilder(sigAlg).setProvider(CryptoProviderTools.getProviderNameFromAlg(sigAlg)).build(presignKey),
                            X509CAImpl.SIGN_BUFFER_SIZE);
                    // Since this certificate may be written to file through the validator we want to ensure it's not a real certificate
                    // We do that by signing with a hard coded fake key, and set authorityKeyIdentifier accordingly, so the cert can
                    // not be verified even accidentally by someone
                    // Confirmed in CT mailing list that this approach is ok.
                    // https://groups.google.com/forum/#!topic/certificate-transparency/sDRcVBAgjCY
                    // - "Anyone can create a certificate with a given issuer and sign it with a key they create. So it cannot be misissuance just because a name was used."

                    // Get the old, real, authorityKeyIdentifier
                    if (exts != null) {
                        Extension ext = exts.getExtension(Extension.authorityKeyIdentifier);
                        if (ext != null) {
                            // Create a new authorityKeyIdentifier for the fake key
                            // SHA1 used here, but it's not security relevant here as this is the RFC5280 Key Identifier
                            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                            AuthorityKeyIdentifier aki = extensionUtils
                                    .createAuthorityKeyIdentifier(CAConstants.getPreSignPublicKey(sigAlg, caSigningPackage.getPrimaryPublicKey()));
                            certbuilder.replaceExtension(Extension.authorityKeyIdentifier, ext.isCritical(), aki.getEncoded());
                        }
                        X509CertificateHolder presignCertHolder = certbuilder.build(presignSigner);
                        X509Certificate presignCert = CertTools.getCertfromByteArray(presignCertHolder.getEncoded(), X509Certificate.class);
                        certGenParams.getCertificateValidationDomainService().validateCertificate(certGenParams.getAuthenticationToken(),
                                IssuancePhase.PRESIGN_CERTIFICATE_VALIDATION, this, subject, presignCert);
                        // Restore the original, real, authorityKeyIdentifier
                        if (ext != null) {
                            certbuilder.replaceExtension(Extension.authorityKeyIdentifier, ext.isCritical(), ext.getExtnValue().getOctets());
                        }
                    }
                } catch (IOException e) {
                    throw new CertificateCreateException("Cannot create presign certificate: ", e);
                } catch (ValidationException e) {
                    throw new CertificateCreateException(ErrorCode.INVALID_CERTIFICATE, e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    if (certGenParams == null) {
                        log.debug("No PRESIGN_CERTIFICATE_VALIDATION: certGenParams is null");
                    } else {
                        log.debug("No PRESIGN_CERTIFICATE_VALIDATION: "
                                + (certGenParams.getAuthenticationToken() != null ? "" : "certGenParams.authenticationToken is null") + ":"
                                + (certGenParams.getCertificateValidationDomainService() != null ? ""
                                        : "certGenParams.getCertificateValidationDomainService is null"));
                    }
                }
            }
        } catch (IOException | CertificateParsingException e) {
            throw new CertificateCreateException("IOException was caught when parsing extensions", e);
        }

        try {
            // Add Certificate Transparency extension. It needs to access the certbuilder and
            // the CA key so it has to be processed here inside X509CA.
             if (ct != null && certProfile.isUseCertificateTransparencyInCerts() && certGenParams != null) {

                // Create CT pre-certificate
                // A critical extension is added to prevent this cert from being used
                ct.addPreCertPoison(precertbuilder);

                // Sign CT pre-certificate
                /*
                 *  TODO: It would be nice to be able to do the SCT fetching on a separate proxy node (ECA-4732).
                 *  The proxy node would then use a special CT pre-certificate signing certificate.
                 *  It should have CA=true and ExtKeyUsage=PRECERTIFICATE_SIGNING_OID
                 *  and should not have any other key usages (see RFC 6962, section 3.1)
                 */
                final String prov;
                if (BouncyCastleProvider.PROVIDER_NAME.equals(caSigningPackage.getPrimaryProvider())) {
                    // Ability to use the PQC provider
                    prov = CryptoProviderTools.getProviderNameFromAlg(sigAlg);
                } else {
                    prov = caSigningPackage.getPrimaryProvider();
                }
                final ContentSigner signer = new BufferingContentSigner(
                        new JcaContentSignerBuilder(sigAlg).setProvider(prov).build(caSigningPackage.getPrimaryPrivateKey()), X509CAImpl.SIGN_BUFFER_SIZE);

                final X509CertificateHolder certHolder;
                if (caSigningPackage.getAlternativePrivateKey() == null) {
                    // TODO: with the new BC methods remove- and replaceExtension we can get rid of the precertbuilder and only use one builder to save some time and space
                    certHolder = precertbuilder.build(signer);
                } else {

                    final String alternativeSigningAlgorithm;
                    if (certProfile.getAlternativeSignatureAlgorithm() == null) {
                        alternativeSigningAlgorithm = getCAToken().getAlternativeSignatureAlgorithm();
                    } else {
                        alternativeSigningAlgorithm = certProfile.getAlternativeSignatureAlgorithm();
                    }

                    final String altProv;
                    if (BouncyCastleProvider.PROVIDER_NAME.equals(caSigningPackage.getAlternativeProvider())) {
                        altProv = CryptoProviderTools.getProviderNameFromAlg(alternativeSigningAlgorithm);
                    } else {
                        altProv = caSigningPackage.getAlternativeProvider();
                    }
                    ContentSigner alternativeSigner = new BufferingContentSigner(new JcaContentSignerBuilder(alternativeSigningAlgorithm)
                            .setProvider(altProv).build(caSigningPackage.getAlternativePrivateKey()), X509CAImpl.SIGN_BUFFER_SIZE);

                    certHolder = precertbuilder.build(signer, false, alternativeSigner);
                }

                final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
                // ECA-6051 Re-Factored with Domain Service Layer.
                if (certGenParams.getAuthenticationToken() != null && certGenParams.getCertificateValidationDomainService() != null) {
                    try {
                        certGenParams.getCertificateValidationDomainService().validateCertificate(certGenParams.getAuthenticationToken(), IssuancePhase.PRE_CERTIFICATE_VALIDATION, this, subject, cert);
                    } catch (ValidationException e) {
                        throw new CertificateCreateException(ErrorCode.INVALID_CERTIFICATE, e);
                    }
                }

                if (certGenParams.getCTSubmissionConfigParams() == null) {
                    log.debug("Not logging to CT. CT submission configuration parameters was null.");
                } else if (MapUtils.isEmpty(certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs())) {
                    log.debug("Not logging to CT. There are no CT logs configured in System Configuration.");
                } else if (certGenParams.getCTAuditLogCallback() == null) {
                    log.debug("Not logging to CT. No CT audit logging callback was passed to X509CA.");
                } else if (certGenParams.getSctDataCallback() == null) {
                    log.debug("Not logging to CT. No sctData persistance callback was passed.");
                } else {
                   // Commit certificate information in case of a rollback, power outage, or similar. This will be picked up by an IncompleteIssuanceServiceWorker (if enabled)
                   final int crlPartitionIndex = getCAInfo().determineCrlPartitionIndex(cert);
                   certGenParams.addToIncompleteIssuanceJournal(new IncompletelyIssuedCertificateInfo(getCAId(), serno, new Date(), subject, cert, cacert, crlPartitionIndex));
                   // Get certificate chain
                   final List<Certificate> chain = new ArrayList<>();
                   chain.add(cert);
                   chain.addAll(getCertificateChain());
                   // Submit to logs and get signed timestamps
                   byte[] sctlist = null;
                   try {
                       sctlist = ct.fetchSCTList(chain, certProfile, certGenParams.getCTSubmissionConfigParams(), certGenParams.getSctDataCallback());
                   } catch (CTLogException e) {
                       e.setPreCertificate(EJBTools.wrap(cert));
                       throw e;
                   } finally {
                       // Notify that pre-cert has been successfully or unsuccessfully submitted so it can be audit logged.
                       certGenParams.getCTAuditLogCallback().logPreCertSubmission(this, subject, cert, sctlist != null);
                   }
                   if (sctlist != null) { // can be null if the CTLog has been deleted from the configuration
                       ASN1ObjectIdentifier sctOid = new ASN1ObjectIdentifier(CertificateTransparency.SCTLIST_OID);
                       certbuilder.addExtension(sctOid, false, new DEROctetString(sctlist));
                   }
                }
            } else {
                if (log.isDebugEnabled()) {
                    String cause = "";
                    if (ct == null) {
                        cause += "CT is not available in this version of EJBCA.";
                    } else {
                        if (!certProfile.isUseCertificateTransparencyInCerts()) {
                            cause += "CT is not enabled in the certificate profile. ";
                        }
                        if (certGenParams == null) {
                            cause += "Certificate generation parameters was null.";
                        }
                    }
                    log.debug("Not logging to CT. "+cause);
                }
            }
        } catch (CertificateException e) {
            throw new CertificateCreateException("Could not process CA's private key when parsing Certificate Transparency extension.", e);
        } catch (IOException e) {
            throw new CertificateCreateException("IOException was caught when parsing Certificate Transparency extension.", e);
        } catch (CTLogException e) {
            throw new CertificateCreateException("An exception occurred because too many CT servers were down to satisfy the certificate profile.", e);
        }

        //Add alternative ("hybrid") signature to certificate if defined
        try {
            if(alternativePublicKey != null) {
                certbuilder.addExtension(Extension.subjectAltPublicKeyInfo, false, SubjectAltPublicKeyInfo.getInstance(alternativePublicKey.getEncoded()));
            }
        } catch (CertIOException e) {
            throw new CertificateCreateException("Could not as alternative key extension to certificate builder.", e);
        }

        //
        // End of extensions
        //

        if (log.isTraceEnabled()) {
            log.trace(">certgen.generate");
        }
        final String prov;
        if (BouncyCastleProvider.PROVIDER_NAME.equals(caSigningPackage.getPrimaryProvider())) {
            prov = CryptoProviderTools.getProviderNameFromAlg(sigAlg);
        } else {
            prov = caSigningPackage.getPrimaryProvider();
        }
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(prov).build(caSigningPackage.getPrimaryPrivateKey()), X509CAImpl.SIGN_BUFFER_SIZE);
        final X509CertificateHolder certHolder;
        if (caSigningPackage.getAlternativePrivateKey() == null) {
            certHolder = certbuilder.build(signer);
        } else {
            final String alternativeSigningAlgorithm;
            if (certProfile.getAlternativeSignatureAlgorithm() == null) {
                alternativeSigningAlgorithm = getCAToken().getAlternativeSignatureAlgorithm();
            } else {
                alternativeSigningAlgorithm = certProfile.getAlternativeSignatureAlgorithm();
            }

            final String altProv;
            if (BouncyCastleProvider.PROVIDER_NAME.equals(caSigningPackage.getAlternativeProvider())) {
                altProv = CryptoProviderTools.getProviderNameFromAlg(alternativeSigningAlgorithm);
            } else {
                altProv = caSigningPackage.getAlternativeProvider();
            }

            ContentSigner alternativeSigner = new BufferingContentSigner(
                    new JcaContentSignerBuilder(alternativeSigningAlgorithm).setProvider(altProv).build(caSigningPackage.getAlternativePrivateKey()),
                    X509CAImpl.SIGN_BUFFER_SIZE);
            certHolder = certbuilder.build(signer, false, alternativeSigner);
        }
        X509Certificate cert;
        try {
            cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException caught when parsing certificate holder.", e);
        } catch (CertificateException e) {
            throw new CertificateCreateException("Could not create certificate from CA's private key,", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<certgen.generate");
        }

        // Verify using the CA certificate before returning
        // If we can not verify the issued certificate using the CA certificate we don't want to issue this cert
        // because something is wrong...
        final PublicKey verifyKey;
        // We must use the configured public key if this is a rootCA, because then we can renew our own certificate, after changing
        // the keys. In this case the _new_ key will not match the current CA certificate.
        if ((cacert != null) && (!isRootCA) && (!linkCertificate)) {
            verifyKey = cacert.getPublicKey();
        } else {
            verifyKey = caSigningPackage.getPrimaryPublicKey();
        }
        try {
            cert.verify(verifyKey);
        } catch (SignatureException e) {
            final String msg = "Public key in the CA certificate does not match the configured certSignKey, is the CA in renewal process? : " + e.getMessage();
            log.warn(msg);
            throw new CertificateCreateException(msg, e);
        } catch (InvalidKeyException e) {
            throw new CertificateCreateException("CA's public key was invalid,", e);
        } catch (NoSuchAlgorithmException | CertificateException e) {
           throw new CertificateCreateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider was unknown", e);
        }

        // Verify any Signed Certificate Timestamps (SCTs) in the certificate before returning. If one of the (embedded) SCTs does
        // not verify over the final certificate, it won't validate in the browser and we don't want to issue such certificates.
        if (ct != null) {
            Collection<CTLogInfo> ctLogs =
                    (certGenParams == null || certGenParams.getCTSubmissionConfigParams() == null || certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs() == null)
                    ? null
                    : certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs().values();
            ct.allSctsAreValidOrThrow(cert, getCertificateChain(), ctLogs);
        }

        //Sub CA certificates check: Check AKI against parent CA SKI and IssuerDN against parent CA SubjectDN
        if(!isRootCA && !linkCertificate){
            final byte[] aki = CertTools.getAuthorityKeyId(cert);
            final byte[] ski = CertTools.getSubjectKeyId(cacert);
            if ((aki != null) && (ski != null)) {
                final boolean eq = Arrays.equals(aki, ski);
                if (!eq) {
                    final String akistr = new String(Hex.encode(aki));
                    final String skistr = new String(Hex.encode(ski));
                    final String msg = intres.getLocalizedMessage("createcert.errorpathverifykeyid", akistr, skistr);
                    log.error(msg);
                    throw new CertificateCreateException(msg);
                }
            }
            final Principal issuerDN = cert.getIssuerX500Principal();
            final Principal caSubjectDN = cacert.getSubjectX500Principal();
            if ((issuerDN != null) && (caSubjectDN != null)) {
                final boolean eq = issuerDN.equals(caSubjectDN);
                if (!eq) {
                    final String msg = intres.getLocalizedMessage("createcert.errorpathverifydn", issuerDN.getName(), caSubjectDN.getName());
                    log.error(msg);
                    throw new CertificateCreateException(msg);
                }
            }
        }

        // Before returning from this method, we will set the private key and provider in the request message, in case the response  message needs to be signed
        if (request != null) {
            request.setResponseKeyInfo(caSigningPackage.getPrimaryPrivateKey(), caSigningPackage.getPrimaryProvider());
        }
        if (log.isDebugEnabled()) {
            log.debug("X509CA: generated certificate, CA " + this.getCAId() + " for DN: " + LogRedactionUtils.getSubjectDnLogSafe(subject.getCertificateDN(), subject.getEndEntityProfileId()) );
        }
        return cert;
    }

    /**
     * Check if we have AlgorithmIdentifier parameters for RSA keys. According to RFC 3279 it must be DERNull, and not missing
     * The params are not used but must be ASN.1 encoded correctly in order to comply with RFC5280/RFC3279.
     * Some client software has been known to generate CSRs where the parameters are missing (which is not invalid ASN.1 encoding, but violates RFCs).
     *        SubjectPublicKeyInfo ::= SEQUENCE {
     *          algorithm AlgorithmIdentifier,
     *          subjectPublicKey BIT STRING }
     *
     *        AlgorithmIdentifier ::= SEQUENCE {
     *          algorithm OBJECT IDENTIFIER,
     *          parameters ANY DEFINED BY algorithm OPTIONAL }
     *
     * RFC3279 section 2.3.1 (null is not ok):
     * The rsaEncryption OID is intended to be used in the algorithm field
     * of a value of type AlgorithmIdentifier.  The parameters field MUST
     * have ASN.1 type NULL for this algorithm identifier.
     *
     * RFC3279 section 2.3.2 (null is ok):
     * The id-dsa algorithm syntax includes optional domain parameters.
     * These parameters are commonly referred to as p, q, and g.  When
     * omitted, the parameters component MUST be omitted entirely.  That is,
     * the AlgorithmIdentifier MUST be a SEQUENCE of one component: the
     * OBJECT IDENTIFIER id-dsa.
     *
     * RFC3279 section 2.3.5 (null is not ok):
     * EcpkParameters ::= CHOICE {
     *    ecParameters  ECParameters,
     *    namedCurve    OBJECT IDENTIFIER,
     *    implicitlyCA  NULL }
     * When the parameters are inherited, the parameters field SHALL contain
     * implictlyCA, which is the ASN.1 value NULL.
     *
     * EC Point encoding can be either non-compressed, the normal case (MUST in RFC3279) or compressed (MAY in RFC3279)
     *
     * @param publicKey to verify that it has the proper ÁlgorithmIdentifier.parameters
     * @param providedRequestMessage if the public key comes from a CSR (P10, CRMF, etc) if can give information how to encode the public key in the certificate, i.e. compressed EC points
     * @return SubjectPublicKeyInfo that can be put in a certificate
     * @throws IllegalKeyException if the publicKey is so invalid that it can not be safely fixed, issuance must be aborted
     */
    private SubjectPublicKeyInfo verifyAndCorrectSubjectPublicKeyInfo(final PublicKey publicKey, final RequestMessage providedRequestMessage) throws IllegalKeyException {
        SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final AlgorithmIdentifier keyAlgId = pkinfo.getAlgorithm();
        if (keyAlgId == null) {
            throw new IllegalKeyException("Public key must have an AlgorithmIdentifier, but it is missing. The public key is invalid.");
        } else if (keyAlgId.getAlgorithm() == null) {
            throw new IllegalKeyException("Public key must have an AlgorithmIdentifier.algorithm OID, but it is missing. The public key is invalid.");
        }
        if (keyAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption) && (keyAlgId.getParameters() == null || !DERNull.INSTANCE.equals(keyAlgId.getParameters()))) {
            // parameters can not be null, and MUST be DERNull
            if (log.isDebugEnabled()) {
                log.debug("Public key is an RSA key, but algorithmID parameters are null or not DERNull, where it should be DERNull according to RFC3279, modifying parameters to DERNull");
                if (keyAlgId.getParameters() != null) {
                    final String dump = ASN1Dump.dumpAsString(keyAlgId.getParameters());
                    log.debug("Invalid parameters (not null): " + dump);
                }
            }
            final AlgorithmIdentifier newAlgId = new AlgorithmIdentifier(keyAlgId.getAlgorithm(), DERNull.INSTANCE);
            try {
                pkinfo = new SubjectPublicKeyInfo(newAlgId, pkinfo.parsePublicKey());
            } catch (IOException e) {
                throw new IllegalKeyException("RSA public key with invalid AlgorithmIdentifier parameters detected, and we are unable to modify it: ", e);
            }
        } else if (keyAlgId.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            if (keyAlgId.getParameters() == null) {
                throw new IllegalKeyException("EC public key without AlgorithmIdentifier parameters, invalid public key.");
            }
            // See if the public key is encoded with compressed point encoding, in that case we should return with the same encoding
            if (providedRequestMessage != null && providedRequestMessage.getRequestSubjectPublicKeyInfo() != null) {
                final byte[] encoding = providedRequestMessage.getRequestSubjectPublicKeyInfo().getPublicKeyData().getBytes();
                // the magic numbers for first bytes are 0x00 (infinity) 0x02 (compressed) 0x03 (compressed, negate Y), 0x04 (uncompressed).
                // You'll never see 0.
                // In CMP you can request server generated keys by a SubjectPublicKeyInfo with only an AlgorithmIdentifier and empty publicKey BIT STRING
                if ((encoding != null && encoding.length > 0) && (encoding[0] == 2 || encoding[0] == 3)) {
                    if (!(publicKey instanceof BCECPublicKey)) {
                        log.warn("CSR has compressed EC point format, but can not set COMPRESSED as encoding because publicKey is not BCECPublicKey: " + publicKey.getClass().getName());
                    } else {
                        log.debug("CSR has compressed EC point format, setting COMPRESSED as certificate SubjectPublicKeyInfo encoding");
                        ((BCECPublicKey)publicKey).setPointFormat("COMPRESSED");
                        pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
                    }
                }
            }
        }
        return pkinfo;
    }


    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber,
            Certificate partitionCaCert) throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException,
            SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        return generateCRL(cryptoToken, crlPartitionIndex, certs, getCRLPeriod(), crlnumber, false, 0, partitionCaCert, new Date());
    }

    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber,
            Certificate partitionCaCert, final Date validFrom) throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException,
            SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        return generateCRL(cryptoToken, crlPartitionIndex, certs, getCRLPeriod(), crlnumber, false, 0, partitionCaCert, validFrom);
    }


    @Override
    public X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber,
            int basecrlnumber, Certificate latestCaCertForParition) throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException,
            SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        return generateCRL(cryptoToken, crlPartitionIndex, certs, getDeltaCRLPeriod(), crlnumber, true, basecrlnumber, latestCaCertForParition,
                new Date());
    }

    @Override
    public ExtensionsGenerator getSubjectAltNameExtensionForCert(Extension subAltNameExt, boolean publishToCT) throws IOException {
        GeneralNames names = DnComponents.getGeneralNamesFromExtension(subAltNameExt);
        GeneralName[] gns = names !=null ? names.getNames() : new GeneralName[0];
        boolean sanEdited = false;
        ASN1EncodableVector nrOfRecactedLables = new ASN1EncodableVector();
        for (int j = 0; j<gns.length; j++) {
            GeneralName generalName = gns[j];
            // Look for DNS name
            if (generalName.getTagNo() == 2) {
                final String str = DnComponents.getGeneralNameString(2, generalName.getName());
                if(StringUtils.contains(str, "(") && StringUtils.contains(str, ")") ) { // if it contains parts that should be redacted
                    // Remove the parentheses from the SubjectAltName that will end up on the certificate
                    String certBuilderDNSValue = StringUtils.remove(str, "dNSName=");
                    certBuilderDNSValue = StringUtils.remove(certBuilderDNSValue, '(');
                    certBuilderDNSValue = StringUtils.remove(certBuilderDNSValue, ')');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(2, new DERIA5String(certBuilderDNSValue));
                    sanEdited = true;
                    if (publishToCT) {
                        String redactedLable = StringUtils.substring(str, StringUtils.indexOf(str, "("), StringUtils.lastIndexOf(str, ")")+1); // tex. (top.secret).domain.se => redactedLable = (top.secret) aka. including the parentheses
                        nrOfRecactedLables.add(new ASN1Integer(StringUtils.countMatches(redactedLable, ".")+1));
                    }
                } else {
                    nrOfRecactedLables.add(new ASN1Integer(0));
                }
            }
            // Look for rfc822Name
            if(generalName.getTagNo() == 1) {
                final String str = DnComponents.getGeneralNameString(1, generalName.getName());
                if(StringUtils.contains(str, "\\+") ) { // if it contains a '+' character that should be unescaped
                    // Remove '\' from the email that will end up on the certificate
                    String certBuilderEmailValue = StringUtils.remove(str, "rfc822name=");
                    certBuilderEmailValue = StringUtils.remove(certBuilderEmailValue, '\\');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(1, new DERIA5String(certBuilderEmailValue));
                }
            }
        }
        ExtensionsGenerator gen = new ExtensionsGenerator();
        // Use the GeneralName from original altName in order to not re-encode anything
        gen.addExtension(Extension.subjectAlternativeName, subAltNameExt.isCritical(), new GeneralNames(gns));
        // If there actually are redacted parts, add the extension containing the number of redacted labels to the certificate
        if(publishToCT && sanEdited) {
            ASN1Encodable seq = new DERSequence(nrOfRecactedLables);
            gen.addExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains), false, seq);
        }

        return gen;
    }

    @Override
    public ExtensionsGenerator getSubjectAltNameExtensionForCTCert(Extension subAltNameExt) throws IOException {
        Pattern parenthesesRegex = Pattern.compile("\\(.*\\)"); // greedy match, so against "(a).(b).example.com" it will match "(a).(b)", like the old code did
        GeneralNames names = DnComponents.getGeneralNamesFromExtension(subAltNameExt);
        GeneralName[] gns = names != null ? names.getNames() : new GeneralName[0];
        for (int j = 0; j<gns.length; j++) {
            GeneralName generalName = gns[j];
            // Look for DNS name
            if (generalName.getTagNo() == 2) {
                final String value = ASN1IA5String.getInstance(generalName.getName()).getString();
                final Matcher matcher = parenthesesRegex.matcher(value);
                if (matcher.find()) {
                    final String newValue = matcher.replaceAll("(PRIVATE)");
                    gns[j] = new GeneralName(2, new DERIA5String(newValue));
                }
            }
            if(generalName.getTagNo() == 1) {
                final String str = DnComponents.getGeneralNameString(1, generalName.getName());
                if(StringUtils.contains(str, "\\+") ) { // if it contains a '+' character that should be unescaped
                    // Remove '\' from the email that will end up on the certificate
                    String certBuilderEmailValue = StringUtils.remove(str, "rfc822name=");
                    certBuilderEmailValue = StringUtils.remove(certBuilderEmailValue, '\\');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(1, new DERIA5String(certBuilderEmailValue));
                }
            }
        }

        ExtensionsGenerator gen = new ExtensionsGenerator();
        gen.addExtension(Extension.subjectAlternativeName, subAltNameExt.isCritical(), new GeneralNames(gns));
        return gen;
    }

    /**
     * Generate a CRL or a deltaCRL
     *
     * @param cryptoToken the cryptoToken with keys used to sign the CRL
     * @param certs list of revoked certificates
     * @param crlPeriod the validity period of the generated CRL, the CRLs nextUpdate will be set to (currentTimeMillis + crlPeriod)
     * @param crlnumber CRLNumber for this CRL
     * @param isDeltaCRL true if we should generate a DeltaCRL
     * @param basecrlnumber caseCRLNumber for a delta CRL, use 0 for full CRLs
     * @param partitionCaCert CA certificate to verify CRL against (mainly used for MS compatible CAs)
     * @param validFrom When this CRL is valid from
     * @return X509CRLHolder with the generated CRL
     * @throws CryptoTokenOfflineException
     * @throws IOException
     * @throws SignatureException
     */
    private X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, long crlPeriod, int crlnumber,
            boolean isDeltaCRL, int basecrlnumber, Certificate partitionCaCert, final Date validFrom) throws CryptoTokenOfflineException, IOException, SignatureException {
        final String sigAlg = getCAInfo().getCAToken().getSignatureAlgorithm();

        if (log.isDebugEnabled()) {
            log.debug("generateCRL(crlPartitionIndex=" + crlPartitionIndex + ", certs.size=" + certs.size() + ", crlPeriod=" + crlPeriod + ", crlNumber=" + crlnumber + ", isDeltaCRL=" + isDeltaCRL + ", baseCRLNumber=" + basecrlnumber);
        }


        // Make DNs
        X509Certificate cacert = (X509Certificate) getCACertificate();
        final X500Name issuer;

        if (isMsCaCompatible() && partitionCaCert != null) {
            cacert = (X509Certificate) partitionCaCert;
        }

        if (cacert == null) {
            // This is an initial root CA, since no CA-certificate exists
            // (I don't think we can ever get here!!!)
            final X500NameStyle nameStyle;
            if (getUsePrintableStringSubjectDN()) {
                nameStyle = PrintableStringNameStyle.INSTANCE;
            } else {
                nameStyle = CeSecoreNameStyle.INSTANCE;
            }
            issuer = DnComponents.stringToBcX500Name(getSubjectDN(), nameStyle, getUseLdapDNOrder());
        } else {
            issuer = X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded());
        }
        final Date thisUpdate = (validFrom != null ? validFrom : new Date());
        final Date nextUpdate = new Date();
        nextUpdate.setTime( thisUpdate.getTime() );
        // Set standard nextUpdate time
        long nextUpdateTime = nextUpdate.getTime() + crlPeriod - ValidityDate.NOT_AFTER_INCLUSIVE_OFFSET;
        nextUpdate.setTime(nextUpdateTime);
        // Check if the time is too large, then set time to "max/final" time according to RFC5280 section 4.1.2.5, 99991231235959Z
        TimeZone tz = TimeZone.getTimeZone("GMT");
        Calendar cal = Calendar.getInstance(tz);
        cal.set(9999, 11, 31, 23, 59, 59); // 99991231235959Z
        if (nextUpdate.getTime() >= cal.getTimeInMillis()) {
            nextUpdate.setTime(cal.getTimeInMillis());
            if (log.isDebugEnabled()) {
                log.debug("nextUpdate is larger than 9999-12-31:23.59.59 GMT, limiting value as specified in RFC5280 4.1.2.5: " + ValidityDate.formatAsUTC(nextUpdate));
            }
        }

        final X509v2CRLBuilder crlgen = new X509v2CRLBuilder(issuer, thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        if (certs != null) {
            if (log.isDebugEnabled()) {
                log.debug("Adding "+certs.size()+" revoked certificates to CRL. Free memory="+Runtime.getRuntime().freeMemory());
            }
            for (final RevokedCertInfo certinfo : certs) {
                if (certinfo.getInvalidityDate() != null) {
                    crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason(), certinfo.getInvalidityDate());
                } else {
                    crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason());
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Finished adding "+certs.size()+" revoked certificates to CRL. Free memory="+Runtime.getRuntime().freeMemory());
            }
        }


        // Authority key identifier
        if (getUseAuthorityKeyIdentifier()) {
            byte[] caSkid = (cacert != null ? CertTools.getSubjectKeyId(cacert) : null);
            if (caSkid != null) {
                // Use subject key id from CA certificate
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(caSkid);
                crlgen.addExtension(Extension.authorityKeyIdentifier, getAuthorityKeyIdentifierCritical(), aki);
            } else {
                // SHA1 used here, but it's not security relevant here as this is the RFC5280 Key Identifier
                JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(cryptoToken.getPublicKey(getCAToken().getAliasFromPurpose(
                        CATokenConstants.CAKEYPURPOSE_CRLSIGN)));
                crlgen.addExtension(Extension.authorityKeyIdentifier, getAuthorityKeyIdentifierCritical(), aki);
            }
        }

        // Authority Information Access
        final ASN1EncodableVector accessList = new ASN1EncodableVector();
        if (getAuthorityInformationAccess() != null) {
            for(String url :  getAuthorityInformationAccess()) {
                if(StringUtils.isNotEmpty(url)) {
                    GeneralName accessLocation = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
                    accessList.add(new AccessDescription(AccessDescription.id_ad_caIssuers, accessLocation));
                }
            }
        }
        if(accessList.size() > 0) {
            AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(new DERSequence(accessList));
            // "This CRL extension MUST NOT be marked critical." according to rfc4325
            crlgen.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
        }

        // CRLNumber extension
        if (getUseCRLNumber()) {
            CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
            crlgen.addExtension(Extension.cRLNumber, this.getCRLNumberCritical(), crlnum);
        }

        // ExpiredCertsOnCRL extension (is always specified as not critical)
        // Date format to be used is: yyyyMMddHHmmss
        // https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2005/CertificateExtensions.html
        //
        // expiredCertsOnCRL EXTENSION ::= {
        //   SYNTAX         ExpiredCertsOnCRL
        //   IDENTIFIED BY  id-ce-expiredCertsOnCRL
        // }
        // ExpiredCertsOnCRL ::= GeneralizedTime
        // The ExpiredCertsOnCRL CRL extension is not specified by IETF-PKIX. It is defined by the ITU-T Recommendation X.509 and
        // indicates that a CRL containing this extension will include revocation status information for certificates that have
        // been already expired. When used, the ExpiredCertsOnCRL contains the date on which the CRL starts to keep revocation
        // status information for expired certificates (i.e. revocation entries are not removed from the CRL for any certificates
        // that expire at or after the date contained in the ExpiredCertsOnCRL extension).
        final ASN1ObjectIdentifier ExpiredCertsOnCRL = new ASN1ObjectIdentifier("2.5.29.60");
        boolean keepexpiredcertsoncrl = getKeepExpiredCertsOnCRL();
        if(keepexpiredcertsoncrl) {
            // For now force parameter with date equals NotBefore of CA certificate, or now
            final DERGeneralizedTime keepDate;
            if (cacert != null) {
                keepDate = new DERGeneralizedTime(cacert.getNotBefore());
            } else {
                // Copied from org.bouncycastle.asn1.x509.Time to get right format of GeneralizedTime (no fractional seconds)
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss");
                dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
                String d = dateF.format(new Date()) + "Z";
                keepDate = new DERGeneralizedTime(d);
            }
            crlgen.addExtension(ExpiredCertsOnCRL, false, keepDate);
            if (log.isDebugEnabled()) {
                log.debug("ExpiredCertsOnCRL extension added to CRL. Keep date: " + keepDate.getTime());
            }
        }

        if (isDeltaCRL) {
            // DeltaCRLIndicator extension
            CRLNumber basecrlnum = new CRLNumber(BigInteger.valueOf(basecrlnumber));
            crlgen.addExtension(Extension.deltaCRLIndicator, true, basecrlnum);
        }
        // CRL Distribution point URI and Freshest CRL DP
        if (getUseCrlDistributionPointOnCrl()) {
            String crldistpoint = getDefaultCRLDistPoint();
            List<DistributionPoint> distpoints = generateDistributionPoints(crldistpoint, crlPartitionIndex);

            if (!distpoints.isEmpty()) {
                IssuingDistributionPoint idp = new IssuingDistributionPoint(distpoints.get(0).getDistributionPoint(), false, false, null, false,
                        false);

                // According to the RFC, IDP must be a critical extension.
                // Nonetheless, at the moment, Mozilla is not able to correctly
                // handle the IDP extension and discards the CRL if it is critical.
                crlgen.addExtension(Extension.issuingDistributionPoint, getCrlDistributionPointOnCrlCritical(), idp);
            }

            if (!isDeltaCRL) {
                String crlFreshestDP = getCADefinedFreshestCRL();
                List<DistributionPoint> freshestDistPoints = generateDistributionPoints(crlFreshestDP, crlPartitionIndex);
                if (!freshestDistPoints.isEmpty()) {
                    CRLDistPoint ext = new CRLDistPoint(freshestDistPoints.toArray(new DistributionPoint[freshestDistPoints.size()]));

                    // According to the RFC, the Freshest CRL extension on a
                    // CRL must not be marked as critical. Therefore it is
                    // hardcoded as not critical and is independent of
                    // getCrlDistributionPointOnCrlCritical().
                    crlgen.addExtension(Extension.freshestCRL, false, ext);
                }

            }
        }

        final X509CRLHolder crl;
        if (log.isDebugEnabled()) {
            log.debug("Signing CRL. Free memory="+Runtime.getRuntime().freeMemory());
        }
        String alias = getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        if (isMsCaCompatible() && partitionCaCert != null) {
            alias = getSignKeyAliasFromSubjectKeyId(cryptoToken, CertTools.getSubjectKeyId(partitionCaCert));
        }

        try {
            String prov = cryptoToken.getSignProviderName();
            if (BouncyCastleProvider.PROVIDER_NAME.equals(prov)) {
                prov = CryptoProviderTools.getProviderNameFromAlg(sigAlg);
            }
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(prov).build(cryptoToken.getPrivateKey(alias)), X509CAImpl.SIGN_BUFFER_SIZE);
            crl = crlgen.build(signer);
        } catch (OperatorCreationException e) {
            // Very fatal error
            throw new RuntimeException("Can not create Jca content signer: ", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Finished signing CRL. Free memory="+Runtime.getRuntime().freeMemory());
        }

        // Verify using the CA certificate before returning
        // If we can not verify the issued CRL using the CA certificate we don't want to issue this CRL
        // because something is wrong...
        final PublicKey verifyKey;
        if (cacert != null) {
            verifyKey = cacert.getPublicKey();
            if (log.isTraceEnabled()) {
                log.trace("Got the verify key from the CA certificate.");
            }
        } else {
            verifyKey = cryptoToken.getPublicKey(alias);
            if (log.isTraceEnabled()) {
                log.trace("Got the verify key from the CA token.");
            }
        }
        try {
            final ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(verifyKey);
            if (!crl.isSignatureValid(verifier)) {
                if (log.isTraceEnabled()) {
                    log.trace("The public key used to verify the CRL:" + System.lineSeparator() + KeyTools.getAsPem(verifyKey));
                    log.trace("The CRL whose signature could not be verified:" + System.lineSeparator() + KeyTools.getAsPem(crl));
                }
                throw new SignatureException("Cannot verify the signature of the CRL for issuer " + "'" + issuer
                        + "' using the public key with SHA-1 fingerprint " + CertTools.createPublicKeyFingerprint(verifyKey, "SHA-1")
                        + ". The CRL signature was created with a private key stored in the token " + cryptoToken.getTokenName()
                        + ". The most likely reason for this error is that the private key stored on the token does not correspond to the public key found in the issuer certificate.");
            }
        } catch (OperatorCreationException e) {
            // Very fatal error
            throw new RuntimeException("Can not create Jca content signer: ", e);
        } catch (CertException e) {
            throw new SignatureException(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Returning CRL. Free memory="+Runtime.getRuntime().freeMemory());
        }
        return crl;
    }

    private String getSignKeyAliasFromSubjectKeyId(CryptoToken cryptoToken, byte[] crlSubjectKeyIdentifier) throws CryptoTokenOfflineException {
        try {
            for (String keyAlias : cryptoToken.getAliases()) {
                String subjectKeyId = new String(Hex.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(keyAlias)).getKeyIdentifier()));
                if (StringUtils.equals(subjectKeyId, new String(Hex.encode(crlSubjectKeyIdentifier)))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Using key alias: '" + keyAlias + "' to sign CRL");
                    }
                    return keyAlias;
                }
            }
        } catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException(e);
        }
        throw new IllegalStateException("No key matching Subject Key Id '" + new String(Hex.encode(crlSubjectKeyIdentifier)) + "' found.");
    }

    /**
     * Generate a list of Distribution points.
     *
     * @param distPoints
     *            distribution points as String in semi column (';') separated format.
     * @return list of distribution points.
     */
    private List<DistributionPoint> generateDistributionPoints(final String distPoints, final int crlPartitionIndex) {
        // Multiple CDPs are separated with the ';' sign
        ArrayList<DistributionPoint> result = new ArrayList<>();
        for (final String uriTemplate : StringTools.splitURIs(StringUtils.defaultString(distPoints))) {
            final String uri = ((X509CAInfo) getCAInfo()).getCrlPartitionUrl(uriTemplate, crlPartitionIndex);
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
            if (log.isDebugEnabled()) {
                log.debug("Added CRL distpoint: " + uri);
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(gn);
            GeneralNames gns = GeneralNames.getInstance(new DERSequence(vec));
            DistributionPointName dpn = new DistributionPointName(0, gns);
            result.add(new DistributionPoint(dpn, null, null));
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getLatestVersion()
     */
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#upgrade()
     */
    @Override
    public void upgrade() {
        final float previousVersion = getVersion();
        super.upgrade();
        if (Float.compare(LATEST_VERSION, previousVersion) != 0) {
            // New version of the class, upgrade
            log.info("Upgrading X509CA with version " + getVersion());
            if (data.get(DEFAULTOCSPSERVICELOCATOR) == null) {
                setDefaultCRLDistPoint("");
                setDefaultOCSPServiceLocator("");
            }
            if (data.get(CRLISSUEINTERVAL) == null) {
                setCRLIssueInterval(0);
            }
            if (data.get(CRLOVERLAPTIME) == null) {
                // Default value 10 minutes
                // This used to be setting of 10, as an Integer, but was refactored to a long (ms) in v18->19,
                // therefore we have to update this to reflect that as well. If's probably not hurting anyone here, it's too old, but right is right.
                setCRLOverlapTime(10 * SimpleTime.MILLISECONDS_PER_MINUTE);
            }
            boolean useprintablestring = true;
            if (data.get("alwaysuseutf8subjectdn") == null) {
                // Default value true, if we had no configuration like this before
                if (data.get(USEUTF8POLICYTEXT) == null) {
                    setUseUTF8PolicyText(true);
                }
            } else {
                // Use the same value as we had before when we had alwaysuseutf8subjectdn
                boolean useutf8 = (Boolean) data.get("alwaysuseutf8subjectdn");
                if (data.get(USEUTF8POLICYTEXT) == null) {
                    setUseUTF8PolicyText(useutf8);
                }
                // If we had checked to use utf8 on an old CA, we do not want to use PrintableString after upgrading
                useprintablestring = !useutf8;
            }
            if (data.get(USEPRINTABLESTRINGSUBJECTDN) == null) {
                // Default value true (as before)
                setUsePrintableStringSubjectDN(useprintablestring);
            }
            if (data.get(DEFAULTCRLISSUER) == null) {
                setDefaultCRLIssuer(null);
            }
            if (data.get(USELDAPDNORDER) == null) {
                setUseLdapDNOrder(true); // Default value
            }
            if (data.get(DELTACRLPERIOD) == null) {
                setDeltaCRLPeriod(0); // v14
            }
            if (data.get(USECRLDISTRIBUTIONPOINTONCRL) == null) {
                setUseCrlDistributionPointOnCrl(false); // v15
            }
            if (data.get(CRLDISTRIBUTIONPOINTONCRLCRITICAL) == null) {
                setCrlDistributionPointOnCrlCritical(false); // v15
            }
            if (data.get(INCLUDEINHEALTHCHECK) == null) {
                setIncludeInHealthCheck(true); // v16
            }
            // v17->v18 is only an upgrade in order to upgrade CA token
            // v18->v19
            Object o = data.get(CRLPERIOD);
            if (o instanceof Integer) {
                setCRLPeriod(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_HOUR); // h to ms
            }
            o = data.get(CRLISSUEINTERVAL);
            if (o instanceof Integer) {
                setCRLIssueInterval(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_HOUR); // h to ms
            }
            o = data.get(CRLOVERLAPTIME);
            if (o instanceof Integer) {
                setCRLOverlapTime(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_MINUTE); // min to ms
            }
            o = data.get(DELTACRLPERIOD);
            if (o instanceof Integer) {
                setDeltaCRLPeriod(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_HOUR); // h to ms
            }
            if (data.get(NAMECHANGED) == null) {
                setNameChanged(false);
            }
            // v21, AIA: Copy CA issuer URI to separated AIA field.
            if (data.get(CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI) == null) {
                if (null != getAuthorityInformationAccess()) {
                    setCertificateAiaDefaultCaIssuerUri( getAuthorityInformationAccess());
                } else {
                    setCertificateAiaDefaultCaIssuerUri( new ArrayList<>());
                }
            }
            // v24 'serial number octet size' assign configured value (or default value if not configured)
            if (data.get(SERIALNUMBEROCTETSIZE) == null) {
                setCaSerialNumberOctetSize(CesecoreConfiguration.getSerialNumberOctetSizeForExistingCa());
            }
        }
    }

    @Override
    public String getCaImplType() {
        return CA_TYPE;
    }







}


