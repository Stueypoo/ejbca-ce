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
package org.cesecore.certificates.certificateprofile;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.stream.Collectors;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.certificate.ca.its.ITSApplicationIds;
import org.cesecore.certificate.ca.its.ITSCertificateType;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.standard.CabForumOrganizationIdentifier;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshExtension;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.ValidityDate;

/**
 * CertificateProfile is a basic class used to customize a certificate configuration or be inherited by fixed certificate profiles.
 *
 * Note that all classes that are serialized to database (such as this one) MUST use deterministic data types.
 * So LinkedHashMap/LinkedHashSet must be used instead of HashMap/HashSet.
 */
public class CertificateProfile extends UpgradeableDataHashMap implements Serializable, Cloneable {
    private static final Logger log = Logger.getLogger(CertificateProfile.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    // Public Constants
    public static final float LATEST_VERSION = (float) 53.0;

    public static final String ROOTCAPROFILENAME = "ROOTCA";
    public static final String SUBCAPROFILENAME = "SUBCA";
    public static final String ENDUSERPROFILENAME = "ENDUSER";
    public static final String OCSPSIGNERPROFILENAME = "OCSPSIGNER";
    public static final String SERVERPROFILENAME = "SERVER";
    public static final String SSHPROFILENAME = "SSH";
    public static final String ITSPROFILENAME = "ITS";

    public static final List<String> FIXED_PROFILENAMES = new ArrayList<>();
    static {
        FIXED_PROFILENAMES.add(ROOTCAPROFILENAME);
        FIXED_PROFILENAMES.add(SUBCAPROFILENAME);
        FIXED_PROFILENAMES.add(ENDUSERPROFILENAME);
        FIXED_PROFILENAMES.add(OCSPSIGNERPROFILENAME);
        FIXED_PROFILENAMES.add(SERVERPROFILENAME);
        FIXED_PROFILENAMES.add(SSHPROFILENAME);
        FIXED_PROFILENAMES.add(ITSPROFILENAME);
    }

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version of this class is not compatible with old versions. See Sun docs for <a
     * href=http://java.sun.com/products/jdk/1.1/docs/guide /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -8069608639716545206L;


    /** Microsoft Template Constants */
    public static final String MSTEMPL_DOMAINCONTROLLER = "DomainController";

    public static final String[] AVAILABLE_MSTEMPLATES = { MSTEMPL_DOMAINCONTROLLER };

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    /**
     * Determines the access rights in CV Certificates. CV Certificates is used by EU EAC ePassports and is issued by a CVC CA. DG3 is access to
     * fingerprints and DG4 access to iris.
     */
    public static final int CVC_ACCESS_NONE = 0;
    public static final int CVC_ACCESS_DG3 = 1;
    public static final int CVC_ACCESS_DG4 = 2;
    public static final int CVC_ACCESS_DG3DG4 = 3;
    public static final int CVC_ACCESS_RFU1 = 0x04;
    public static final int CVC_ACCESS_RFU2 = 0x08;
    public static final int CVC_ACCESS_RFU3 = 0x10;
    public static final int CVC_ACCESS_RFU4 = 0x20;
    // For signature terminals (defined in version 2.10 of the EAC specification)
    public static final int CVC_ACCESS_SIGN = 16;
    public static final int CVC_ACCESS_QUALSIGN = 32;
    public static final int CVC_ACCESS_SIGN_AND_QUALSIGN = 48;

    /**
     * CVC terminal types. Controls which set of roles and access rights are available.
     */
    public static final int CVC_TERMTYPE_IS = 0;
    /** Authentication terminal */
    public static final int CVC_TERMTYPE_AT = 1;
    /** Signature terminal */
    public static final int CVC_TERMTYPE_ST = 2;

    /** Accreditation Body DV for signature terminals. ABs accredits CSPs */
    public static final int CVC_SIGNTERM_DV_AB = 0;
    /** Certification Service Provider DV for signature terminals */
    public static final int CVC_SIGNTERM_DV_CSP = 1;

    /** Supported certificate versions. */
    public static final String VERSION_X509V3 = "X509v3";
    public static final String CUSTOMPROFILENAME = "CUSTOM";

    /** Constant indicating that any CA can be used with this certificate profile. */
    public static final int ANYCA = -1;
    /** Constant indicating that any elliptic curve may be used with this profile. */
    public static final String ANY_EC_CURVE = "ANY_EC_CURVE";

    public static final byte[] DEFAULT_CVC_RIGHTS_AT = { 0, 0, 0, 0, 0 };

    /** Constants for validity and private key usage period. */
    public static final String DEFAULT_CERTIFICATE_VALIDITY = "2y";
    /** Constant for default validity for fixed profiles is 25 years including 6 or 7 leap days. */
    public static final String DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA = "25y7d";
    /** Constant for default validity offset (for backward compatibility': -10m'!) */
    public static final String DEFAULT_CERTIFICATE_VALIDITY_OFFSET = "-10m";
    public static final long DEFAULT_PRIVATE_KEY_USAGE_PERIOD_OFFSET = 0;
    public static final long DEFAULT_PRIVATE_KEY_USAGE_PERIOD_LENGTH = 730 * 24 * 3600;

    // Profile fields
    protected static final String CERTVERSION = "certversion";
    @Deprecated
    protected static final String VALIDITY = "validity";
    protected static final String ENCODED_VALIDITY = "encodedvalidity";
    protected static final String USE_CERTIFICATE_VALIDITY_OFFSET = "usecertificatevalidityoffset";
    protected static final String CERTIFICATE_VALIDITY_OFFSET = "certificatevalidityoffset";
    protected static final String USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS = "useexpirationrestrictionforweekdays";
    protected static final String EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE = "expirationrestrictionforweekdaysbefore";
    protected static final String EXPIRATION_RESTRICTION_WEEKDAYS = "expirationrestrictionweekdays";
    protected static final String ALLOWVALIDITYOVERRIDE = "allowvalidityoverride";
    protected static final String ALLOWEXPIREDVALIDITYENDDATE = "allowexpiredvalidityenddate";
    protected static final String ALLOWKEYUSAGEOVERRIDE = "allowkeyusageoverride";
    protected static final String ALLOWBACKDATEDREVOCATION = "allowbackdatedrevokation";
    protected static final String ALLOWEXTENSIONOVERRIDE = "allowextensionoverride";
    protected static final String ALLOWDNOVERRIDE = "allowdnoverride";
    protected static final String ALLOWDNOVERRIDEBYEEI = "allowdnoverridebyeei";
    protected static final String ALLOWCERTSNOVERIDE = "allowcertsnoverride";

    //Standard key settings
    protected static final String AVAILABLEKEYALGORITHMS = "availablekeyalgorithms";
    protected static final String AVAILABLEECCURVES = "availableeccurves";
    protected static final String AVAILABLEBITLENGTHS = "availablebitlengths";
    protected static final String MINIMUMAVAILABLEBITLENGTH = "minimumavailablebitlength";
    protected static final String MAXIMUMAVAILABLEBITLENGTH = "maximumavailablebitlength";

    //Alternative key settings, with a focus on hybrid certificates
    private static final String ALTERNATIVE_AVAILABLEKEYALGORITHMS = "alternativeAvailableKeyAlgorithms";

    public static final String TYPE = "type";
    protected static final String AVAILABLECAS = "availablecas";
    protected static final String USEDPUBLISHERS = "usedpublishers";
    protected static final String USECNPOSTFIX = "usecnpostfix";
    protected static final String CNPOSTFIX = "cnpostfix";
    protected static final String USESUBJECTDNSUBSET = "usesubjectdnsubset";
    protected static final String SUBJECTDNSUBSET = "subjectdnsubset";
    protected static final String USESUBJECTALTNAMESUBSET = "usesubjectaltnamesubset";
    protected static final String SUBJECTALTNAMESUBSET = "subjectaltnamesubset";
    protected static final String USEDCERTIFICATEEXTENSIONS = "usedcertificateextensions";
    protected static final String DESCRIPTION = "description";
    protected static final String EABNAMESPACES = "eabnamespaces";
    /**
     * @deprecated since 6.8.0, where approval settings and profiles became interlinked.
     */
    @Deprecated
    protected static final String APPROVALSETTINGS = "approvalsettings";
    /**
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    public static final String NUMOFREQAPPROVALS = "numofreqapprovals";
    /**
     * @deprecated since 6.8.0, where approval settings and profiles became interlinked.
     */
    @Deprecated
    protected static final String APPROVALPROFILE = "approvalProfile";
    protected static final String APPROVALS = "approvals";

    protected static final String SIGNATUREALGORITHM = "signaturealgorithm";
    private static final String ALTERNATIVE_SIGNATUREALGORITHM = "alternativeSignatureAlgorithm";
    private static final String USE_ALTERNATIVE_SIGNATURE = "useAlternativeSignature";

    protected static final String USECERTIFICATESTORAGE = "usecertificatestorage";
    protected static final String STORECERTIFICATEDATA = "storecertificatedata";
    protected static final String STORESUBJECTALTNAME = "storesubjectaltname";
    //
    // CRL extensions
    protected static final String USECRLNUMBER = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL = "crlnumbercritical";
    //
    // Certificate extensions
    protected static final String USEBASICCONSTRAINTS = "usebasicconstrants";
    protected static final String BASICCONSTRAINTSCRITICAL = "basicconstraintscritical";
    protected static final String USEPATHLENGTHCONSTRAINT = "usepathlengthconstraint";
    protected static final String PATHLENGTHCONSTRAINT = "pathlengthconstraint";
    protected static final String USEKEYUSAGE = "usekeyusage";
    protected static final String KEYUSAGECRITICAL = "keyusagecritical";
    protected static final String KEYUSAGE_FORBIDENCRYPTIONUSAGEFORECC = "keyusageforbidencyrptionusageforecc";
    protected static final String KEYUSAGE = "keyusage";
    protected static final String USESUBJECTKEYIDENTIFIER = "usesubjectkeyidentifier";
    protected static final String USETRUNCATEDSUBJECTKEYIDENTIFIER = "usetruncatedsubjectkeyidentifier";
    protected static final String SUBJECTKEYIDENTIFIERCRITICAL = "subjectkeyidentifiercritical";
    protected static final String USEAUTHORITYKEYIDENTIFIER = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USESUBJECTALTERNATIVENAME = "usesubjectalternativename";
    protected static final String SUBJECTALTERNATIVENAMECRITICAL = "subjectalternativenamecritical";
    protected static final String USEISSUERALTERNATIVENAME = "useissueralternativename";
    protected static final String ISSUERALTERNATIVENAMECRITICAL = "issueralternativenamecritical";
    protected static final String USECRLDISTRIBUTIONPOINT = "usecrldistributionpoint";
    protected static final String USEDEFAULTCRLDISTRIBUTIONPOINT = "usedefaultcrldistributionpoint";
    protected static final String CRLDISTRIBUTIONPOINTCRITICAL = "crldistributionpointcritical";
    protected static final String CRLDISTRIBUTIONPOINTURI = "crldistributionpointuri";
    protected static final String CRLISSUER = "crlissuer";
    protected static final String USEFRESHESTCRL = "usefreshestcrl";
    protected static final String USECADEFINEDFRESHESTCRL = "usecadefinedfreshestcrl";
    protected static final String FRESHESTCRLURI = "freshestcrluri";
    protected static final String USECERTIFICATEPOLICIES = "usecertificatepolicies";
    protected static final String CERTIFICATEPOLICIESCRITICAL = "certificatepoliciescritical";
    /** Policy containing oid, User Notice and Cps Url */
    protected static final String CERTIFICATE_POLICIES = "certificatepolicies";
    protected static final String USEEXTENDEDKEYUSAGE = "useextendedkeyusage";
    protected static final String EXTENDEDKEYUSAGE = "extendedkeyusage";
    protected static final String EXTENDEDKEYUSAGECRITICAL = "extendedkeyusagecritical";
    protected static final String USEDOCUMENTTYPELIST = "usedocumenttypelist";
    protected static final String DOCUMENTTYPELISTCRITICAL = "documenttypelistcritical";
    protected static final String DOCUMENTTYPELIST = "documenttypelist";
    protected static final String USEOCSPNOCHECK = "useocspnocheck";
    protected static final String USEAUTHORITYINFORMATIONACCESS = "useauthorityinformationaccess";
    protected static final String USEOCSPSERVICELOCATOR = "useocspservicelocator";
    protected static final String USEDEFAULTCAISSUER = "usedefaultcaissuer";
    protected static final String USEDEFAULTOCSPSERVICELOCATOR = "usedefaultocspservicelocator";
    protected static final String OCSPSERVICELOCATORURI = "ocspservicelocatoruri";
    protected static final String USECAISSUERS = "usecaissuersuri";
    protected static final String CAISSUERS = "caissuers";
    protected static final String USELDAPDNORDER = "useldapdnorder";
    protected static final String USEMICROSOFTTEMPLATE = "usemicrosofttemplate";
    protected static final String MICROSOFTTEMPLATE = "microsofttemplate";
    /**Microsoft szOID_NTDS_CA_SECURITY_EXT for ADCS vuln. CVE-2022-26931 */
    protected static final String USE_MS_OBJECTSID_SECURITY_EXTENSION = "usemsobjectsidextension";
    protected static final String USECARDNUMBER = "usecardnumber";
    protected static final String USEQCSTATEMENT = "useqcstatement";
    protected static final String USEPKIXQCSYNTAXV2 = "usepkixqcsyntaxv2";
    protected static final String QCSTATEMENTCRITICAL = "useqcstatementcritical";
    protected static final String QCSTATEMENTRANAME = "useqcstatementraname";
    protected static final String QCSSEMANTICSID = "useqcsematicsid";
    protected static final String USEQCETSIQCCOMPLIANCE = "useqcetsiqccompliance";
    protected static final String USEQCETSIVALUELIMIT = "useqcetsivaluelimit";
    protected static final String QCETSIVALUELIMIT = "qcetsivaluelimit";
    protected static final String QCETSIVALUELIMITEXP = "qcetsivaluelimitexp";
    protected static final String QCETSIVALUELIMITCURRENCY = "qcetsivaluelimitcurrency";
    protected static final String USEQCETSIRETENTIONPERIOD = "useqcetsiretentionperiod";
    protected static final String QCETSIRETENTIONPERIOD = "qcetsiretentionperiod";
    protected static final String USEQCETSISIGNATUREDEVICE = "useqcetsisignaturedevice";
    protected static final String USEQCETSITYPE = "useqcetsitype";
    protected static final String QCETSITYPE = "qcetsitype";
    protected static final String QCETSIPDS = "qcetsipds";
    /** @deprecated since EJBCA 6.6.1. It was only used in 6.6.0, and is needed to handle upgrades from that version
     * PDS URLs are now handled in QCETSIPDS */
    @Deprecated
    protected static final String QCETSIPDSURL = "qcetsipdsurl";
    /** @deprecated since EJBCA 6.6.1. It was only used in 6.6.0, and is needed to handle upgrades from that version
    * PDS URLs are now handled in QCETSIPDS */
    @Deprecated
    protected static final String QCETSIPDSLANG = "qcetsipdslang";
    protected static final String USEQCPSD2 = "useqcpsd2";
    protected static final String USEQCCOUNTRIES = "useqccountries";
    protected static final String QCCOUNTRIESSTRING = "qccountriestring";
    protected static final String USEQCCUSTOMSTRING = "useqccustomstring";
    protected static final String QCCUSTOMSTRINGOID = "qccustomstringoid";
    protected static final String QCCUSTOMSTRINGTEXT = "qccustomstringtext";
    protected static final String USE_VALIDITY_ASSURED_SHORT_TERM = "usevalidityassuredshortterm";
    protected static final String VALIDITY_ASSURED_SHORT_TERM_CRITICAL = "validityassuredshorttermcritical";
    protected static final String USENAMECONSTRAINTS = "usenameconstraints";
    protected static final String NAMECONSTRAINTSCRITICAL = "nameconstraintscritical";
    protected static final String USECABFORGANIZATIONIDENTIFIER = "usecabforganizationidentifier";
    protected static final String USESUBJECTDIRATTRIBUTES = "usesubjectdirattributes";
    protected static final String CVCTERMINALTYPE = "cvctermtype";
    protected static final String CVCACCESSRIGHTS = "cvcaccessrights";
    protected static final String CVCLONGACCESSRIGHTS = "cvclongaccessrights";
    protected static final String CVCSIGNTERMDVTYPE = "cvcsigntermdvtype";
    protected static final String USEPRIVKEYUSAGEPERIOD          = "useprivkeyusageperiod";
    protected static final String USEPRIVKEYUSAGEPERIODNOTBEFORE = "useprivkeyusageperiodnotbefore";
    protected static final String USEPRIVKEYUSAGEPERIODNOTAFTER  = "useprivkeyusageperiodnotafter";
    protected static final String PRIVKEYUSAGEPERIODSTARTOFFSET  = "privkeyusageperiodstartoffset";
    protected static final String PRIVKEYUSAGEPERIODLENGTH           = "privkeyusageperiodlength";
    protected static final String USECERTIFICATETRANSPARENCYINCERTS = "usecertificatetransparencyincerts";
    protected static final String USECERTIFICATETRANSPARENCYINOCSP  = "usecertificatetransparencyinocsp";
    protected static final String USECERTIFICATETRANSPARENCYINPUBLISHERS  = "usecertificatetransparencyinpublisher";

    /* Certificate Transparency */
    protected static final String CTSUBMITEXISTING  = "ctsubmitexisting";
    protected static final String CTLOGS = "ctlogs";
    protected static final String CTLABELS = "ctlabels";
    @Deprecated
    protected static final String CT_MIN_TOTAL_SCTS = "ctminscts"; // This key is the same as in previous versions
    @Deprecated
    protected static final String CT_MIN_TOTAL_SCTS_OCSP = "ctminsctsocsp"; // This key is also the same as in previous versions
    @Deprecated
    protected static final String CT_MAX_SCTS = "ctmaxscts"; // Only used to fetch old value after upgrade, replaced by CT_MAX_NON_MANDATORY_SCTS and CT_MAX_MANDATORY_SCTS
    @Deprecated
    protected static final String CT_MAX_SCTS_OCSP = "ctmaxsctsocsp"; // Only used to fetch old value after upgrade, replaced by CT_MAX_NONMANDATORY_SCTS_OCSP and CT_MAX_MANDATORY_SCTS

    /* All deprecated below were removed in 6.10.1. Keep for upgrade purposes or move keys to UpgradeSessionBean */
    @Deprecated
    protected static final String CT_MIN_MANDATORY_SCTS = "ctminmandatoryscts";
    @Deprecated
    protected static final String CT_MAX_MANDATORY_SCTS = "ctmaxmandatoryscts";
    @Deprecated
    protected static final String CT_MIN_MANDATORY_SCTS_OCSP = "ctminmandatorysctsocsp";
    @Deprecated
    protected static final String CT_MAX_MANDATORY_SCTS_OCSP = "ctmaxmandatorysctsocsp";
    @Deprecated
    protected static final String CT_MIN_NONMANDATORY_SCTS = "ctminnonmandatoryscts";
    @Deprecated
    protected static final String CT_MAX_NONMANDATORY_SCTS = "ctmaxnonmandatoryscts";
    @Deprecated
    protected static final String CT_MIN_NONMANDATORY_SCTS_OCSP = "ctminnonmandatorysctsocsp";
    @Deprecated
    protected static final String CT_MAX_NONMANDATORY_SCTS_OCSP = "ctmaxnonmandatorysctsocsp";
    protected static final String CT_SCTS_MIN = "ctsctsmin";
    protected static final String CT_SCTS_MAX = "ctsctsmax";
    protected static final String CT_SCTS_MIN_OCSP = "ctsctsminocsp";
    protected static final String CT_SCTS_MAX_OCSP = "ctsctsmaxocsp";
    protected static final String CT_NUMBER_OF_SCTS_BY_VALIDITY = "ctnumberofsctsbyvalidity";
    protected static final String CT_NUMBER_OF_SCTS_BY_CUSTOM = "ctnumberofsctsbycustom";
    protected static final String CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY = "ctmaxnumberofsctsbyvalidity";
    protected static final String CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM = "ctmaxnumberofsctsbycustom";
    protected static final String CTMAXRETRIES = "ctmaxretries";

    protected static final String USERSINGLEACTIVECERTIFICATECONSTRAINT = "usesingleactivecertificateconstraint";
    protected static final String USECUSTOMDNORDER = "usecustomdnorder";
    protected static final String USECUSTOMDNORDERLDAP = "usecustomdnorderldap";
    protected static final String CUSTOMDNORDER = "customdnorder";
    protected static final String OVERRIDABLEEXTENSIONOIDS = "overridableextensionoids";
    protected static final String NONOVERRIDABLEEXTENSIONOIDS = "nonoverridableextensionoids";

    // SSH Certificate specific values
    protected static final String SSH_CERTIFICATE_TYPE = "sshcertificatetype";
    protected static final String SSH_EXTENSIONS = "sshextensions";
    protected static final String SSH_ALLOW_EXTERNAL_EXTENSIONS = "allowExternalSshExtensions";
    protected static final String SSH_REQUIRE_EXTERNAL_EXTENSIONS_DEFINED = "requireExternalSshExtensionsDefined";

    // ITS Certificate specific values
    protected static final String ITS_CERTIFICATE_TYPE = "itscertificatetype";
    protected static final String ITS_APP_PERMISSIONS = "itsapplicationpermissions";
    protected static final String ITS_CERT_ISSUNG_PERMISSIONS = "itscertissuingpermissions";


    /**
     * OID for creating Smartcard Number Certificate Extension SEIS Cardnumber Extension according to SS 614330/31
     */
    public static final String OID_CARDNUMBER = "1.2.752.34.2.1";

    protected static final Map<String, String> useStandardCertificateExtensions = new LinkedHashMap<>();
    {
        // Please keep the cert extensions ordered in this order
        // in order to not break assumptions made by clients/other software.
        // (This used to be a plain HashMap, hence the strange ordering)
        useStandardCertificateExtensions.put(USEDOCUMENTTYPELIST, "2.23.136.1.1.6.2");
        useStandardCertificateExtensions.put(USEBASICCONSTRAINTS, Extension.basicConstraints.getId());
        useStandardCertificateExtensions.put(USEAUTHORITYKEYIDENTIFIER, Extension.authorityKeyIdentifier.getId());
        useStandardCertificateExtensions.put(USEAUTHORITYINFORMATIONACCESS, Extension.authorityInfoAccess.getId());
        useStandardCertificateExtensions.put(USEFRESHESTCRL, Extension.freshestCRL.getId());
        useStandardCertificateExtensions.put(USEISSUERALTERNATIVENAME, Extension.issuerAlternativeName.getId());
        useStandardCertificateExtensions.put(USECARDNUMBER, OID_CARDNUMBER);
        useStandardCertificateExtensions.put(USESUBJECTALTERNATIVENAME, Extension.subjectAlternativeName.getId());
        useStandardCertificateExtensions.put(USE_MS_OBJECTSID_SECURITY_EXTENSION, CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT);
        useStandardCertificateExtensions.put(USENAMECONSTRAINTS, Extension.nameConstraints.getId());
        useStandardCertificateExtensions.put(USECERTIFICATEPOLICIES, Extension.certificatePolicies.getId());
        useStandardCertificateExtensions.put(USESUBJECTDIRATTRIBUTES, Extension.subjectDirectoryAttributes.getId());
        useStandardCertificateExtensions.put(USEOCSPNOCHECK, OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
        useStandardCertificateExtensions.put(USEEXTENDEDKEYUSAGE, Extension.extendedKeyUsage.getId());
        useStandardCertificateExtensions.put(USEQCSTATEMENT, Extension.qCStatements.getId());
        useStandardCertificateExtensions.put(USECABFORGANIZATIONIDENTIFIER, CabForumOrganizationIdentifier.OID);
        useStandardCertificateExtensions.put(USECRLDISTRIBUTIONPOINT, Extension.cRLDistributionPoints.getId());
        useStandardCertificateExtensions.put(USEMICROSOFTTEMPLATE, CertTools.OID_MSTEMPLATE);
        useStandardCertificateExtensions.put(USESUBJECTKEYIDENTIFIER, Extension.subjectKeyIdentifier.getId());
        useStandardCertificateExtensions.put(USEPRIVKEYUSAGEPERIOD, Extension.privateKeyUsagePeriod.getId());
        useStandardCertificateExtensions.put(USEKEYUSAGE, Extension.keyUsage.getId());
        useStandardCertificateExtensions.put(USE_VALIDITY_ASSURED_SHORT_TERM, CertTools.OID_VALIDITY_ASSURED_SHORT_TERM);
    }


    // Old values used to upgrade from v22 to v23
    protected static final String CERTIFICATEPOLICYID = "certificatepolicyid";
    /** Policy Notice Url to CPS field alias in the data structure */
    protected static final String POLICY_NOTICE_CPS_URL = "policynoticecpsurl";
    /** Policy Notice User Notice field alias in the data structure */
    protected static final String POLICY_NOTICE_UNOTICE_TEXT = "policynoticeunoticetext";

    // Public Methods

    /**
     * Creates a new instance of CertificateProfile. The default contructor creates a basic CertificateProfile
     * that is the same as an End User certificateProfile, except that there are _no_ key usages. this means that a certificate
     * issued with a default profile should not be usable for anything. Should be used for testing and where you want to create your own
     * CertificateProfile for specific purposes.
     *
     */
    public CertificateProfile() {
        setCommonDefaults();
    }

    /**
     * Creates a new instance of CertificateProfile
     *
     * These settings are general for all sub-profiles, only differing values are overridden in the sub-profiles. If changing any present value here
     * you must therefore go through all sub-profiles and add an override there. I.e. only add new values here, don't change any present settings.
     *
     * @param type
     *            one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_NO_PROFILE, CERTPROFILE_NO_ENDUSER, etc
     */
    public CertificateProfile(int type) {
        setCommonDefaults();
        setDefaultValues(type);
    }

    private void setCommonDefaults() {
        setType(CertificateConstants.CERTTYPE_ENDENTITY);
        setCertificateVersion(VERSION_X509V3);
        setEncodedValidity(DEFAULT_CERTIFICATE_VALIDITY);
        setUseCertificateValidityOffset(false);
        setCertificateValidityOffset(DEFAULT_CERTIFICATE_VALIDITY_OFFSET);
        setUseExpirationRestrictionForWeekdays(false);
        setExpirationRestrictionForWeekdaysExpireBefore(true);
        setDefaultExpirationRestrictionWeekdays();
        setAllowValidityOverride(false);
        setAllowExpiredValidityEndDate(false);
        setDescription("");

        setAllowExtensionOverride(false);

        setAllowDNOverride(false);
        setAllowDNOverrideByEndEntityInformation(false);
        setAllowBackdatedRevocation(false);
        setUseCertificateStorage(true);
        setStoreCertificateData(true);
        setStoreSubjectAlternativeName(true); // New profiles created after EJBCA 6.6.0 will store SAN by default

        setUseBasicConstraints(true);
        setBasicConstraintsCritical(true);

        setUseSubjectKeyIdentifier(true);
        setSubjectKeyIdentifierCritical(false);

        setUseAuthorityKeyIdentifier(true);
        setAuthorityKeyIdentifierCritical(false);

        setUseSubjectAlternativeName(true);
        setSubjectAlternativeNameCritical(false);

        setUseIssuerAlternativeName(true);
        setIssuerAlternativeNameCritical(false);

        setUseCRLDistributionPoint(false);
        setUseDefaultCRLDistributionPoint(false);
        setCRLDistributionPointCritical(false);
        setCRLDistributionPointURI("");
        setUseFreshestCRL(false);
        setUseCADefinedFreshestCRL(false);
        setFreshestCRLURI("");
        setCRLIssuer(null);

        setUseCertificatePolicies(false);
        setCertificatePoliciesCritical(false);
        ArrayList<CertificatePolicy> policies = new ArrayList<>();
        setCertificatePolicies(policies);

        setAvailableKeyAlgorithmsAsList(AlgorithmTools.getAvailableKeyAlgorithms());
        setAvailableEcCurvesAsList(Collections.singletonList(ANY_EC_CURVE));
        setAvailableBitLengthsAsList(AlgorithmTools.getAllBitLengths());
        setSignatureAlgorithm(null);
        setUseAlternativeSignature(false);
        setAlternativeAvailableKeyAlgorithmsAsList(
                AlgorithmTools.getAvailableKeyAlgorithms().stream().filter(alg -> AlgorithmTools.isPQC(alg)).collect(Collectors.toList()));
        setAlternativeSignatureAlgorithm(null);

        setUseKeyUsage(true);
        setKeyUsage(new boolean[9]);
        setAllowKeyUsageOverride(false);
        setKeyUsageCritical(true);

        setUseExtendedKeyUsage(false);
        setExtendedKeyUsage(new ArrayList<>());
        setExtendedKeyUsageCritical(false);

        setUseDocumentTypeList(false);
        setDocumentTypeListCritical(false);
        setDocumentTypeList(new ArrayList<>());

        ArrayList<Integer> availablecas = new ArrayList<>();
        availablecas.add(ANYCA);
        setAvailableCAs(availablecas);

        setPublisherList(new ArrayList<>());

        setUseOcspNoCheck(false);

        setUseLdapDnOrder(true);
        setUseCustomDnOrder(false);

        setUseMicrosoftTemplate(false);
        setMicrosoftTemplate("");
        setUseMsObjectSidSecurityExtension(true);
        setUseCardNumber(false);

        setUseCNPostfix(false);
        setCNPostfix("");

        setUseSubjectDNSubSet(false);
        setSubjectDNSubSet(new ArrayList<>());
        setUseSubjectAltNameSubSet(false);
        setSubjectAltNameSubSet(new ArrayList<>());

        setUsePathLengthConstraint(false);
        setPathLengthConstraint(0);

        setUseQCStatement(false);
        setUsePkixQCSyntaxV2(false);
        setQCStatementCritical(false);
        setQCStatementRAName(null);
        setQCSemanticsIds(null);
        setUseQCEtsiQCCompliance(false);
        setUseQCEtsiSignatureDevice(false);
        setUseQCEtsiValueLimit(false);
        setQCEtsiValueLimit(0);
        setQCEtsiValueLimitExp(0);
        setQCEtsiValueLimitCurrency(null);
        setUseQCEtsiRetentionPeriod(false);
        setQCEtsiRetentionPeriod(0);
        setUseQCCountries(false);
        setQCCountriesString("");
        setUseQCCustomString(false);
        setQCCustomStringOid(null);
        setQCCustomStringText(null);
        setQCEtsiPds(null);
        setQCEtsiType(null);

        setUseValidityAssuredShortTerm(false);
        setValidityAssuredShortTermCritical(false);

        setUseCertificateTransparencyInCerts(false);
        setUseCertificateTransparencyInOCSP(false);
        setUseCertificateTransparencyInPublishers(false);

        setUseSubjectDirAttributes(false);
        setUseNameConstraints(false);
        setUseAuthorityInformationAccess(false);
        setCaIssuers(new ArrayList<>());
        setUseDefaultCAIssuer(false);
        setUseDefaultOCSPServiceLocator(false);
        setOCSPServiceLocatorURI("");

        // Default to have access to fingerprint and iris
        setCVCAccessRightsIS(CertificateProfile.CVC_ACCESS_DG3DG4);

        setUsedCertificateExtensions(new ArrayList<>());
        setApprovals(new LinkedHashMap<>());

        // PrivateKeyUsagePeriod extension
        setUsePrivateKeyUsagePeriodNotBefore(false);
        setUsePrivateKeyUsagePeriodNotAfter(false);
        setPrivateKeyUsagePeriodStartOffset(DEFAULT_PRIVATE_KEY_USAGE_PERIOD_OFFSET);
        setPrivateKeyUsagePeriodLength(DEFAULT_PRIVATE_KEY_USAGE_PERIOD_LENGTH);

        setSingleActiveCertificateConstraint(false);

        setOverridableExtensionOIDs(new LinkedHashSet<>());
        setNonOverridableExtensionOIDs(new LinkedHashSet<>());
        setEabNamespaces(new LinkedHashSet<>());
    }

    /**
     * @param type
     *            one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_FIXED_ROOTCA
     */

    private void setDefaultValues(int type) {
        setDefaultEncodedValidity(type);
        setDefaultExtendedKeyUsage(type);
        setDefaultKeyUsage(type);

        if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA) {
            setType(CertificateConstants.CERTTYPE_ROOTCA);
            setAllowValidityOverride(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA) {
            setType(CertificateConstants.CERTTYPE_SUBCA);
            setAllowValidityOverride(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            setUseOcspNoCheck(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SERVER) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
        }
    }

    // Public Methods.

    /**
     *
     * @param type one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_FIXED_ROOTCA
     */
    public void setDefaultEncodedValidity(final int type) {
        if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA || type == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA) {
            setEncodedValidity(DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA);
        } else {
            setEncodedValidity(DEFAULT_CERTIFICATE_VALIDITY);
        }
    }

    /**
     *
     * @param type one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_FIXED_ROOTCA
     */
    public void setDefaultExtendedKeyUsage(final int type) {
        setExtendedKeyUsageCritical(false);
        if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA || type == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA) {
            setUseExtendedKeyUsage(false);
            setExtendedKeyUsage(new ArrayList<>());
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER) {
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_clientAuth.getId());
            eku.add(KeyPurposeId.id_kp_emailProtection.getId());
            setExtendedKeyUsage(eku);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER) {
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_OCSPSigning.getId());
            setExtendedKeyUsage(eku);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SERVER) {
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_serverAuth.getId());
            setExtendedKeyUsage(eku);
        }
    }

    /**
     * @param type one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_FIXED_ROOTCA
     */
    public void setDefaultKeyUsage(final int type) {
        if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA) {
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
            setKeyUsage(CertificateConstants.CRLSIGN, true);
            setKeyUsageCritical(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA) {
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
            setKeyUsage(CertificateConstants.CRLSIGN, true);
            setKeyUsageCritical(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER) {
            // Standard key usages for end users are: digitalSignature | nonRepudiation, and/or (keyEncipherment or keyAgreement)
            // Default key usage is digitalSignature | nonRepudiation | keyEncipherment
            // Create an array for KeyUsage according to X509Certificate.getKeyUsage()
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.NONREPUDIATION, true);
            setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
            setKeyUsageCritical(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER) {
            // Default key usage for an OCSP signer is digitalSignature
            // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsageCritical(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SERVER) {
            // Standard key usages for server are: digitalSignature | (keyEncipherment or keyAgreement)
            // Default key usage is digitalSignature | keyEncipherment
            // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
            setKeyUsageCritical(true);
        }
    }

    /** Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateProfile class. */
    public String getCertificateVersion() {
        return (String) data.get(CERTVERSION);
    }

    /**
     * Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateProfile class.
     */
    public void setCertificateVersion(String version) {
        data.put(CERTVERSION, version);
    }

    /**
     * @see ValidityDate#getDateBeforeVersion661(long, java.util.Date)
     * @return a long that is used to provide the end date of certificates for this profile, interpreted by ValidityDate#getDate
     * @deprecated since EJBCA 6.6.1
     */
    @Deprecated
    public long getValidity() {
        return (Long) data.get(VALIDITY);
    }

    /**
     * Gets the encoded validity.
     * @return the validity as ISO8601 date or relative time.
     * @see {@link org.cesecore.util.ValidityDate ValidityDate}
     * @see {@link org.cesecore.util.SimpleTime SimpleTime}
     */
    @SuppressWarnings("deprecation")
    public String getEncodedValidity() {
        String result = (String) data.get(ENCODED_VALIDITY);
        if (StringUtils.isBlank(result)) {
            result = ValidityDate.getStringBeforeVersion661(getValidity());
            setEncodedValidity(result);
        }
        return result;
    }

    /**
     * Sets the encoded validity .
     * @param encodedValidity the validity as ISO8601 date or relative time.
     * @see {@link org.cesecore.util.ValidityDate ValidityDate}
     * @see {@link org.cesecore.util.SimpleTime SimpleTime}
     */
    public void setEncodedValidity(String encodedValidity) {
        data.put(ENCODED_VALIDITY, encodedValidity);
    }

    /**
     * Gets the certificate validity offset.
     * @return true if we should overwrite the default certificate validity offset with the one specified in the certificate profile.
     * @see {@link #setCertificateValidityOffset(String)}
     */
    public boolean getUseCertificateValidityOffset() {
        // Extra null check to handle in-development upgrades
        if (data.get(USE_CERTIFICATE_VALIDITY_OFFSET) != null) {
            return (Boolean) data.get(USE_CERTIFICATE_VALIDITY_OFFSET);
        } else {
            return false;
        }
    }

    /**
     * Use certificate validity offset.
     * @param enabled enabled
     */
    public void setUseCertificateValidityOffset(boolean enabled) {
        data.put(USE_CERTIFICATE_VALIDITY_OFFSET, enabled);
    }

    /**
     * Gets the certificate validity offset.
     * @return the offset as simple time string with seconds precision (i.e. '-10m')
     * @see org.cesecore.util.SimpleTime
     */
    public String getCertificateValidityOffset() {
        return (String) data.get(CERTIFICATE_VALIDITY_OFFSET);
    }

    /**
     * Sets the certificate not before offset.
     * @param simpleTime the offset as simple time string with seconds precision.
     * @see org.cesecore.util.SimpleTime
     */
    public void setCertificateValidityOffset(String simpleTime) {
        data.put(CERTIFICATE_VALIDITY_OFFSET, simpleTime);
    }

    /**
     * @return true if we should apply restrictions that certificate expiration can only occur on week days specified by setExpirationRestrictionWeekday
     * @see #setExpirationRestrictionWeekdays(boolean[])
     */
    public boolean getUseExpirationRestrictionForWeekdays() {
        return (Boolean) data.get(USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS);
    }

    /**
     * Use validity expiration restriction.
     * @param enabled enabled
     */
    public void setUseExpirationRestrictionForWeekdays(boolean enabled) {
        data.put(USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS, enabled);
    }

    /**
     * @return true if we should roll back expiration or false of we should roll forward expiration to match week days specified by setExpirationRestrictionWeekday
     * @see #setExpirationRestrictionWeekdays(boolean[])
     */
    public boolean getExpirationRestrictionForWeekdaysExpireBefore() {
        return (Boolean) data.get(EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE);
    }

    /**
     * Sets if the certificate validity shall expire earlier as requested if a the expiration
     * restriction was applied?
     *
     * @param enabled true, otherwise false.
     */
    public void setExpirationRestrictionForWeekdaysExpireBefore(boolean enabled) {
        data.put(EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE, enabled);
    }

    /**
     * @param weekday (see java.util.Calendar.MONDAY - SUNDAY)
     * @return true if the weekday is selected as validity expiration restriction.
     */
    @SuppressWarnings("unchecked")
    public boolean getExpirationRestrictionWeekday(int weekday) {
        return ((ArrayList<Boolean>) data.get(EXPIRATION_RESTRICTION_WEEKDAYS)).get(weekday - 1);
    }

    /**
     * Include a weekday as validity expiration restriction.
     * @param weekday (see java.util.Calendar.MONDAY - SUNDAY)
     * @param enabled enabled
     */
    @SuppressWarnings("unchecked")
    public void setExpirationRestrictionWeekday(int weekday, boolean enabled) {
        ((ArrayList<Boolean>) data.get(EXPIRATION_RESTRICTION_WEEKDAYS)).set(weekday-1, enabled);
    }

    /**
     * Gets a copy of the List<Boolean> where validity restriction for weekdays are stored.
     *
     * @return boolean array.
     */
    @SuppressWarnings("unchecked")
    public boolean[] getExpirationRestrictionWeekdays() {
        final ArrayList<Boolean> list = (ArrayList<Boolean>) data.get(EXPIRATION_RESTRICTION_WEEKDAYS);
        final boolean[] result = new boolean[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = list.get(i);
        }
        return result;
    }

    public void setExpirationRestrictionWeekdays(boolean[] weekdays) {
        final ArrayList<Boolean> list = new ArrayList<>(weekdays.length);
        for (boolean weekday : weekdays) {
            list.add(weekday);
        }
        data.put(EXPIRATION_RESTRICTION_WEEKDAYS, list);
    }

    private void setDefaultExpirationRestrictionWeekdays() {
        setExpirationRestrictionWeekdays(new boolean[7]);
        setExpirationRestrictionWeekday(Calendar.MONDAY, true);
        setExpirationRestrictionWeekday(Calendar.FRIDAY, true);
        setExpirationRestrictionWeekday(Calendar.SATURDAY, true);
        setExpirationRestrictionWeekday(Calendar.SUNDAY, true);
    }

    public boolean getUseValidityAssuredShortTerm() {
        return Optional.ofNullable((Boolean) data.get(USE_VALIDITY_ASSURED_SHORT_TERM)).orElse(false);
    }

    public void setUseValidityAssuredShortTerm(boolean enabled) {
        data.put(USE_VALIDITY_ASSURED_SHORT_TERM, enabled);
    }

    public boolean getValidityAssuredShortTermCritical() {
        return Optional.ofNullable((Boolean) data.get(VALIDITY_ASSURED_SHORT_TERM_CRITICAL)).orElse(false);
    }

    public void setValidityAssuredShortTermCritical(boolean critical) {
        data.put(VALIDITY_ASSURED_SHORT_TERM_CRITICAL, critical);
    }

    /**
     * If validity override is allowed, a certificate can have a shorter validity than the one specified in the certificate profile, but never longer.
     * A certificate created with validity override can hava a starting point in the future.
     *
     * @return true if validity override is allowed
     */
    public boolean getAllowValidityOverride() {
        return (Boolean) data.get(ALLOWVALIDITYOVERRIDE);
    }

    /**
     * If validity override is allowed, a certificate can have a shorter validity than the one specified in the certificate profile, but never longer.
     * A certificate created with validity override can hava a starting point in the future.
     */
    public void setAllowValidityOverride(boolean allowvalidityoverride) {
        data.put(ALLOWVALIDITYOVERRIDE, allowvalidityoverride);
    }

    /**
     * Allows creation of certificates with end date in the past.
     */
    public boolean getAllowExpiredValidityEndDate() {
        final Object d = data.get(ALLOWEXPIREDVALIDITYENDDATE);
        return d != null && (Boolean) d;
    }

    /**
     * Allows creation of certificates with end date in the past.
     * @param   allowExpiredValidityEndDate
     */
    public void setAllowExpiredValidityEndDate(boolean allowExpiredValidityEndDate) {
        data.put(ALLOWEXPIREDVALIDITYENDDATE, allowExpiredValidityEndDate);
    }

    /**
     * If extension override is allowed, the X509 certificate extension created in a certificate can come from the request sent by the user. If the
     * request contains an extension than will be used instead of the one defined in the profile. If the request does not contain an extension, the
     * one defined in the profile will be used.
     */
    public boolean getAllowExtensionOverride() {
        final Object d = data.get(ALLOWEXTENSIONOVERRIDE);
        return d != null && (Boolean) d;
    }

    /** @see #getAllowExtensionOverride() */
    public void setAllowExtensionOverride(boolean allowextensionoverride) {
        data.put(ALLOWEXTENSIONOVERRIDE, allowextensionoverride);
    }

    /**
     * If DN override is allowed, the X509 subject DN extension created in a certificate can
     * come directly from the CSR in the request sent by the user. This is instead of the normal way where the user's
     * registered DN is used.
     */
    public boolean getAllowDNOverride() {
        final Object d = data.get(ALLOWDNOVERRIDE);
        return d != null && (Boolean) d;
    }

    /** @see #getAllowDNOverride() */
    public void setAllowDNOverride(boolean allowdnoverride) {
        data.put(ALLOWDNOVERRIDE, allowdnoverride);
    }

    /**
     * If DN override by End Entity Information is allowed, the X509 subject DN extension created in a certificate can
     * come directly from the request meta information sent by the user. This is instead of the normal way where the
     * user's registered DN is used.
     */
    public boolean getAllowDNOverrideByEndEntityInformation() {
        Object d = data.get(ALLOWDNOVERRIDEBYEEI);
        return d != null && (Boolean) d;
    }

    /** @see #getAllowDNOverrideByEndEntityInformation() */
    public void setAllowDNOverrideByEndEntityInformation(final boolean value) {
        data.put(ALLOWDNOVERRIDEBYEEI, value);
    }

    /**
     * If override is allowed the serial number could be specified.
     *
     * @return true if allowed
     */
    public boolean getAllowCertSerialNumberOverride() {
        Object d = data.get(ALLOWCERTSNOVERIDE);
        return d != null && (Boolean) d;
    }

    /**
     * @see #getAllowDNOverride()
     * @param allowdnoverride
     *            new value
     */
    public void setAllowCertSerialNumberOverride(boolean allowdnoverride) {
        data.put(ALLOWCERTSNOVERIDE, allowdnoverride);
    }

    public boolean getUseBasicConstraints() {
        return (Boolean) data.get(USEBASICCONSTRAINTS);
    }

    public void setUseBasicConstraints(boolean usebasicconstraints) {
        data.put(USEBASICCONSTRAINTS, usebasicconstraints);
    }

    public boolean getBasicConstraintsCritical() {
        return (Boolean) data.get(BASICCONSTRAINTSCRITICAL);
    }

    public void setBasicConstraintsCritical(boolean basicconstraintscritical) {
        data.put(BASICCONSTRAINTSCRITICAL, basicconstraintscritical);
    }

    public boolean getUseKeyUsage() {
        return (Boolean) data.get(USEKEYUSAGE);
    }

    public void setUseKeyUsage(boolean usekeyusage) {
        data.put(USEKEYUSAGE, usekeyusage);
    }

    public boolean getKeyUsageCritical() {
        return (Boolean) data.get(KEYUSAGECRITICAL);
    }

    public void setKeyUsageCritical(boolean keyusagecritical) {
        data.put(KEYUSAGECRITICAL, keyusagecritical);
    }

    public boolean getKeyUsageForbidEncryptionUsageForECC() {
        return (Boolean) data.getOrDefault(KEYUSAGE_FORBIDENCRYPTIONUSAGEFORECC, false);
    }

    public void setKeyUsageForbidEncryptionUsageForECC(boolean keyUsageForbidEncryptionUsageForECC) {
        data.put(KEYUSAGE_FORBIDENCRYPTIONUSAGEFORECC, keyUsageForbidEncryptionUsageForECC);
    }

    public boolean getUseSubjectKeyIdentifier() {
        return (Boolean) data.get(USESUBJECTKEYIDENTIFIER);
    }

    public void setUseSubjectKeyIdentifier(boolean usesubjectkeyidentifier) {
        data.put(USESUBJECTKEYIDENTIFIER, usesubjectkeyidentifier);
    }

    /**
     * If the truncated version (method 2 in RFC5280) of key identifier should be used.
     * It is uncommon, only few known (EV charging as of march 2023) used method 2
     * @return true if truncated method should be used, default false if not set to true explicitly
     */
    public boolean getUseTruncatedSubjectKeyIdentifier() {
        Object d = data.get(USETRUNCATEDSUBJECTKEYIDENTIFIER);
        return d != null && (Boolean) d;
    }

    public void setUseTruncatedSubjectKeyIdentifier(boolean usetruncatedsubjectkeyidentifier) {
        data.put(USETRUNCATEDSUBJECTKEYIDENTIFIER, usetruncatedsubjectkeyidentifier);
    }

    public boolean getSubjectKeyIdentifierCritical() {
        return (Boolean) data.get(SUBJECTKEYIDENTIFIERCRITICAL);
    }

    public void setSubjectKeyIdentifierCritical(boolean subjectkeyidentifiercritical) {
        data.put(SUBJECTKEYIDENTIFIERCRITICAL, subjectkeyidentifiercritical);
    }

    public boolean getUseAuthorityKeyIdentifier() {
        return (Boolean) data.get(USEAUTHORITYKEYIDENTIFIER);
    }

    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) {
        data.put(USEAUTHORITYKEYIDENTIFIER, useauthoritykeyidentifier);
    }

    public boolean getAuthorityKeyIdentifierCritical() {
        return (Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL);
    }

    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) {
        data.put(AUTHORITYKEYIDENTIFIERCRITICAL, authoritykeyidentifiercritical);
    }

    public boolean getUseSubjectAlternativeName() {
        return (Boolean) data.get(USESUBJECTALTERNATIVENAME);
    }

    public void setUseSubjectAlternativeName(boolean usesubjectalternativename) {
        data.put(USESUBJECTALTERNATIVENAME, usesubjectalternativename);
    }

    public boolean getStoreCertificateData() {
        // Lazy upgrade for profiles created prior to EJBCA 6.2.10
        final Boolean value = (Boolean) data.get(STORECERTIFICATEDATA);
        if (value == null) {
            // Default for existing profiles is true
            setStoreCertificateData(true);
            return true;
        } else {
            return value;
        }
    }

    public void setStoreCertificateData(boolean storeCertificateData) {
        data.put(STORECERTIFICATEDATA, storeCertificateData);
    }

    /** @return true if the CertificateData.subjectAltName column should be populated. */
    public boolean getStoreSubjectAlternativeName() {
        // Lazy upgrade for profiles created prior to EJBCA 6.6.0
        final Boolean value = (Boolean) data.get(STORESUBJECTALTNAME);
        if (value == null) {
            // Old profiles created before EJBCA 6.6.0 will not store SAN by default.
            setStoreSubjectAlternativeName(false);
            return false;
        } else {
            return value;
        }
    }

    public void setStoreSubjectAlternativeName(final boolean storeSubjectAlternativeName) {
        data.put(STORESUBJECTALTNAME, storeSubjectAlternativeName);
    }

    public boolean getSubjectAlternativeNameCritical() {
        return (Boolean) data.get(SUBJECTALTERNATIVENAMECRITICAL);
    }

    public void setSubjectAlternativeNameCritical(boolean subjectalternativenamecritical) {
        data.put(SUBJECTALTERNATIVENAMECRITICAL, subjectalternativenamecritical);
    }

    public boolean getUseIssuerAlternativeName() {
        return (Boolean) data.get(USEISSUERALTERNATIVENAME);
    }

    public void setUseIssuerAlternativeName(boolean useissueralternativename) {
        data.put(USEISSUERALTERNATIVENAME, useissueralternativename);
    }

    public boolean getIssuerAlternativeNameCritical() {
        return (Boolean) data.get(ISSUERALTERNATIVENAMECRITICAL);
    }

    public void setIssuerAlternativeNameCritical(boolean issueralternativenamecritical) {
        data.put(ISSUERALTERNATIVENAMECRITICAL, issueralternativenamecritical);
    }

    public boolean getUseCRLDistributionPoint() {
        return (Boolean) data.get(USECRLDISTRIBUTIONPOINT);
    }

    public void setUseCRLDistributionPoint(boolean usecrldistributionpoint) {
        data.put(USECRLDISTRIBUTIONPOINT, usecrldistributionpoint);
    }

    public boolean getUseDefaultCRLDistributionPoint() {
        return (Boolean) data.get(USEDEFAULTCRLDISTRIBUTIONPOINT);
    }

    public void setUseDefaultCRLDistributionPoint(boolean usedefaultcrldistributionpoint) {
        data.put(USEDEFAULTCRLDISTRIBUTIONPOINT, usedefaultcrldistributionpoint);
    }

    public boolean getCRLDistributionPointCritical() {
        return (Boolean) data.get(CRLDISTRIBUTIONPOINTCRITICAL);
    }

    public void setCRLDistributionPointCritical(boolean crldistributionpointcritical) {
        data.put(CRLDISTRIBUTIONPOINTCRITICAL, crldistributionpointcritical);
    }

    public String getCRLDistributionPointURI() {
        return (String) data.get(CRLDISTRIBUTIONPOINTURI);
    }

    public void setCRLDistributionPointURI(String crldistributionpointuri) {
        if (crldistributionpointuri == null) {
            data.put(CRLDISTRIBUTIONPOINTURI, "");
        } else {
            data.put(CRLDISTRIBUTIONPOINTURI, crldistributionpointuri);
        }
    }

    public String getCRLIssuer() {
        return (String) data.get(CRLISSUER);
    }

    public void setCRLIssuer(String crlissuer) {
        if (crlissuer == null) {
            data.put(CRLISSUER, "");
        } else {
            data.put(CRLISSUER, crlissuer);
        }
    }

    public boolean getUseFreshestCRL() {
        final Object obj = data.get(USEFRESHESTCRL);
        return obj != null && (Boolean) obj;
    }

    public void setUseFreshestCRL(boolean usefreshestcrl) {
        data.put(USEFRESHESTCRL, usefreshestcrl);
    }

    public boolean getUseCADefinedFreshestCRL() {
        Object obj = data.get(USECADEFINEDFRESHESTCRL);
        return obj != null && (Boolean) obj;
    }

    public void setUseCADefinedFreshestCRL(boolean usecadefinedfreshestcrl) {
        data.put(USECADEFINEDFRESHESTCRL, usecadefinedfreshestcrl);
    }

    public String getFreshestCRLURI() {
        return ((String) data.get(FRESHESTCRLURI));
    }

    public void setFreshestCRLURI(String freshestcrluri) {
        if (freshestcrluri == null) {
            data.put(FRESHESTCRLURI, "");
        } else {
            data.put(FRESHESTCRLURI, freshestcrluri);
        }
    }

    public boolean getUseCertificatePolicies() {
        return (Boolean) data.get(USECERTIFICATEPOLICIES);
    }

    public void setUseCertificatePolicies(boolean usecertificatepolicies) {
        data.put(USECERTIFICATEPOLICIES, usecertificatepolicies);
    }

    public boolean getUseCertificateStorage() {
        //Lazy upgrade for profiles created prior to EJBCA 6.2.10
        Boolean value = (Boolean) data.get(USECERTIFICATESTORAGE);
        if (value == null) {
            //Default is true
            setUseCertificateStorage(true);
            return true;
        } else {
            return value;
        }
    }

    public void setUseCertificateStorage(boolean useCertificateStorage) {
        data.put(USECERTIFICATESTORAGE, useCertificateStorage);
    }

    public boolean getCertificatePoliciesCritical() {
        return (Boolean) data.get(CERTIFICATEPOLICIESCRITICAL);
    }

    public void setCertificatePoliciesCritical(boolean certificatepoliciescritical) {
        data.put(CERTIFICATEPOLICIESCRITICAL, certificatepoliciescritical);
    }

    public List<CertificatePolicy> getCertificatePolicies() {
        @SuppressWarnings("unchecked")
        List<CertificatePolicy> l = (List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES);
        if (l == null) {
            l = new ArrayList<>();
        } else if (!l.isEmpty()) {
            // Check class name, because we changed this in EJBCA 5 and need to support older versions in the database for 100% upgrade
            try {
                // Don't remove the unused test object
                CertificatePolicy test = l.get(0); // NOPMD: we need to actually get the text object, otherwise the cast will not be tried
                test.getPolicyID();
            } catch (ClassCastException e) {
                if (log.isDebugEnabled()) {
                    log.debug("CertificatePolicy in profile is old class name (< EJBCA 5), post-upgrade has not been run. Converting in code to return new class type.");
                }
                @SuppressWarnings("unchecked")
                List<Object> oldl = (List<Object>) data.get(CERTIFICATE_POLICIES);
                // In worst case they can have mixed old and new classes, therefore we use a "normal" iterator so we can verify the cast
                l = new ArrayList<>();
                for (Object anOldl : oldl) {
                    try {
                        org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy oldPol = (org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy) anOldl;
                        CertificatePolicy newPol = new CertificatePolicy(oldPol.getPolicyID(), oldPol.getQualifierId(), oldPol.getQualifier());
                        if (log.isTraceEnabled()) {
                            log.trace("Adding converted policy");
                        }
                        l.add(newPol);
                    } catch (ClassCastException e2) {
                        // This was already a new class, there are mixed policies here...
                        CertificatePolicy newPol = (CertificatePolicy) anOldl;
                        if (log.isTraceEnabled()) {
                            log.trace("Adding non-converted policy");
                        }
                        l.add(newPol);
                    }
                }
            }
        }
        return l;
    }

    @SuppressWarnings("unchecked")
    public void addCertificatePolicy(CertificatePolicy policy) {
        if (data.get(CERTIFICATE_POLICIES) == null) {
            setCertificatePolicies(new ArrayList<>());
        }
        ((List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES)).add(policy);
    }

    public void setCertificatePolicies(List<CertificatePolicy> policies) {
        if (policies == null) {
            data.put(CERTIFICATE_POLICIES, new ArrayList<>(0));
        } else {
            data.put(CERTIFICATE_POLICIES, policies);
        }
    }

    @SuppressWarnings("unchecked")
    public void removeCertificatePolicy(CertificatePolicy policy) {
        if (data.get(CERTIFICATE_POLICIES) != null) {
            ((List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES)).remove(policy);
        }
    }

    /** Type is used when setting BasicConstraints, i.e. to determine if it is a CA or an end entity
     * @see {@link CertificateConstants#CERTTYPE_ROOTCA}, etc
     */
    public int getType() {
        return (Integer) data.get(TYPE);
    }

    /** Type is used when setting BasicConstraints, i.e. to determine if it is a CA or an end entity
     * @see {@link CertificateConstants#CERTTYPE_ROOTCA}, etc
     */
    public void setType(int type) {
        data.put(TYPE, type);
    }

    public boolean isTypeSubCA() {
        return (Integer) data.get(TYPE) == CertificateConstants.CERTTYPE_SUBCA;
    }

    public boolean isTypeRootCA() {
        return (Integer) data.get(TYPE) == CertificateConstants.CERTTYPE_ROOTCA;
    }

    public boolean isTypeEndEntity() {
        return (Integer) data.get(TYPE) == CertificateConstants.CERTTYPE_ENDENTITY;
    }

    public boolean isKeyAlgorithmsECType() {
        List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
        return availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_EC)
                || availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA);
    }

    public boolean doSelectedEcRequirebitLenths() {
        List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
        return (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_EC)
                || availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) && getAvailableEcCurvesAsList().contains(ANY_EC_CURVE);
    }

    public boolean isKeyAlgorithmsRequireKeySizes() {
        List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
        return  doSelectedEcRequirebitLenths()
                || availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_RSA);
    }

    public String[] getAvailableKeyAlgorithms() {
        final List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
        return availableKeyAlgorithms.toArray(new String[availableKeyAlgorithms.size()]);
    }

    @SuppressWarnings("unchecked")
    public List<String> getAvailableKeyAlgorithmsAsList() {
        return (ArrayList<String>) data.get(AVAILABLEKEYALGORITHMS);
    }

    public void setAvailableKeyAlgorithms(final String[] availableKeyAlgorithms) {
        setAvailableKeyAlgorithmsAsList(Arrays.asList(availableKeyAlgorithms));
    }

    public void setAvailableKeyAlgorithmsAsList(final List<String> availableKeyAlgorithms) {
        data.put(AVAILABLEKEYALGORITHMS, new ArrayList<>(availableKeyAlgorithms));
    }

    public String[] getAlternativeAvailableKeyAlgorithms() {
        final List<String> availableKeyAlgorithms = getAlternativeAvailableKeyAlgorithmsAsList();
        if (availableKeyAlgorithms == null) {
            return ArrayUtils.EMPTY_STRING_ARRAY;
        }
        return availableKeyAlgorithms.toArray(new String[availableKeyAlgorithms.size()]);
    }

    @SuppressWarnings("unchecked")
    public List<String> getAlternativeAvailableKeyAlgorithmsAsList() {
        return (ArrayList<String>) data.get(ALTERNATIVE_AVAILABLEKEYALGORITHMS);
    }

    public void setAlternativeAvailableKeyAlgorithms(final String[] alternativeAvailableKeyAlgorithms) {
        setAlternativeAvailableKeyAlgorithmsAsList(Arrays.asList(alternativeAvailableKeyAlgorithms));
    }

    public void setAlternativeAvailableKeyAlgorithmsAsList(final List<String> alternativeAvailableKeyAlgorithms) {
        data.put(ALTERNATIVE_AVAILABLEKEYALGORITHMS, new ArrayList<>(alternativeAvailableKeyAlgorithms));
    }

    public String[] getAvailableEcCurves() {
        final List<String> availableEcCurves = getAvailableEcCurvesAsList();
        return availableEcCurves.toArray(new String[availableEcCurves.size()]);
    }

    @SuppressWarnings("unchecked")
    public List<String> getAvailableEcCurvesAsList() {
        return (ArrayList<String>) data.get(AVAILABLEECCURVES);
    }

    public void setAvailableEcCurves(final String[] availableEcCurves) {
        setAvailableEcCurvesAsList(Arrays.asList(availableEcCurves));
    }

    public void setAvailableEcCurvesAsList(final List<String> availableEcCurves) {
        data.put(AVAILABLEECCURVES, new ArrayList<>(availableEcCurves));
    }

    public int[] getAvailableBitLengths() {
        final List<Integer> availablebitlengths = getAvailableBitLengthsAsList();
        final int[] returnval = new int[availablebitlengths.size()];
        for (int i = 0; i < availablebitlengths.size(); i++) {
            returnval[i] = availablebitlengths.get(i);
        }
        return returnval;
    }

    @SuppressWarnings("unchecked")
    public List<Integer> getAvailableBitLengthsAsList() {
        return (ArrayList<Integer>) data.get(AVAILABLEBITLENGTHS);
    }

    public void setAvailableBitLengthsAsList(final List<Integer> availableBitLengths) {
        if (log.isTraceEnabled()) {
            log.trace("setAvailableBitLengthsAsList");
            log.trace("[" + availableBitLengths + "]");
        }
        // Strange values here, but it makes the <> below work for sure
        int minimumavailablebitlength = 99999999;
        int maximumavailablebitlength = 0;
        for (Integer availablebitlength : availableBitLengths) {
            if (availablebitlength > maximumavailablebitlength) {
                maximumavailablebitlength = availablebitlength;
            }
            if (availablebitlength < minimumavailablebitlength) {
                minimumavailablebitlength = availablebitlength;
            }
        }
        data.put(AVAILABLEBITLENGTHS, availableBitLengths);
        data.put(MINIMUMAVAILABLEBITLENGTH, minimumavailablebitlength);
        data.put(MAXIMUMAVAILABLEBITLENGTH, maximumavailablebitlength);
    }

    public void setAvailableBitLengths(int[] availablebitlengths) {
        List<Integer> availbitlengths = new ArrayList<>(availablebitlengths.length);
        for (int availablebitlength : availablebitlengths) {
            availbitlengths.add(availablebitlength);
        }
        setAvailableBitLengthsAsList(availbitlengths);
    }

    public int getMinimumAvailableBitLength() {
        return (Integer) data.get(MINIMUMAVAILABLEBITLENGTH);
    }

    public int getMaximumAvailableBitLength() {
        return (Integer) data.get(MAXIMUMAVAILABLEBITLENGTH);
    }

    /**
     * Returns true if the given combination of keyAlgorithm/keySpecification is allowed by this certificate profile.
     */
    public boolean isKeyTypeAllowed(final String keyAlgorithm, final String keySpecification) {
        final List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
        final List<Integer> availableBitLengths = getAvailableBitLengthsAsList();
        final List<String> availableEcCurves = getAvailableEcCurvesAsList();
        if (!availableKeyAlgorithms.contains(keyAlgorithm)) {
            return false;
        }
        if (StringUtils.isNumeric(keySpecification)) {
            // keySpecification is a bit length (RSA)
            return availableBitLengths.contains(Integer.parseInt(keySpecification));
        } else if (AlgorithmConstants.KEYALGORITHM_EC.equals(keyAlgorithm) || AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
            // keySpecification is a curve name (EC)
            final boolean anyCurveIsAllowed = availableEcCurves.contains(CertificateProfile.ANY_EC_CURVE);
            final boolean specifiedCurveIsAllowed = availableEcCurves
                    .stream()
                    .anyMatch(AlgorithmTools.getEcKeySpecAliases(keySpecification)::contains);
            return anyCurveIsAllowed || specifiedCurveIsAllowed;
        } else {
            return availableKeyAlgorithms.contains(keyAlgorithm);
        }
    }

    /**
     * Returns the chosen algorithm to be used for signing the certificates or null if it is to be inherited from the CA (i.e., it is the same as the
     * algorithm used to sign the CA certificate).
     *
     * @see com.keyfactor.util.crypto.algorithm.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     * @return JCE identifier for the signature algorithm or null if it is to be inherited from the CA (i.e., it is the same as the algorithm used to
     *         sign the CA certificate).
     */
    public String getSignatureAlgorithm() {
        // If it's null, it is inherited from issuing CA.
        return (String) data.get(SIGNATUREALGORITHM);
    }

    /**
     * Returns the alternative chosen algorithm to be used for signing the certificates or null if it is to be inherited from the CA (i.e., it is the same as the
     * algorithm used to sign the CA certificate).
     *
     * This value is used for alternative key certificates, i.e. quantum safe hybrid certificates containing two keys and signatures
     *
     * @see com.keyfactor.util.crypto.algorithm.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     * @return JCE identifier for the signature algorithm or null if it is to be inherited from the CA (i.e., it is the same as the algorithm used to
     *         sign the CA certificate).
     */
    public String getAlternativeSignatureAlgorithm() {
        // If it's null, it is inherited from issuing CA.
        return (String) data.get(ALTERNATIVE_SIGNATUREALGORITHM);
    }

    /**
     * Sets the algorithm to be used for signing the certificates. A null value means that the signature algorithm is to be inherited from the CA
     * (i.e., it is the same as the algorithm used to sign the CA certificate).
     *
     * @param signAlg
     *            JCE identifier for the signature algorithm or null if it is to be inherited from the CA (i.e., it is the same as the algorithm used
     *            to sign the CA certificate).
     * @see com.keyfactor.util.crypto.algorithm.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     */
    public void setSignatureAlgorithm(String signAlg) {
        data.put(SIGNATUREALGORITHM, signAlg);
    }

    /**
     * Sets the alternate algorithm to be used for signing the certificates. A null value means that the signature algorithm is to be inherited from the CA
     * (i.e., it is the same as the algorithm used to sign the CA certificate).
     *
     * This value is used for alternative key certificates, i.e. quantum safe hybrid certificates containing two keys and signatures
     *
     * @param alternativeSignatureAlgorithm JCE identifier for the signature algorithm or null if it is to be inherited from the CA (i.e., it is the same as the algorithm used
     *            to sign the CA certificate).
     * @see com.keyfactor.util.crypto.algorithm.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     */
    public void setAlternativeSignatureAlgorithm(String alternativeSignatureAlgorithm) {
        data.put(ALTERNATIVE_SIGNATUREALGORITHM, alternativeSignatureAlgorithm);
    }

    public boolean getUseAlternativeSignature() {
        return BooleanUtils.isTrue((Boolean) data.get(USE_ALTERNATIVE_SIGNATURE));
    }

    public void setUseAlternativeSignature(boolean enabled) {
        data.put(USE_ALTERNATIVE_SIGNATURE, enabled);
    }

    public boolean[] getKeyUsage() {
        @SuppressWarnings("unchecked")
        ArrayList<Boolean> keyusage = (ArrayList<Boolean>) data.get(KEYUSAGE);
        boolean[] returnval = new boolean[keyusage.size()];
        for (int i = 0; i < keyusage.size(); i++) {
            returnval[i] = keyusage.get(i);
        }
        return returnval;
    }

    /**
     * @param keyusageconstant
     *            from CertificateConstants.DIGITALSIGNATURE etc
     * @return true or false if the key usage is set or not.
     */
    @SuppressWarnings("unchecked")
    public boolean getKeyUsage(int keyusageconstant) {
        return ((ArrayList<Boolean>) data.get(KEYUSAGE)).get(keyusageconstant);
    }

    public void setKeyUsage(boolean[] keyusage) {
        ArrayList<Boolean> keyuse = new ArrayList<>(keyusage.length);
        for (boolean aKeyusage : keyusage) {
            keyuse.add(aKeyusage);
        }
        data.put(KEYUSAGE, keyuse);
    }

    /**
     * @param keyusageconstant
     *            from CertificateConstants.DIGITALSIGNATURE etc
     * @param value
     *            true or false if the key usage is set or not.
     */
    @SuppressWarnings("unchecked")
    public void setKeyUsage(int keyusageconstant, boolean value) {
        ((ArrayList<Boolean>) data.get(KEYUSAGE)).set(keyusageconstant, value);
    }

    public void setAllowKeyUsageOverride(boolean override) {
        data.put(ALLOWKEYUSAGEOVERRIDE, override);
    }

    public boolean getAllowKeyUsageOverride() {
        return (Boolean) data.get(ALLOWKEYUSAGEOVERRIDE);
    }

    public void setAllowBackdatedRevocation(boolean override) {
        this.data.put(ALLOWBACKDATEDREVOCATION, override);
    }

    public boolean getAllowBackdatedRevocation() {
        final Object value = this.data.get(ALLOWBACKDATEDREVOCATION);
        return value!=null && value instanceof Boolean && (Boolean) value;
    }

    public void setUseDocumentTypeList(boolean use) {
        data.put(USEDOCUMENTTYPELIST, use);
    }

    public boolean getUseDocumentTypeList() {
        return (Boolean) data.get(USEDOCUMENTTYPELIST);
    }

    public void setDocumentTypeListCritical(boolean critical) {
        data.put(DOCUMENTTYPELISTCRITICAL, critical);
    }

    public boolean getDocumentTypeListCritical() {
        return (Boolean) data.get(DOCUMENTTYPELISTCRITICAL);
    }

    public void setDocumentTypeList(ArrayList<String> docTypes) {
        data.put(DOCUMENTTYPELIST, docTypes);
    }

    @SuppressWarnings("unchecked")
    public ArrayList<String> getDocumentTypeList() {
        return (ArrayList<String>) data.get(DOCUMENTTYPELIST);
    }

    public void setUseExtendedKeyUsage(boolean use) {
        data.put(USEEXTENDEDKEYUSAGE, use);
    }

    public boolean getUseExtendedKeyUsage() {
        return (Boolean) data.get(USEEXTENDEDKEYUSAGE);
    }

    public void setExtendedKeyUsageCritical(boolean critical) {
        data.put(EXTENDEDKEYUSAGECRITICAL, critical);
    }

    public boolean getExtendedKeyUsageCritical() {
        return (Boolean) data.get(EXTENDEDKEYUSAGECRITICAL);
    }

    /**
     * Extended Key Usage is an arraylist of oid Strings. Usually oids comes from KeyPurposeId in BC.
     */
    public void setExtendedKeyUsage(ArrayList<String> extendedkeyusage) {
        data.put(EXTENDEDKEYUSAGE, extendedkeyusage);
    }

    /**
     * Extended Key Usage is an arraylist of Strings with eku oids.
     */
    @SuppressWarnings("unchecked")
    public ArrayList<String> getExtendedKeyUsageOids() {
        return (ArrayList<String>) data.get(EXTENDEDKEYUSAGE);
    }
    public void setExtendedKeyUsageOids(final ArrayList<String> extendedKeyUsageOids) {
        setExtendedKeyUsage(extendedKeyUsageOids);
    }

    public void setUseCustomDnOrder(boolean use) {
        data.put(USECUSTOMDNORDER, use);
    }

    public boolean getUseCustomDnOrder() {
        boolean ret = false; // Default value is false here
        Object o = data.get(USECUSTOMDNORDER);
        if (o != null) {
            ret = (Boolean) o;
        }
        return ret;
    }

    /** Set to true if we should apply the rules for LDAP DN Order (separate flag)
     * to the custom DN order
     * @param useldap true or false
     */
    public void setUseCustomDnOrderWithLdap(boolean useldap) {
        data.put(USECUSTOMDNORDERLDAP, useldap);
    }

    /**
     * @return true if we should apply the rules for LDAP DN Order (separate flag), default to false for new usage, where no custom order exists,
     * and to true for old usage to be backward compatible
     */
    public boolean getUseCustomDnOrderWithLdap() {
        boolean ret = true; // Default value is true here
        Object o = data.get(USECUSTOMDNORDERLDAP);
        if (o != null) {
            ret = (Boolean) o;
        } else if (getCustomDnOrder().isEmpty()) {
            // We have not set a value for this checkbox, and we have no custom DN order defined
            // in this case we default to false (new usage)
            ret = false;
        }
        return ret;
    }


    /** Custom DN order is an ArrayList of DN strings
     * @see DnComponents
     * @return ArrayList of Strings or an empty ArrayList
     */
    @SuppressWarnings("unchecked")
    public ArrayList<String> getCustomDnOrder() {
        if (data.get(CUSTOMDNORDER) == null) {
            return new ArrayList<>();
        }
        return (ArrayList<String>) data.get(CUSTOMDNORDER);
    }

    public void setCustomDnOrder(final ArrayList<String> dnOrder) {
        data.put(CUSTOMDNORDER, dnOrder);
    }

    public boolean getUseLdapDnOrder() {
        boolean ret = true; // Default value is true here
        Object o = data.get(USELDAPDNORDER);
        if (o != null) {
            ret = (Boolean) o;
        }
        return ret;
    }

    public void setUseLdapDnOrder(boolean use) {
        data.put(USELDAPDNORDER, use);
    }

    public boolean getUseMicrosoftTemplate() {
        return (Boolean) data.get(USEMICROSOFTTEMPLATE);
    }

    public void setUseMicrosoftTemplate(boolean use) {
        data.put(USEMICROSOFTTEMPLATE, use);
    }

    public boolean getUseMsObjectSidSecurityExtension() {
        return (Boolean) data.get(USE_MS_OBJECTSID_SECURITY_EXTENSION);
    }

    public void setUseMsObjectSidSecurityExtension(boolean use) {
        data.put(USE_MS_OBJECTSID_SECURITY_EXTENSION, use);
    }

    public String getMicrosoftTemplate() {
        return (String) data.get(MICROSOFTTEMPLATE);
    }

    public void setMicrosoftTemplate(String mstemplate) {
        data.put(MICROSOFTTEMPLATE, mstemplate);
    }

    public boolean getUseCardNumber() {
        return (Boolean) data.get(USECARDNUMBER);
    }

    public void setUseCardNumber(boolean use) {
        data.put(USECARDNUMBER, use);
    }

    public boolean getUseCNPostfix() {
        return (Boolean) data.get(USECNPOSTFIX);
    }

    public void setUseCNPostfix(boolean use) {
        data.put(USECNPOSTFIX, use);
    }

    public String getCNPostfix() {
        return (String) data.get(CNPOSTFIX);
    }

    public void setCNPostfix(String cnpostfix) {
        data.put(CNPOSTFIX, cnpostfix);

    }

    public boolean getUseSubjectDNSubSet() {
        return (Boolean) data.get(USESUBJECTDNSUBSET);
    }

    public void setUseSubjectDNSubSet(boolean use) {
        data.put(USESUBJECTDNSUBSET, use);
    }

    /**
     * Returns a List of Integer (DNFieldExtractor constants) indicating which subject dn fields that should be used in certificate.
     *
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getSubjectDNSubSet() {
        return (List<Integer>) data.get(SUBJECTDNSUBSET);
    }

    /**
     * Sets a subset of subject DN fields to use in the certificate.
     *
     * @param subjectDNSubset a list of {@link DNFieldExtractor} constants.
     */
    public void setSubjectDNSubSet(final List<Integer> subjectDNSubset) {
        data.put(SUBJECTDNSUBSET, subjectDNSubset);
    }

    // Method name alias for Configdump
    @SuppressWarnings("unchecked")
    public List<Integer> getSubjectDNSubSets() {
        return (List<Integer>) data.get(SUBJECTDNSUBSET);
    }

    // Method name alias for Configdump
    public void setSubjectDNSubSets(final List<Integer> subjectDns) {
        final List<Integer> subjectDnIds = (subjectDns == null || subjectDns.isEmpty() ? new ArrayList<>() : subjectDns);
        data.put(SUBJECTDNSUBSET, subjectDnIds);
    }

    /**
     * Overridable Extension OIDs is an Set of oid Strings.
     * It is used to list what are the extensions that can be overridden when allow extension override is enabled in the Certificate Profile.
     * @param overridableextensionoids Set of oids (strings), or an empty set, should not be null
     */
    public void setOverridableExtensionOIDs(Set<String> overridableextensionoids) {
        data.put(OVERRIDABLEEXTENSIONOIDS, new LinkedHashSet<>(overridableextensionoids));
    }

    /**
     * Overridable Extension OIDs is an Set of oid Strings.
     * It is used to list what are the extensions that can be overridden when allow extension override is enabled in the Certificate Profile.
     * @return Set of strings containing oids, or an empty set, never null
     */
    @SuppressWarnings("unchecked")
    public Set<String> getOverridableExtensionOIDs() {
        if (data.get(OVERRIDABLEEXTENSIONOIDS) == null) {
            return new LinkedHashSet<>();
        }
        return (Set<String>) data.get(OVERRIDABLEEXTENSIONOIDS);
    }

    /**
     * Non Overridable Extension OIDs is a Set of oid Strings.
     * It is used to list what are the extensions that can not be overridden when allow extension override is enabled in the Certificate Profile..
     * @param nonoverridableextensionoids Set of oids (strings) that are not allowed to be overridden, or empty set to not disallow anything, not null
     */
    public void setNonOverridableExtensionOIDs(Set<String> nonoverridableextensionoids) {
        data.put(NONOVERRIDABLEEXTENSIONOIDS, new LinkedHashSet<>(nonoverridableextensionoids));
    }

    /**
     * Non Overridable Extension OIDs is a Set of oid Strings.
     * It is used to list what are the extensions that can not be overridde when allow extension override is enabled in the Certificate Profile..
     * @return Set of strings containing oids, or an empty set, never null
     */
    @SuppressWarnings("unchecked")
    public Set<String> getNonOverridableExtensionOIDs() {
        if (data.get(NONOVERRIDABLEEXTENSIONOIDS) == null) {
            return new LinkedHashSet<>();
        }
        return (Set<String>) data.get(NONOVERRIDABLEEXTENSIONOIDS);
    }

    /**
     * Method taking a full user dn and returns a DN only containing the DN fields specified in the subjectdn sub set array.
     *
     * @param dn DN
     * @return a subset of original DN
     */

    public String createSubjectDNSubSet(String dn) {
        DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
        return constructUserData(extractor, getSubjectDNSubSet());
    }

    public boolean getUseSubjectAltNameSubSet() {
        return (Boolean) data.get(USESUBJECTALTNAMESUBSET);
    }

    public void setUseSubjectAltNameSubSet(boolean use) {
        data.put(USESUBJECTALTNAMESUBSET, use);
    }

    /**
     * Returns a List of Integer (DNFieldExtractor constants) indicating which subject altnames fields that should be used in certificate.
     *
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getSubjectAltNameSubSet() {
        return (List<Integer>) data.get(SUBJECTALTNAMESUBSET);
    }

    /**
     * Sets a List of Integer (DNFieldExtractor constants) indicating which subject altnames fields that should be used in certificate.
     *
     */
    public void setSubjectAltNameSubSet(List<Integer> subjectaltnames) {
        data.put(SUBJECTALTNAMESUBSET, subjectaltnames);

    }

    /**
     * Method taking a full user dn and returns a AltName only containing the AltName fields specified in the subjectaltname sub set array.
     *
     * @param subjectaltname subject alt name
     * @return a subset of original DN
     */
    public String createSubjectAltNameSubSet(String subjectaltname) {
        DNFieldExtractor extractor = new DNFieldExtractor(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        return constructUserData(extractor, getSubjectAltNameSubSet());
    }

    /**
     * Help method converting a full DN or Subject Alt Name to one usng only specified fields
     *
     * @param extractor extractor
     * @param usefields usefields
     */
    private static String constructUserData(final DNFieldExtractor extractor, final Collection<Integer> usefields) {
        String retval = "";

        if (usefields instanceof List<?>) {
            Collections.sort((List<Integer>) usefields);
        }
        String dnField = null;
        for (Integer next : usefields) {
            dnField = extractor.getFieldString(next);
            if (StringUtils.isNotEmpty(dnField)) {
                if (retval.length() == 0) {
                    retval += dnField; // first item, don't start with a comma
                } else {
                    retval += "," + dnField;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("CertificateProfile: constructed DN or AltName: " + retval);
        }
        return retval;
    }

    /**
     * Get a list of CA IDs indicating which CAs the profile should be applicable to.
     *
     * May contain the constant {@link CAConstants.ALLCAS} to indicate that the
     * profile is applicable to all CAs.
     *
     * @return a list of CA IDs, never null.
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getAvailableCAs() {
        return data.get(AVAILABLECAS) == null
                ? Collections.emptyList()
                : (List<Integer>) data.get(AVAILABLECAS);
    }

    /**
     * Saves the CertificateProfile's list of CAs the cert profile is applicable to.
     *
     * @param availablecas
     *            a List of caids (Integer)
     */

    public void setAvailableCAs(List<Integer> availablecas) {
        data.put(AVAILABLECAS, availablecas);
    }

    @SuppressWarnings("unchecked")
    public boolean isApplicableToAnyCA() {
        return ((List<Integer>) data.get(AVAILABLECAS)).contains(ANYCA);
    }

    /**
     * Returns a List of publisher id's (Integer) indicating which publishers a certificate created with this profile should be published to.
     * Never returns null.
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getPublisherList() {
        Object o = data.get(USEDPUBLISHERS);
        if (o == null) {
            o = new ArrayList<Integer>();
        }
        return (List<Integer>) o;
    }

    /**
     * Saves the CertificateProfile's list of publishers that certificates created with this profile should be published to.
     *
     * @param publishers a List<Integer> of publisher Ids
     */

    public void setPublisherList(List<Integer> publishers) {
        data.put(USEDPUBLISHERS, publishers);
    }

    /**
     * Method indicating that Path Length Constraint should be used in the BasicConstaint
     */
    public boolean getUsePathLengthConstraint() {
        return (Boolean) data.get(USEPATHLENGTHCONSTRAINT);
    }

    /**
     * Method indicating that Path Length Constraint should be used in the BasicConstraint
     */
    public void setUsePathLengthConstraint(boolean use) {
        data.put(USEPATHLENGTHCONSTRAINT, use);
    }

    public int getPathLengthConstraint() {
        return (Integer) data.get(PATHLENGTHCONSTRAINT);
    }

    public void setPathLengthConstraint(int pathlength) {
        data.put(PATHLENGTHCONSTRAINT, pathlength);
    }

    public void setCaIssuers(List<String> caIssuers) {
        data.put(CAISSUERS, caIssuers);
    }

    @SuppressWarnings("unchecked")
    public void addCaIssuer(String caIssuer) {
        caIssuer = caIssuer.trim();
        if (caIssuer.length() < 1) {
            return;
        }
        if (data.get(CAISSUERS) == null) {
            List<String> caIssuers = new ArrayList<>();
            caIssuers.add(caIssuer);
            this.setCaIssuers(caIssuers);
        } else {
            ((List<String>) data.get(CAISSUERS)).add(caIssuer);
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> getCaIssuers() {
        if (data.get(CAISSUERS) == null) {
            return new ArrayList<>();
        } else {
            return (List<String>) data.get(CAISSUERS);
        }
    }

    public void removeCaIssuer(String caIssuer) {
        if (data.get(CAISSUERS) != null) {
            ((List<?>) data.get(CAISSUERS)).remove(caIssuer);
        }
    }

    public boolean getUseOcspNoCheck() {
        return data.get(USEOCSPNOCHECK) != null && (Boolean) data.get(USEOCSPNOCHECK);
    }

    public void setUseOcspNoCheck(boolean useocspnocheck) {
        data.put(USEOCSPNOCHECK, useocspnocheck);
    }

    public boolean getUseAuthorityInformationAccess() {
        return (Boolean) data.get(USEAUTHORITYINFORMATIONACCESS);
    }

    public void setUseAuthorityInformationAccess(boolean useauthorityinformationaccess) {
        data.put(USEAUTHORITYINFORMATIONACCESS, useauthorityinformationaccess);
    }

    public boolean getUseDefaultCAIssuer() {
        // Lazy instantiation in case upgrade for some reason fails
        data.putIfAbsent(USEDEFAULTCAISSUER, false);
        return (Boolean) data.get(USEDEFAULTCAISSUER);
    }

    public void setUseDefaultCAIssuer(boolean usedefaultcaissuer) {
        data.put(USEDEFAULTCAISSUER, usedefaultcaissuer);
    }

    public boolean getUseDefaultOCSPServiceLocator() {
        return (Boolean) data.get(USEDEFAULTOCSPSERVICELOCATOR);
    }

    public void setUseDefaultOCSPServiceLocator(boolean usedefaultocspservicelocator) {
        data.put(USEDEFAULTOCSPSERVICELOCATOR, usedefaultocspservicelocator);
    }

    public String getOCSPServiceLocatorURI() {
        return (String) data.get(OCSPSERVICELOCATORURI);
    }

    public void setOCSPServiceLocatorURI(String ocspservicelocatoruri) {
        if (ocspservicelocatoruri == null) {
            data.put(OCSPSERVICELOCATORURI, "");
        } else {
            data.put(OCSPSERVICELOCATORURI, ocspservicelocatoruri);
        }
    }

    public String getDescription() {
        return (String) data.get(DESCRIPTION);
    }

    public void setDescription(String description) {
        if (description == null) {
            data.put(DESCRIPTION, "");
        } else {
            data.put(DESCRIPTION, description);
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getEabNamespaces() {
        if (data.get(EABNAMESPACES) == null) {
            return new LinkedHashSet<>();
        }
        return (Set<String>) data.get(EABNAMESPACES);
    }

    public void setEabNamespaces(Set<String> eabNamespaces) {
        if (eabNamespaces == null) {
            data.put(EABNAMESPACES, new LinkedHashSet<>());
        } else {
            data.put(EABNAMESPACES, new LinkedHashSet<>(eabNamespaces));
        }
    }

    public boolean getUseQCStatement() {
        return (Boolean) data.get(USEQCSTATEMENT);
    }

    public void setUseQCStatement(boolean useqcstatement) {
        data.put(USEQCSTATEMENT, useqcstatement);
    }

    public boolean getUsePkixQCSyntaxV2() {
        return (Boolean) data.get(USEPKIXQCSYNTAXV2);
    }

    public void setUsePkixQCSyntaxV2(boolean pkixqcsyntaxv2) {
        data.put(USEPKIXQCSYNTAXV2, pkixqcsyntaxv2);
    }

    public boolean getQCStatementCritical() {
        return (Boolean) data.get(QCSTATEMENTCRITICAL);
    }

    public void setQCStatementCritical(boolean qcstatementcritical) {
        data.put(QCSTATEMENTCRITICAL, qcstatementcritical);
    }

    /** @return String with RAName or empty string */
    public String getQCStatementRAName() {
        return (String) data.get(QCSTATEMENTRANAME);
    }

    public void setQCStatementRAName(String qcstatementraname) {
        if (qcstatementraname == null) {
            data.put(QCSTATEMENTRANAME, "");
        } else {
            data.put(QCSTATEMENTRANAME, qcstatementraname);
        }
    }

    /** @return String with semicolon separated list of SemanticsIds or empty string */
    public String getQCSemanticsIds() {
        return (String) data.get(QCSSEMANTICSID);
    }

    public void setQCSemanticsIds(String qcsemanticsid) {
        if (qcsemanticsid == null) {
            data.put(QCSSEMANTICSID, "");
        } else {
            data.put(QCSSEMANTICSID, qcsemanticsid);
        }
    }

    public boolean getUseQCEtsiQCCompliance() {
        return (Boolean) data.get(USEQCETSIQCCOMPLIANCE);
    }

    public void setUseQCEtsiQCCompliance(boolean useqcetsiqccompliance) {
        data.put(USEQCETSIQCCOMPLIANCE, useqcetsiqccompliance);
    }

    public boolean getUseQCEtsiValueLimit() {
        return (Boolean) data.get(USEQCETSIVALUELIMIT);
    }

    public void setUseQCEtsiValueLimit(boolean useqcetsivaluelimit) {
        data.put(USEQCETSIVALUELIMIT, useqcetsivaluelimit);
    }

    public int getQCEtsiValueLimit() {
        return (Integer) data.get(QCETSIVALUELIMIT);
    }

    public void setQCEtsiValueLimit(int qcetsivaluelimit) {
        data.put(QCETSIVALUELIMIT, qcetsivaluelimit);
    }

    public int getQCEtsiValueLimitExp() {
        return (Integer) data.get(QCETSIVALUELIMITEXP);
    }

    public void setQCEtsiValueLimitExp(int qcetsivaluelimitexp) {
        data.put(QCETSIVALUELIMITEXP, qcetsivaluelimitexp);
    }

    /** @return String with Currency or empty string */
    public String getQCEtsiValueLimitCurrency() {
        return (String) data.get(QCETSIVALUELIMITCURRENCY);
    }

    public void setQCEtsiValueLimitCurrency(String qcetsivaluelimitcurrency) {
        if (qcetsivaluelimitcurrency == null) {
            data.put(QCETSIVALUELIMITCURRENCY, "");
        } else {
            data.put(QCETSIVALUELIMITCURRENCY, qcetsivaluelimitcurrency);
        }
    }

    public boolean getUseQCEtsiRetentionPeriod() {
        return (Boolean) data.get(USEQCETSIRETENTIONPERIOD);
    }

    public void setUseQCEtsiRetentionPeriod(boolean useqcetsiretentionperiod) {
        data.put(USEQCETSIRETENTIONPERIOD, useqcetsiretentionperiod);
    }

    public int getQCEtsiRetentionPeriod() {
        return (Integer) data.get(QCETSIRETENTIONPERIOD);
    }

    public void setQCEtsiRetentionPeriod(int qcetsiretentionperiod) {
        data.put(QCETSIRETENTIONPERIOD, qcetsiretentionperiod);
    }

    public boolean getUseQCEtsiSignatureDevice() {
        return (Boolean) data.get(USEQCETSISIGNATUREDEVICE);
    }

    public void setUseQCEtsiSignatureDevice(boolean useqcetsisignaturedevice) {
        data.put(USEQCETSISIGNATUREDEVICE, useqcetsisignaturedevice);
    }

    /** @return String with Type OID or null (or empty string) if it's not to be used (EN 319 412-05)
     * 0.4.0.1862.1.6.1 = id-etsi-qct-esign
     * 0.4.0.1862.1.6.2 = id-etsi-qct-eseal
     * 0.4.0.1862.1.6.3 = id-etsi-qct-web
     */
    public String getQCEtsiType() {
        return (String) data.get(QCETSITYPE);
    }
    public void setQCEtsiType(String qcetsitype) {
        data.put(QCETSITYPE, qcetsitype);
    }

    /**
     * Returns the PKI Disclosure Statements (EN 319 412-05) used in this profile, or null if none are present.
     */
    @SuppressWarnings("unchecked")
    public List<PKIDisclosureStatement> getQCEtsiPds() {
        List<PKIDisclosureStatement> result = null;
        List<PKIDisclosureStatement> pdsList = (List<PKIDisclosureStatement>)data.get(QCETSIPDS);
        if (pdsList != null && !pdsList.isEmpty()) {
            result = new ArrayList<>(pdsList.size());
            try {
                for (final PKIDisclosureStatement pds : pdsList) {
                    result.add((PKIDisclosureStatement) pds.clone());
                }
            } catch (CloneNotSupportedException e) {
                throw new IllegalStateException(e);
            }
        }
        return result;
    }

    /**
     * Sets the PKI Disclosure Statements (EN 319 412-05).
     * Both null and empty lists are interpreted as an "none".
     */
    public void setQCEtsiPds(final List<PKIDisclosureStatement> pds) {
        if (pds == null || pds.isEmpty()) { // never store an empty list
            data.put(QCETSIPDS, null);
        } else {
            data.put(QCETSIPDS, new ArrayList<>(pds));
        }
        // Remove old data from EJBCA < 6.6.1
        data.remove(QCETSIPDSURL);
        data.remove(QCETSIPDSLANG);
    }

    /**
     * @return true if the PSD2 QC statement should be included, or false (default) if it should not
     */
    public boolean getUseQCPSD2() {
        Boolean ret = ((Boolean) data.get(USEQCPSD2));
        // default value
        return ret != null && ret;
    }

    public void setUseQCPSD2(boolean useqcpsd2) {
        data.put(USEQCPSD2, useqcpsd2);
    }

    public boolean getUseQCCountries() {
        return (Boolean) data.get(USEQCCOUNTRIES);
    }

    public void setUseQCCountries(boolean useqccountriesstring) {
        data.put(USEQCCOUNTRIES, useqccountriesstring);
    }

    public String getQCCountriesString() {
        return (String) data.get(QCCOUNTRIESSTRING);
    }

    public void setQCCountriesString(String iso3166_2_list) {
        if (iso3166_2_list == null) {
            data.put(QCCOUNTRIESSTRING, "");
        } else {
            data.put(QCCOUNTRIESSTRING, iso3166_2_list);
        }
    }

    public boolean getUseQCCustomString() {
        return (Boolean) data.get(USEQCCUSTOMSTRING);
    }

    public void setUseQCCustomString(boolean useqccustomstring) {
        data.put(USEQCCUSTOMSTRING, useqccustomstring);
    }

    /** @return String with oid or empty string */
    public String getQCCustomStringOid() {
        return (String) data.get(QCCUSTOMSTRINGOID);
    }

    public void setQCCustomStringOid(String qccustomstringoid) {
        if (qccustomstringoid == null) {
            data.put(QCCUSTOMSTRINGOID, "");
        } else {
            data.put(QCCUSTOMSTRINGOID, qccustomstringoid);
        }
    }

    /** @return String with custom text or empty string */
    public String getQCCustomStringText() {
        return (String) data.get(QCCUSTOMSTRINGTEXT);
    }

    public void setQCCustomStringText(String qccustomstringtext) {
        if (qccustomstringtext == null) {
            data.put(QCCUSTOMSTRINGTEXT, "");
        } else {
            data.put(QCCUSTOMSTRINGTEXT, qccustomstringtext);
        }
    }

    /**
     * @return true if the CA/B Forum Organization Identifier extension should be included, or false (default) if it should not
     */
    public boolean getUseCabfOrganizationIdentifier() {
        Boolean ret = ((Boolean) data.get(USECABFORGANIZATIONIDENTIFIER));
        if (ret == null) {
            return false; // default value
        }
        return ret;
    }

    public void setUseCabfOrganizationIdentifier(boolean use) {
        data.put(USECABFORGANIZATIONIDENTIFIER, use);
    }

    public boolean getUseNameConstraints() {
        Boolean b = (Boolean) data.get(USENAMECONSTRAINTS);
        return b != null && b;
    }

    public void setUseNameConstraints(boolean use) {
        data.put(USENAMECONSTRAINTS, use);
    }

    public boolean getNameConstraintsCritical() {
        Boolean b = (Boolean) data.get(NAMECONSTRAINTSCRITICAL);
        return b != null && b;
    }

    public void setNameConstraintsCritical(boolean use) {
        data.put(NAMECONSTRAINTSCRITICAL, use);
    }

    public boolean getUseSubjectDirAttributes() {
        return (Boolean) data.get(USESUBJECTDIRATTRIBUTES);
    }

    public void setUseSubjectDirAttributes(boolean use) {
        data.put(USESUBJECTDIRATTRIBUTES, use);
    }

    public void setSingleActiveCertificateConstraint(final boolean enabled) {
        data.put(USERSINGLEACTIVECERTIFICATECONSTRAINT, enabled);
    }

    public boolean isSingleActiveCertificateConstraint() {
        Object constraintObject = data.get(USERSINGLEACTIVECERTIFICATECONSTRAINT);
        if(constraintObject == null) {
            //For upgrading from versions prior to 6.3.1
            setSingleActiveCertificateConstraint(false);
            return false;
        } else {
            return (Boolean) data.get(USERSINGLEACTIVECERTIFICATECONSTRAINT);
        }
    }

    /**
     * Returns which type of terminals are used in this ca/certificate hierarchy.
     * The values correspond to the id-roles-1/2/3 OIDs.
     */
    public int getCVCTerminalType() {
        if (data.get(CVCTERMINALTYPE) == null) {
            return CertificateProfile.CVC_TERMTYPE_IS;
        }
        return (Integer) data.get(CVCTERMINALTYPE);
    }

    public void setCVCTerminalType(int termtype) {
        data.put(CVCTERMINALTYPE, termtype);
    }

    public boolean isCvcTerminalTypeIs() { return getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_IS; }
    public boolean isCvcTerminalTypeAt() { return getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_AT; }
    public boolean isCvcTerminalTypeSt() { return getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_ST; }

    public int getCVCAccessRights() {
        if (data.get(CVCACCESSRIGHTS) == null) {
            return CertificateProfile.CVC_ACCESS_NONE;
        }
        return (Integer) data.get(CVCACCESSRIGHTS);
    }

    public void setCVCAccessRights(int access) {
        data.put(CVCACCESSRIGHTS, access);
    }

    // Method name alias for Configdump
    public int getCVCAccessRightsIS() {
        return getCVCAccessRights();
    }

    // Method name alias for Configdump
    public void setCVCAccessRightsIS(int access) {
        setCVCAccessRights(access);
    }

    // Method name alias for Configdump
    public int getCVCAccessRightsST() {
        return getCVCAccessRights();
    }

    // Method name alias for Configdump
    public void setCVCAccessRightsST(int access) {
        setCVCAccessRights(access);
    }

    /**
     * Used for bitmasks that don't fit in an int.
     * E.g. the 5-byte bitmask for Authentication Terminals
     */
    public byte[] getCVCLongAccessRights() {
        if (data.get(CVCLONGACCESSRIGHTS) == null) {
            return null;
        }
        @SuppressWarnings("unchecked")
        List<Byte> rightsList = (List<Byte>)data.get(CVCLONGACCESSRIGHTS);
        return ArrayUtils.toPrimitive(rightsList.toArray(new Byte[0]));
    }

    public void setCVCLongAccessRights(byte[] access) {
        if (access == null) {
            data.put(CVCLONGACCESSRIGHTS, null);
        } else {
            // Convert to List<Byte> since byte[] doesn't work with database protection
            data.put(CVCLONGACCESSRIGHTS, new ArrayList<>(Arrays.asList(ArrayUtils.toObject(access))));
        }
    }

    public int getCVCSignTermDVType() {
        if (data.get(CVCSIGNTERMDVTYPE) == null) {
            return CertificateProfile.CVC_SIGNTERM_DV_CSP;
        }
        return (Integer) data.get(CVCSIGNTERMDVTYPE);
    }

    public void setCVCSignTermDVType(int type) {
        data.put(CVCSIGNTERMDVTYPE, type);
    }

    /**
     * Method returning a list of (Integers) of ids of used CUSTOM certificate extensions. I.e. those custom certificate extensions selected for this
     * profile. Never null.
     *
     * Autoupgradable method
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getUsedCertificateExtensions() {
        if (data.get(USEDCERTIFICATEEXTENSIONS) == null) {
            return new ArrayList<>();
        }
        return (List<Integer>) data.get(USEDCERTIFICATEEXTENSIONS);
    }

    /**
     * Method setting a list of used certificate extensions a list of Integers containing CertificateExtension Id is expected
     *
     * @param usedCertificateExtensions used certificate extensions
     */
    public void setUsedCertificateExtensions(List<Integer> usedCertificateExtensions) {
        if (usedCertificateExtensions == null) {
            data.put(USEDCERTIFICATEEXTENSIONS, new ArrayList<>());
        } else {
            data.put(USEDCERTIFICATEEXTENSIONS, usedCertificateExtensions);
        }
    }

    /**
     * Function that looks up in the profile all certificate extensions that we should use if the value is that we should use it, the oid for this
     * extension is returned in the list
     *
     * @return List of oid Strings for standard certificate extensions that should be used
     */
    public List<String> getUsedStandardCertificateExtensions() {
        ArrayList<String> ret = new ArrayList<>();
        for (String s : useStandardCertificateExtensions.keySet()) {
            if ((data.get(s) != null) && (Boolean) data.get(s)) {
                ret.add(useStandardCertificateExtensions.get(s));
                if (log.isDebugEnabled()) {
                    log.debug("Using standard certificate extension: " + s);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Not using standard certificate extensions: " + s);
                }
            }
        }
        return ret;
    }

    /** Returns the names of all allowed built-in extensions in the profile. The keys are used in the ExtendedInformation class. */
    public Set<String> getUsedStandardCertificateExtensionKeys() {
        final Set<String> ret = new LinkedHashSet<>();
        for (final String key : useStandardCertificateExtensions.keySet()) {
            if (data.get(key) != null && (Boolean) data.get(key)) {
                // All extension use keys in the Certificate Profile are named "use" + name of extension
                ret.add(StringUtils.removeStart(key, "use"));
            }
        }
        return ret;
    }

    /** Returns the names of all supported (i.e. not only used) built-in certificate extensions. The keys are used in the ExtendedInformation class. */
    public static Set<String> getAllStandardCertificateExtensionKeys() {
        final Set<String> ret = new LinkedHashSet<>();
        for (final String key : useStandardCertificateExtensions.keySet()) {
            // All extension use keys in the Certificate Profile are named "use" + name of extension
            ret.add(StringUtils.removeStart(key, "use"));
        }
        return ret;
    }

    /**
     * @return a List of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals, default none, never null
     *
     * @deprecated since 6.8.0. Use getApprovals() instead;
     */
    @SuppressWarnings("unchecked")
    @Deprecated
    public List<Integer> getApprovalSettings() {
        List<Integer> approvalSettings = (List<Integer>) data.get(APPROVALSETTINGS);
        if (approvalSettings != null) {
            return approvalSettings;
        } else {
            return new ArrayList<>();
        }
    }

    /**
     * List of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals
     *
     * @deprecated since 6.8.0. Use setApprovals() instead;
     */
    @Deprecated
    public void setApprovalSettings(List<Integer> approvalSettings) {
        data.put(APPROVALSETTINGS, approvalSettings);
    }

    /**
     * Returns the number of different administrators that needs to approve an action, default 1.
     *
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    public int getNumOfReqApprovals() {
        Integer result = (Integer) data.get(NUMOFREQAPPROVALS);
        if(result != null) {
            return result;
        } else {
            return 1;
        }
    }

    /**
     * The number of different administrators that needs to approve
     *
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    public void setNumOfReqApprovals(int numOfReqApprovals) {
        data.put(NUMOFREQAPPROVALS, numOfReqApprovals);
    }

    /**
     * @return the id of the approval profile. ID -1 means  that no approval profile was set
     *
     * @deprecated since 6.8.0. Use getApprovals() instead;
     */
    @Deprecated
    public int getApprovalProfileID() {
        Integer approvalProfileId = (Integer) data.get(APPROVALPROFILE);
        if(approvalProfileId != null) {
            return approvalProfileId;
        } else {
            return -1;
        }
    }

    /**
     * Sets the ID of an approval profile
     * @deprecated since 6.8.0. Use setApprovals() instead;
     */
    @Deprecated
    public void setApprovalProfileID(int approvalProfileID) {
        data.put(APPROVALPROFILE, approvalProfileID);
    }

    public void setApprovals(Map<ApprovalRequestType, Integer> approvals) {
        if(approvals == null) {
            approvals = new LinkedHashMap<>();
        }
        // We must store this as a predictable order map in the database, in order for databaseprotection to work
        data.put(APPROVALS, new LinkedHashMap<>(approvals));
    }

    /**
     * @return a map of approvals, mapped as approval setting (as defined in this class) : approval profile ID. Never returns null.
     */
    @SuppressWarnings("unchecked")
    public Map<ApprovalRequestType, Integer> getApprovals() {
        if (data.get(APPROVALS) == null) {
            Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
            int approvalProfileId = getApprovalProfileID();
            if(approvalProfileId != -1) {
                for(int approvalSetting : getApprovalSettings()) {
                    approvals.put(ApprovalRequestType.getFromIntegerValue(approvalSetting), approvalProfileId);
                }
            }
            setApprovals(approvals);
        }
        return (Map<ApprovalRequestType, Integer>) data.get(APPROVALS);
    }

    /**
     * @return If the PrivateKeyUsagePeriod extension should be used and with the notBefore component.
     */
    public boolean isUsePrivateKeyUsagePeriodNotBefore() {
        return data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) != null && (Boolean) data.get(USEPRIVKEYUSAGEPERIODNOTBEFORE);
    }

    /**
     * Sets if the PrivateKeyUsagePeriod extension should be used and with
     * the notBefore component.
     * Setting this to true means that there will be an PrivateKeyUsagePeriod
     * extension and that it also at least will contain an notBefore component.
     * Setting this to false means that the extension will not contain an
     * notBefore component. In that case if there will be an extension depends
     * on if {@link #isUsePrivateKeyUsagePeriodNotAfter()} is true.
     *
     * @param use True if the notBefore component should be used.
     */
    public void setUsePrivateKeyUsagePeriodNotBefore(final boolean use) {
            data.put(USEPRIVKEYUSAGEPERIODNOTBEFORE, use);
            data.put(USEPRIVKEYUSAGEPERIOD, use || isUsePrivateKeyUsagePeriodNotAfter());
    }

    /**
     * @return If the PrivateKeyUsagePeriod extension should be used and with the notAfter component.
     */
    public boolean isUsePrivateKeyUsagePeriodNotAfter() {
        return data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) != null && (Boolean) data.get(USEPRIVKEYUSAGEPERIODNOTAFTER);
    }

    /**
     * Sets if the PrivateKeyUsagePeriod extension should be used and with
     * the notAfter component.
     * Setting this to true means that there will be an PrivateKeyUsagePeriod
     * extension and that it also at least will contain an notAfter component.
     * Setting this to false means that the extension will not contain an
     * notAfter component. In that case if there will be an extension depends
     * on if {@link #isUsePrivateKeyUsagePeriodNotBefore()} is true.
     *
     * @param use True if the notAfter component should be used.
     */
    public void setUsePrivateKeyUsagePeriodNotAfter(final boolean use) {
        data.put(USEPRIVKEYUSAGEPERIODNOTAFTER, use);
        data.put(USEPRIVKEYUSAGEPERIOD, use || isUsePrivateKeyUsagePeriodNotBefore());
    }

    /**
     * @return How long (in seconds) after the certificate's notBefore date the
     * PrivateKeyUsagePeriod's notBefore date should be.
     */
    public long getPrivateKeyUsagePeriodStartOffset() {
        return (Long) data.get(PRIVKEYUSAGEPERIODSTARTOFFSET);
    }

    /**
     * Sets how long (in seconds) after the certificate's notBefore date the PrivateKeyUsagePeriod's notBefore date should be.
     *
     * @param start Offset from certificate issuance.
     */
    public void setPrivateKeyUsagePeriodStartOffset(final long start) {
        data.put(PRIVKEYUSAGEPERIODSTARTOFFSET, start);
    }

    /**
     * @return The private key usage period (private key validity) length (in seconds).
     */
    public long getPrivateKeyUsagePeriodLength() {
        return (Long) data.get(PRIVKEYUSAGEPERIODLENGTH);
    }

    /**
     * Sets the private key usage period (private key validity) length (in seconds).
     *
     * @param validity The length.
     */
    public void setPrivateKeyUsagePeriodLength(final long validity) {
        data.put(PRIVKEYUSAGEPERIODLENGTH, validity);
    }

    /**
     * Whether Certificate Transparency (CT) should be used when generating new certificates. CT is specified in RFC 6962
     */
    public boolean isUseCertificateTransparencyInCerts() {
        return data.get(USECERTIFICATETRANSPARENCYINCERTS) != null && (Boolean) data.get(USECERTIFICATETRANSPARENCYINCERTS);
    }

    public void setUseCertificateTransparencyInCerts(boolean use) {
        data.put(USECERTIFICATETRANSPARENCYINCERTS, use);
    }

    /**
     * Whether Certificate Transparency (CT) should be used in OCSP responses. CT is specified in RFC 6962
     */
    public boolean isUseCertificateTransparencyInOCSP() {
        return data.get(USECERTIFICATETRANSPARENCYINOCSP) != null && (Boolean) data.get(USECERTIFICATETRANSPARENCYINOCSP);
    }

    public void setUseCertificateTransparencyInOCSP(boolean use) {
        data.put(USECERTIFICATETRANSPARENCYINOCSP, use);
    }

    /**
     * Whether Certificate Transparency (CT) should be used in publishers.
     * You have to create a publisher and enable it in the profile also!
     */
    public boolean isUseCertificateTransparencyInPublishers() {
        if (data.get(USECERTIFICATETRANSPARENCYINPUBLISHERS) == null) {
            // Default to being enabled if CT in OCSP was enabled
            return isUseCertificateTransparencyInOCSP();
        }
        return (Boolean) data.get(USECERTIFICATETRANSPARENCYINPUBLISHERS);
    }

    public void setUseCertificateTransparencyInPublishers(boolean use) {
        data.put(USECERTIFICATETRANSPARENCYINPUBLISHERS, use);
    }

    public boolean isCtEnabled() {
        return isUseCertificateTransparencyInCerts() ||
            isUseCertificateTransparencyInOCSP() ||
            isUseCertificateTransparencyInPublishers();
    }

    public boolean isNumberOfSctByValidity() {
        if (data.get(CT_NUMBER_OF_SCTS_BY_VALIDITY) == null) {
            // Default value
            return true;
        }
        return (Boolean)data.get(CT_NUMBER_OF_SCTS_BY_VALIDITY);
    }

    public void setNumberOfSctByValidity(boolean use) {
        data.put(CT_NUMBER_OF_SCTS_BY_VALIDITY, use);
    }

    public boolean isNumberOfSctByCustom() {
        if (data.get(CT_NUMBER_OF_SCTS_BY_CUSTOM) == null) {
            // Default value
            return false;
        }
        return (Boolean)data.get(CT_NUMBER_OF_SCTS_BY_CUSTOM);
    }

    public void setNumberOfSctByCustom(boolean use) {
        data.put(CT_NUMBER_OF_SCTS_BY_CUSTOM, use);
    }

    public String getNumberOfSctBy() {
        if (isNumberOfSctByValidity()) {
            return CT_NUMBER_OF_SCTS_BY_VALIDITY;
        }
        return CT_NUMBER_OF_SCTS_BY_CUSTOM;
    }

    public void setNumberOfSctBy(String choice) {
        if (CT_NUMBER_OF_SCTS_BY_VALIDITY.equals(choice)) {
            setNumberOfSctByValidity(true);
            setNumberOfSctByCustom(false);
        } else {
            setNumberOfSctByValidity(false);
            setNumberOfSctByCustom(true);
        }
    }

    public String getMaxNumberOfSctBy() {
        if (isMaxNumberOfSctByValidity()) {
            return CT_NUMBER_OF_SCTS_BY_VALIDITY;
        }
        return CT_NUMBER_OF_SCTS_BY_CUSTOM;
    }

    public void setMaxNumberOfSctBy(String choice) {
        if (CT_NUMBER_OF_SCTS_BY_VALIDITY.equals(choice)) {
            setMaxNumberOfSctByValidity(true);
            setMaxNumberOfSctByCustom(false);
        } else {
            setMaxNumberOfSctByValidity(false);
            setMaxNumberOfSctByCustom(true);
        }
    }

    public boolean isMaxNumberOfSctByValidity() {
        if (data.get(CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY) == null) {
            // Default value
            return false;
        }
        return (Boolean)data.get(CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY);
    }

    public void setMaxNumberOfSctByValidity(boolean use) {
        data.put(CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY, use);
    }

    public boolean isMaxNumberOfSctByCustom() {
        if (data.get(CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM) == null) {
            // Default value
            return true;
        }
        return (Boolean)data.get(CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM);
    }

    public void setMaxNumberOfSctByCustom(boolean use) {
        data.put(CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM, use);
    }

    /**
     * Whether existing certificates should be submitted by the CT publisher and the CT OCSP extension class.
     */
    public boolean isUseCTSubmitExisting() {
        return data.get(CTSUBMITEXISTING) == null || (Boolean) data.get(CTSUBMITEXISTING);
    }

    public void setUseCTSubmitExisting(boolean use) {
        data.put(CTSUBMITEXISTING, use);
    }

    /**
     * Gets the IDs of the CT logs that are activated in this profile.
     */
    @SuppressWarnings("unchecked")
    @Deprecated
    public Set<Integer> getEnabledCTLogs() {
        if (data.get(CTLOGS) == null) {
            return new LinkedHashSet<>();
        }

        return (Set<Integer>)data.get(CTLOGS);
    }

    /** Sets the enabled CT logs. NOTE: The argument must be a LinkedHashSet, since order is important */
    @Deprecated
    public void setEnabledCTLogs(LinkedHashSet<Integer> logIds) {
        data.put(CTLOGS, new LinkedHashSet<>(logIds));
    }

    @SuppressWarnings("unchecked")
    public Set<String> getEnabledCtLabels() {
        if (data.get(CTLABELS) == null) {
            return new LinkedHashSet<>();
        }
        return (Set<String>)data.get(CTLABELS);
    }

    public void setEnabledCtLabels(final Set<String> ctLabels) {
        data.put(CTLABELS, new LinkedHashSet<>(ctLabels));
    }

    /**
     * <p>Number of CT logs to require an SCT from, or it will be considered an error. If zero, CT is completely optional and
     * ignored if no log servers can be contacted.</p>
     * <p>This value is used for certificates and publishers. For OCSP responses, @see CertificateProfile#getCtMinTotalSctsOcsp
     * <p>
     * @return the total number of SCTs required
     */
    @Deprecated
    public int getCtMinTotalScts() {
        if (data.get(CT_MIN_TOTAL_SCTS) == null) {
            return 0; // setting is OFF
        }
        return (Integer) data.get(CT_MIN_TOTAL_SCTS);
    }

    /** @param value minimum number of SCTs required in total */
    @Deprecated
    public void setCtMinTotalScts(int value) {
        data.put(CT_MIN_TOTAL_SCTS, value);
    }

    /** @see CertificateProfile#getCtMinTotalScts */
    @Deprecated
    public int getCtMinTotalSctsOcsp() {
        if (data.get(CT_MIN_TOTAL_SCTS_OCSP) == null) {
            return getCtMinTotalScts();
        }
        return (Integer) data.get(CT_MIN_TOTAL_SCTS_OCSP);
    }

    /** @param value minimum number of SCTs for OCSP responses required in total */
    @Deprecated
    public void setCtMinTotalSctsOcsp(int value) {
        data.put(CT_MIN_TOTAL_SCTS_OCSP, value);
    }

    /**
     * <p>Number of SCTs retrieved after which we will stop contacting non-mandatory log servers.</p>
     * @return the maximum number of non-mandatory SCTs
     */
    @Deprecated
    public int getCtMaxNonMandatoryScts() {
        if (data.get(CT_MAX_NONMANDATORY_SCTS) == null) {
            if (data.get(CT_MAX_SCTS) == null) {
                log.info("CT_MAX_NON_MANDATORY_SCTS is null => legacy value is also null, using 1 log as default.");
                return 1;
            }
            log.info("CT_MAX_NON_MANDATORY_SCTS is null => using legacy value: " + data.get(CT_MAX_SCTS));
            return (Integer) data.get(CT_MAX_SCTS);
        }
        return (Integer) data.get(CT_MAX_NONMANDATORY_SCTS);
    }

    /** @param value the maximum number of non-mandatory SCTs */
    @Deprecated
    public void setCtMaxNonMandatoryScts(int value) {
        data.put(CT_MAX_NONMANDATORY_SCTS, value);
    }

    /** @see CertificateProfile#getCtMaxNonMandatoryScts */
    @Deprecated
    public int getCtMaxNonMandatorySctsOcsp() {
        if (data.get(CT_MAX_NONMANDATORY_SCTS_OCSP) == null) {
            if (data.get(CT_MAX_SCTS_OCSP) == null) {
                log.info("CT_MAX_NON_MANDATORY_SCTS_OCSP is null => legacy value is also null, using 1 log as default.");
                return 1;
            }
            log.info("CT_MAX_NON_MANDATORY_SCTS_OCSP is null => using legacy value: " + data.get(CT_MAX_SCTS_OCSP));
            return (Integer) data.get(CT_MAX_SCTS_OCSP);
        }
        return (Integer) data.get(CT_MAX_NONMANDATORY_SCTS_OCSP);
    }

    /** @param value maximum value number of non-mandatory SCTs for OCSP responses */
    @Deprecated
    public void setCtMaxNonMandatorySctsOcsp(int value) {
        data.put(CT_MAX_NONMANDATORY_SCTS_OCSP, value);
    }

    /**
     * <p>Number of CT logs marked as "not mandatory" to require an SCT from, or it will be considered an error. Default is zero logs.</p>
     * <p>For publishers, certificates are submitted to all enabled logs.</p>
     */
    @Deprecated
    public int getCtMinNonMandatoryScts() {
        if (data.get(CT_MIN_NONMANDATORY_SCTS) == null) {
            return getCtMinTotalScts();
        }
        return (Integer) data.get(CT_MIN_NONMANDATORY_SCTS);
    }

    /** @param value minimum number of non-mandatory SCTs */
    @Deprecated
    public void setCtMinNonMandatoryScts(int value) {
        data.put(CT_MIN_NONMANDATORY_SCTS, value);
    }

    /** @see CertificateProfile#getCtMinNonMandatoryScts */
    @Deprecated
    public int getCtMinNonMandatorySctsOcsp() {
        if (data.get(CT_MIN_NONMANDATORY_SCTS_OCSP) == null) {
            return getCtMinNonMandatoryScts();
        }
        return (Integer) data.get(CT_MIN_NONMANDATORY_SCTS_OCSP);
    }

    /** @param value minimum number of non-mandatory SCTs */
    @Deprecated
    public void setCtMinNonMandatorySctsOcsp(int value) {
        data.put(CT_MIN_NONMANDATORY_SCTS_OCSP, value);
    }

    public int getCtMinScts() {
        if (data.get(CT_SCTS_MIN) == null) {
            return getCtMinTotalScts();
        }
        return (Integer) data.get(CT_SCTS_MIN);
    }

    public void setCtMinScts(int value) {
        data.put(CT_SCTS_MIN, value);
    }

    public int getCtMaxScts() {
        if (data.get(CT_SCTS_MAX) == null) {
            return getCtMinTotalScts();
        }
        return (Integer) data.get(CT_SCTS_MAX);
    }

    public void setCtMaxScts(int value) {
        data.put(CT_SCTS_MAX, value);
    }

    public int getCtMinSctsOcsp() {
        if (data.get(CT_SCTS_MIN_OCSP) == null) {
            return getCtMinTotalScts();
        }
        return (Integer) data.get(CT_SCTS_MIN_OCSP);
    }

    public void setCtMinSctsOcsp(int value) {
        data.put(CT_SCTS_MIN_OCSP, value);
    }

    public int getCtMaxSctsOcsp() {
        if (data.get(CT_SCTS_MAX_OCSP) == null) {
            return getCtMinTotalScts();
        }
        return (Integer) data.get(CT_SCTS_MAX_OCSP);
    }

    public void setCtMaxSctsOcsp(int value) {
        data.put(CT_SCTS_MAX_OCSP, value);
    }


    /** Number of times to retry connecting to a Certificate Transparency log */
    public int getCTMaxRetries() {
        if (data.get(CTMAXRETRIES) == null) {
            return 0;
        }
        return (Integer)data.get(CTMAXRETRIES);
    }

    public void setCTMaxRetries(int numRetries) {
        data.put(CTMAXRETRIES, numRetries);
    }

    /** SSH Getters & Setters */
    public SshCertificateType getSshCertificateType() {
        data.putIfAbsent(SSH_CERTIFICATE_TYPE, SshCertificateType.USER);
        return (SshCertificateType) data.get(SSH_CERTIFICATE_TYPE);
    }

    public void setSshCertificateType(final SshCertificateType certificateType) {
        data.put(SSH_CERTIFICATE_TYPE, certificateType);
    }

    public Map<String, String> getSshExtensionsMap() {
        final Map<?,?> extensionsInDb = (Map<?,?>) data.get(SSH_EXTENSIONS);
        if (extensionsInDb == null) {
            return SshExtension.EXTENSIONS_MAP;
        }
        // Versions prior to 8.1 sometimes stored the map values as an empty byte[],
        // and sometimes as String. In practice, the byte[] code path probably couldn't
        // be reached.
        //
        // byte[] does not work in toString() properly, which breaks database protection.
        // so we have to change byte[] to String here.
        final Map<String,String> extensions = new LinkedHashMap<>();
        for (final Entry<?,?> entry : extensionsInDb.entrySet()) {
            final String value = (entry.getValue() instanceof String ? (String) entry.getValue() : "");
            extensions.put((String) entry.getKey(), value);
        }
        return extensions;
    }

    public Map<String, byte[]> getSshExtensionsBytesMap() {
        final Map<String,byte[]> extensions = new LinkedHashMap<>();
        for (final Entry<String,String> entry : getSshExtensionsMap().entrySet()) {
            extensions.put(entry.getKey(), entry.getValue().getBytes(StandardCharsets.UTF_8));
        }
        return extensions;
    }

    public List<String> getSshExtensions() {
        return new ArrayList<>(getSshExtensionsMap().keySet());
    }

    public void setSshExtensionsMap(Map<String, String> extensions) {
        data.put(SSH_EXTENSIONS, extensions);
    }

    public void setSshExtensions(List<String> extensionsList) {
        Map<String, String> extensions = new LinkedHashMap<>();
        for(String extension : extensionsList) {
            extensions.put(extension, "");
        }
        data.put(SSH_EXTENSIONS, extensions);
    }

    public boolean getAllowExternalSshExtensions() {
        if(!data.containsKey(SSH_ALLOW_EXTERNAL_EXTENSIONS)) {
            data.put(SSH_ALLOW_EXTERNAL_EXTENSIONS, false);
        }
        return (boolean) data.get(SSH_ALLOW_EXTERNAL_EXTENSIONS);
    }

    public void setAllowExternalSshExtensions(boolean allow) {
        data.put(SSH_ALLOW_EXTERNAL_EXTENSIONS, allow);
    }

    public boolean getRequireExternalSshExtensionsDefined() {
        if(!data.containsKey(SSH_REQUIRE_EXTERNAL_EXTENSIONS_DEFINED)) {
            data.put(SSH_REQUIRE_EXTERNAL_EXTENSIONS_DEFINED, false);
        }
        return (boolean) data.get(SSH_REQUIRE_EXTERNAL_EXTENSIONS_DEFINED);
    }

    public void setRequireExternalSshExtensionsDefined(boolean allow) {
        data.put(SSH_REQUIRE_EXTERNAL_EXTENSIONS_DEFINED, allow);
    }

    /** ITS Getters & Setters */
    public ITSCertificateType getItsCertificateType() {
        data.putIfAbsent(ITS_CERTIFICATE_TYPE, ITSCertificateType.EXPLICIT);
        return (ITSCertificateType) data.get(ITS_CERTIFICATE_TYPE);
    }

    public void setItsCertificateType(final ITSCertificateType certificateType) {
        data.put(ITS_CERTIFICATE_TYPE, certificateType);
    }

    /**
     * Get a list of List of appPermission PsIds indicating which ITS application permissions the profile should allow.
     *
     * @return a list of List of appPermission PsIds, never null.
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getItsApplicationPermissions() {
        return data.get(ITS_APP_PERMISSIONS) == null
                ? Collections.emptyList()
                : (List<Integer>) data.get(ITS_APP_PERMISSIONS);
    }

    /**
     * Saves the CertificateProfile's list of ITS appPermissions the cert profile is applicable to.
     *
     * @param applicationPermissions List of appPermission PsIds (Integer)
     * @see ITSApplicationIds
     */

    public void setItsApplicationPermissions(List<Integer> applicationPermissions) {
        data.put(ITS_APP_PERMISSIONS, applicationPermissions);
    }

    /**
     * Get a list of List of certIssuingPermissions PsIds indicating which ITS certificate issuing permissions the profile should allow.
     *
     * @return a list of List of certIssuingPermission PsIds, never null.
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getItsCertIssuingPermissions() {
        return data.get(ITS_CERT_ISSUNG_PERMISSIONS) == null
                ? Collections.emptyList()
                : (List<Integer>) data.get(ITS_CERT_ISSUNG_PERMISSIONS);
    }

    /**
     * Saves the CertificateProfile's list of ITS certIssuingPermissions the cert profile is applicable to.
     *
     * @param certIssuingPermissions List of certIssuingPermissions PsIds (Integer)
     * @see ITSApplicationIds
     */

    public void setItsCertIssuingPermissions(List<Integer> certIssuingPermissions) {
        data.put(ITS_CERT_ISSUNG_PERMISSIONS, certIssuingPermissions);
    }

    /**
     * Usage only intended for post upgrade!
     * Removes CT data prior to EJBCA 6.10.1 from certificate profile.
     * */
    public void removeLegacyCtData() {
        if (data.get(CT_MAX_SCTS) != null) {
            data.remove(CT_MAX_SCTS);
        }
        if (data.get(CT_MAX_SCTS_OCSP) != null) {
            data.remove(CT_MAX_SCTS_OCSP);
        }
        if (data.get(CT_MIN_MANDATORY_SCTS) != null) {
            data.remove(CT_MIN_MANDATORY_SCTS);
        }
        if (data.get(CT_MAX_MANDATORY_SCTS) != null) {
            data.remove(CT_MAX_MANDATORY_SCTS);
        }
        if (data.get(CT_MIN_MANDATORY_SCTS_OCSP) != null) {
            data.remove(CT_MIN_MANDATORY_SCTS_OCSP);
        }
        if (data.get(CT_MAX_MANDATORY_SCTS_OCSP) != null) {
            data.remove(CT_MAX_MANDATORY_SCTS_OCSP);
        }
        if (data.get(CT_MIN_NONMANDATORY_SCTS) != null) {
            data.remove(CT_MIN_NONMANDATORY_SCTS);
        }
        if (data.get(CT_MAX_NONMANDATORY_SCTS) != null) {
            data.remove(CT_MAX_NONMANDATORY_SCTS);
        }
        if (data.get(CT_MIN_NONMANDATORY_SCTS_OCSP) != null) {
            data.remove(CT_MIN_NONMANDATORY_SCTS_OCSP);
        }
        if (data.get(CT_MAX_NONMANDATORY_SCTS_OCSP) != null) {
            data.remove(CT_MAX_NONMANDATORY_SCTS_OCSP);
        }
    }

    /**
     * Checks that a public key fulfills the policy in the CertificateProfile
     *
     * @param publicKey PublicKey to verify
     * @throws IllegalKeyException if the PublicKey does not fulfill policy in CertificateProfile
     */
    public void verifyKey(final PublicKey publicKey) throws IllegalKeyException {
        final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
        final int keyLength = KeyTools.getKeyLength(publicKey);
        if (log.isDebugEnabled()) {
            log.debug("KeyAlgorithm: " + keyAlgorithm + " KeyLength: " + keyLength);
        }
        // Verify that the key algorithm is compliant with the certificate profile
        if (!getAvailableKeyAlgorithmsAsList().contains(keyAlgorithm)) {
            if(log.isDebugEnabled()) {
                log.debug("Algorithm " + keyAlgorithm + " is not among the list of available algorithms: " + getAvailableKeyAlgorithmsAsList());
            }
            throw new IllegalKeyException(intres.getLocalizedMessage("createcert.illegalkeyalgorithm", keyAlgorithm));
        }
        if (AlgorithmConstants.KEYALGORITHM_ED25519.equals(keyAlgorithm) || AlgorithmConstants.KEYALGORITHM_ED448.equals(keyAlgorithm)) {
            // The "complete" algorithm is allowed, so we don't check key length
            if (log.isDebugEnabled()) {
                log.debug("Not verifying key length, which is implicitly allowed already, for " + keyAlgorithm);
            }
            return;
        }
        if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
            final List<String> availableEcCurves = getAvailableEcCurvesAsList();
            final String keySpecification = AlgorithmTools.getKeySpecification(publicKey);
            for (final String ecNamedCurveAlias : AlgorithmTools.getEcKeySpecAliases(keySpecification)) {
                if (availableEcCurves.contains(ecNamedCurveAlias)) {
                    // Curve is allowed, so we don't check key length
                    return;
                }
            }
            if (!availableEcCurves.contains(ANY_EC_CURVE)) {
                // Curve will never be allowed by bit length check
                throw new IllegalKeyException(intres.getLocalizedMessage("createcert.illegaleccurve", keySpecification));
            }
        }
        if (AlgorithmTools.isPQC(keyAlgorithm)) {
            //We implicitly allow a specific key length when configuring FALCON and/or ML-DSA algorithms,
            //hence we don't need to check for key length compliancy with the certificate profile.
            return;
         }
        // Verify key length that it is compliant with certificate profile
        if (keyLength == -1) {
            throw new IllegalKeyException(intres.getLocalizedMessage("createcert.unsupportedkeytype", publicKey.getClass().getName()));
        }
        // This can look a bit illogical from a configuration perspective, it checks if the requested key length/strength is
        // in in interval. I.e. if you select 2048 and 4096 for RSA keys in a certificate profile, but does not select 3072
        // 3072 is still allowed because it is within the interval configured in the certificate profile
        if ((keyLength < (getMinimumAvailableBitLength() - 1)) || (keyLength > (getMaximumAvailableBitLength()))) {
            throw new IllegalKeyException(intres.getLocalizedMessage("createcert.illegalkeylength", keyLength));
        }
    }

    /**
     * Checks that provided caId is allowed.
     *
     * @param caId caId to verify
     * @return Returns true, if caId belongs to availableCas or if any CA is allowed (-1 is in availableCAs list)
     */
    public boolean isCaAllowed(int caId) {
        List<Integer> availableCAs = getAvailableCAs();
        return availableCAs.contains(-1) || availableCAs.contains(caId);
    }

    @Override
    public CertificateProfile clone() throws CloneNotSupportedException {
        final CertificateProfile clone = new CertificateProfile(0);
        // We need to make a deep copy of the LinkedHashMap here
        clone.data = new LinkedHashMap<>((int)Math.ceil(data.size()/MAP_LOAD_FACTOR));
        for (final Entry<Object,Object> entry : data.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof ArrayList<?>) {
                        // We need to make a clone of this object, but the stored immutables can still be referenced
                        value = ((ArrayList<?>)value).clone();
                }
                clone.data.put(entry.getKey(), value);
        }
        return clone;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Function setting the current version of the class data. Used for JUnit testing
     */
    protected void setVersion(float version) {
        data.put(VERSION, version);
    }

    /**
     * Implementation of UpgradableDataHashMap function upgrade.
     */
    @SuppressWarnings("deprecation")
    @Override
    public void upgrade() {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        if (Float.compare(getLatestVersion(), getVersion()) != 0) {
            // New version of the class, upgrade
            String msg = intres.getLocalizedMessage("certprofile.upgrade", getVersion());
            log.info(msg);

            data.putIfAbsent(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
            data.putIfAbsent(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
            data.computeIfAbsent(EXTENDEDKEYUSAGE, k -> new ArrayList<String>());
            data.putIfAbsent(EXTENDEDKEYUSAGECRITICAL, Boolean.FALSE);
            data.computeIfAbsent(AVAILABLECAS, k -> Collections.singletonList(ANYCA));
            data.computeIfAbsent(USEDPUBLISHERS, k -> new ArrayList<Integer>());
            if ( (data.get(USEOCSPSERVICELOCATOR) == null) && (data.get(USEAUTHORITYINFORMATIONACCESS) == null) ) {
                // Only set this flag if we have not already set the new flag USEAUTHORITYINFORMATIONACCESS
                // setUseOCSPServiceLocator(false);
                data.put(USEOCSPSERVICELOCATOR, Boolean.FALSE);
                setOCSPServiceLocatorURI("");
            }

            if (data.get(USEMICROSOFTTEMPLATE) == null) {
                setUseMicrosoftTemplate(false);
                setMicrosoftTemplate("");
            }

            if (data.get(USE_MS_OBJECTSID_SECURITY_EXTENSION) == null) {
                setUseMsObjectSidSecurityExtension(true);
            }

            if (data.get(USECNPOSTFIX) == null) {
                setUseCNPostfix(false);
                setCNPostfix("");
            }

            if (data.get(USESUBJECTDNSUBSET) == null) {
                setUseSubjectDNSubSet(false);
                setSubjectDNSubSet(new ArrayList<>());
                setUseSubjectAltNameSubSet(false);
                setSubjectAltNameSubSet(new ArrayList<>());
            }

            if (data.get(USEPATHLENGTHCONSTRAINT) == null) {
                setUsePathLengthConstraint(false);
                setPathLengthConstraint(0);
            }

            if (data.get(USEQCSTATEMENT) == null) {
                setUseQCStatement(false);
                setUsePkixQCSyntaxV2(false);
                setQCStatementCritical(false);
                setQCStatementRAName(null);
                setQCSemanticsIds(null);
                setUseQCEtsiQCCompliance(false);
                setUseQCEtsiSignatureDevice(false);
                setUseQCEtsiValueLimit(false);
                setUseQCEtsiRetentionPeriod(false);
                setQCEtsiRetentionPeriod(0);
                setQCEtsiValueLimit(0);
                setQCEtsiValueLimitExp(0);
                setQCEtsiValueLimitCurrency(null);
            }

            if (data.get(USEDEFAULTCRLDISTRIBUTIONPOINT) == null) {
                setUseDefaultCRLDistributionPoint(false);
                setUseDefaultOCSPServiceLocator(false);
            }

            if (data.get(USEQCCUSTOMSTRING) == null) {
                setUseQCCustomString(false);
                setQCCustomStringOid(null);
                setQCCustomStringText(null);
            }
            if (data.get(USESUBJECTDIRATTRIBUTES) == null) {
                setUseSubjectDirAttributes(false);
            }
            if (data.get(ALLOWVALIDITYOVERRIDE) == null) {
                setAllowValidityOverride(false);
            }

            if (data.get(ALLOWEXPIREDVALIDITYENDDATE) == null) {
                setAllowExpiredValidityEndDate(false);
            }

            if (data.get(CRLISSUER) == null) {
                setCRLIssuer(null); // v20
            }

            if (data.get(USEOCSPNOCHECK) == null) {
                setUseOcspNoCheck(false); // v21
            }
            if (data.get(USEFRESHESTCRL) == null) {
                setUseFreshestCRL(false); // v22
                setUseCADefinedFreshestCRL(false);
                setFreshestCRLURI(null);
            }

            if (data.get(CERTIFICATE_POLICIES) == null) { // v23
                if (data.get(CERTIFICATEPOLICYID) != null) {
                    String ids = (String) data.get(CERTIFICATEPOLICYID);
                    String unotice = null;
                    String cpsuri = null;
                    if (data.get(POLICY_NOTICE_UNOTICE_TEXT) != null) {
                        unotice = (String) data.get(POLICY_NOTICE_UNOTICE_TEXT);
                    }
                    if (data.get(POLICY_NOTICE_CPS_URL) != null) {
                        cpsuri = (String) data.get(POLICY_NOTICE_CPS_URL);
                    }
                    // Only the first policy could have user notice and cpsuri in the old scheme
                    StringTokenizer tokenizer = new StringTokenizer(ids, ";", false);
                    if (tokenizer.hasMoreTokens()) {
                        String id = tokenizer.nextToken();
                        CertificatePolicy newpolicy = null;
                        if (StringUtils.isNotEmpty(unotice)) {
                            newpolicy = new CertificatePolicy(id, CertificatePolicy.id_qt_unotice, unotice);
                            addCertificatePolicy(newpolicy);
                        }
                        if (StringUtils.isNotEmpty(cpsuri)) {
                            newpolicy = new CertificatePolicy(id, CertificatePolicy.id_qt_cps, cpsuri);
                            addCertificatePolicy(newpolicy);
                        }
                        // If it was a lonely policy id
                        if (newpolicy == null) {
                            newpolicy = new CertificatePolicy(id, null, null);
                            addCertificatePolicy(newpolicy);
                        }
                    }
                    while (tokenizer.hasMoreTokens()) {
                        String id = tokenizer.nextToken();
                        CertificatePolicy newpolicy = new CertificatePolicy(id, null, null);
                        addCertificatePolicy(newpolicy);
                    }
                }
            }

            if ( (data.get(USECAISSUERS) == null) && (data.get(USEAUTHORITYINFORMATIONACCESS) == null) ) {
                // Only set this flag if we have not already set the new flag USEAUTHORITYINFORMATIONACCESS
                // setUseCaIssuers(false); // v24
                data.put(USECAISSUERS, Boolean.FALSE); // v24
                setCaIssuers(new ArrayList<>());
            }
            if ( ((data.get(USEOCSPSERVICELOCATOR) != null) || (data.get(USECAISSUERS) != null)) && (data.get(USEAUTHORITYINFORMATIONACCESS) == null) ) {
                // Only do this if we have not already set the new flag USEAUTHORITYINFORMATIONACCESS
                boolean ocsp = false;
                if ((data.get(USEOCSPSERVICELOCATOR) != null)) {
                    ocsp = (Boolean) data.get(USEOCSPSERVICELOCATOR);
                }
                boolean caissuers = false;
                if ((data.get(USECAISSUERS) != null)) {
                    caissuers = (Boolean) data.get(USECAISSUERS);
                }
                if (ocsp || caissuers) {
                    setUseAuthorityInformationAccess(true); // v25
                } else {
                    setUseAuthorityInformationAccess(false); // v25
                }
            } else if (data.get(USEAUTHORITYINFORMATIONACCESS) == null) {
                setUseAuthorityInformationAccess(false);
            }

            if (data.get(ALLOWEXTENSIONOVERRIDE) == null) {
                setAllowExtensionOverride(false); // v26
            }

            if (data.get(USEQCETSIRETENTIONPERIOD) == null) {
                setUseQCEtsiRetentionPeriod(false); // v27
                setQCEtsiRetentionPeriod(0);
            }

            if (data.get(CVCACCESSRIGHTS) == null) {
                setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE); // v28
            }

            if (data.get(USELDAPDNORDER) == null) {
                setUseLdapDnOrder(true); // v29, default value is true
            }

            if (data.get(USECARDNUMBER) == null) { // v30, default value is false
                setUseCardNumber(false);
            }

            if (data.get(ALLOWDNOVERRIDE) == null) {
                setAllowDNOverride(false); // v31
            }

            if (data.get(NUMOFREQAPPROVALS) == null) { // v 33
                setNumOfReqApprovals(1);
            }
            if (data.get(APPROVALSETTINGS) == null) { // v 33
                setApprovalSettings(new ArrayList<>());
            }

            if (data.get(SIGNATUREALGORITHM) == null) { // v 34
                setSignatureAlgorithm(null);
            }

            if (data.get(USEPRIVKEYUSAGEPERIODNOTBEFORE) == null) { // v 35
                setUsePrivateKeyUsagePeriodNotBefore(false);
            }
            if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) { // v 35
                setUsePrivateKeyUsagePeriodNotAfter(false);
            }
            if (data.get(PRIVKEYUSAGEPERIODSTARTOFFSET) == null) { // v 35
                setPrivateKeyUsagePeriodStartOffset(DEFAULT_PRIVATE_KEY_USAGE_PERIOD_OFFSET);
            }
            if (data.get(PRIVKEYUSAGEPERIODLENGTH) == null) { // v 35
                setPrivateKeyUsagePeriodLength(DEFAULT_PRIVATE_KEY_USAGE_PERIOD_LENGTH);
            }
            if(data.get(USEISSUERALTERNATIVENAME) == null) { // v 36
                setUseIssuerAlternativeName(false);
            }
            if(data.get(ISSUERALTERNATIVENAMECRITICAL) == null) { // v 36
                setIssuerAlternativeNameCritical(false);
            }
            if(data.get(USEDOCUMENTTYPELIST) == null) { // v 37
                setUseDocumentTypeList(false);
            }
            if(data.get(DOCUMENTTYPELISTCRITICAL) == null) { // v 37
                setDocumentTypeListCritical(false);
            }
            if(data.get(DOCUMENTTYPELIST) == null) { // v 37
                setDocumentTypeList(new ArrayList<>());
            }
            if(data.get(AVAILABLEKEYALGORITHMS) == null) { // v 39
                // Make some intelligent guesses what key algorithm this profile is used for
                final List<String> availableKeyAlgorithms = AlgorithmTools.getAvailableKeyAlgorithms();
                if (getMinimumAvailableBitLength()>521) {
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_ECDSA);
                }
                if (getMaximumAvailableBitLength()<1024) {
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_RSA);
                }
                setAvailableKeyAlgorithmsAsList(availableKeyAlgorithms);
            }
            if (data.get(AVAILABLEECCURVES) == null) { // v 40
               setAvailableEcCurves(new String[]{ ANY_EC_CURVE });
            }
            if(data.get(APPROVALPROFILE) == null) { // v41
                setApprovalProfileID(-1);
            }
            // v42. ETSI QC Type and PDS specified in EN 319 412-05.
            // Nothing to set though, since null values means to not use the new values

            // v43, ECA-5304.
            if (data.get(USEDEFAULTCAISSUER) == null) {
                setUseDefaultCAIssuer(false);
            }

            // v44. ECA-5141
            // 'encodedValidity' is derived by the former long value!
            if(null == data.get(ENCODED_VALIDITY)) {
                if (data.get(VALIDITY) != null) { // avoid NPE if this is a very raw profile
                    setEncodedValidity(ValidityDate.getStringBeforeVersion661(getValidity()));
                }
                // Don't upgrade to anything is there was nothing to upgrade
            }
            // v44. ECA-5330
            // initialize fields for expiration restriction for weekdays. use is false because of backward compatibility, the before restriction default is true
            if(null == data.get(USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS)) {
                setUseExpirationRestrictionForWeekdays(false);
            }
            if(null == data.get(EXPIRATION_RESTRICTION_WEEKDAYS)) {
                setDefaultExpirationRestrictionWeekdays();
            }
            if(null == data.get(EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE)) {
                setExpirationRestrictionForWeekdaysExpireBefore(true);
            }
            // v44. ECA-3554
            // initialize default certificate not before offset (default '-10m' because of backward compatibility).
            if(null == data.get(USE_CERTIFICATE_VALIDITY_OFFSET)) {
                setUseCertificateValidityOffset(false);
            }
            if(null == data.get(CERTIFICATE_VALIDITY_OFFSET)) {
                setCertificateValidityOffset(DEFAULT_CERTIFICATE_VALIDITY_OFFSET);
            }

            // v45: Multiple ETSI QC PDS values (ECA-5478)
            if (!data.containsKey(QCETSIPDS)) {
                final String url = (String) data.get(QCETSIPDSURL);
                final String lang = (String) data.get(QCETSIPDSLANG);
                if (StringUtils.isNotEmpty(url)) {
                    final List<PKIDisclosureStatement> pdsList = new ArrayList<>();
                    pdsList.add(new PKIDisclosureStatement(url, lang));
                    data.put(QCETSIPDS, pdsList);
                } else {
                    data.put(QCETSIPDS, null);
                }
            }
            // v46: approvals changed type to LinkedHashMap
            setApprovals(getApprovals());

            // v48: ECA-9500 ETSI QC Legislation Countries
            if (data.get(USEQCCOUNTRIES) == null) {
                setUseQCCountries(false);
                setQCCountriesString("");
            }

            // v50: truncated subject key identifier
            if (data.get(USETRUNCATEDSUBJECTKEYIDENTIFIER) == null) {
                setUseTruncatedSubjectKeyIdentifier(false);
            }

            // v52: ETSI Validity Assured - Short Term certificate extension specified in EN 319 412-01.
            if (data.get(USE_VALIDITY_ASSURED_SHORT_TERM) == null) {
                setUseValidityAssuredShortTerm(false);
                setValidityAssuredShortTermCritical(false);
            }
            
            // v53: Remove support for GOST and DSTU if present
            List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
            availableKeyAlgorithms.remove("ECGOST3410");
            availableKeyAlgorithms.remove("DSTU4145");
            setAvailableKeyAlgorithmsAsList(availableKeyAlgorithms);
            // Make sure that they didn't sneak into the alternate set
            List<String> alternativeAvailableKeyAlgorithms = getAlternativeAvailableKeyAlgorithmsAsList();
            if (alternativeAvailableKeyAlgorithms != null && !alternativeAvailableKeyAlgorithms.isEmpty()) {
                alternativeAvailableKeyAlgorithms.remove("ECGOST3410");
                alternativeAvailableKeyAlgorithms.remove("DSTU4145");
                setAlternativeAvailableKeyAlgorithmsAsList(alternativeAvailableKeyAlgorithms);
            }

            data.put(VERSION, LATEST_VERSION);
        }
        log.trace("<upgrade");
    }


    /**
     * Determine if the certificate profile supports Elliptic Curve Cryptography (ECC).
     *
     * @param certificateProfile the certificate profile to check.
     * @return true if the certificate profile supports a key algorithm which utilises ECC, false otherwise.
     */
    public boolean isEccCapable() {
        return getAvailableKeyAlgorithmsAsList().contains("ECDSA");
    }

}
