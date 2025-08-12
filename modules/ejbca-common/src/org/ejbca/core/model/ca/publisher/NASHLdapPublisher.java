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
 
package org.ejbca.core.model.ca.publisher;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity;
import org.ejbca.util.LdapNameStyle;
import org.ejbca.util.LdapTools;
import org.ejbca.util.TCPTool;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPJSSEStartTLSFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

/**
 * NASHLdapPublisher is based upon the BasicLdapPublisher, but is designed to update additional attributes in the LDAP entry
 * which are used by by the NASH website for searching.
 * 
 * The additional fields are:
 *   dc             : contains the HPIO number, which is found in the Subject DN
 *   employeeType   : contains the Policy OID value
 *   employeeNumber : contains the RA Number, which is within certificate extension OID=1.2.36.73665175.1.10009
 * 
 * Note: Originally a SAN value was published under 'labeledUri' attribute, but the SAN is no longer included in the 
 *       active NASH certificate Policies.
 *       
 * This publisher is intended for NASH end entities. However, it can also support publishing of CA certificates and CRLs.
 *       
 * When configuring this publisher, the same properties are supported as per BasicLdapPublisher. These are:
 *   hostnames=<LDAP host names or IPs. Use ';' to separate entries.> NOTE: Only one LDAP is actually updated as LDAP replication should update the others.
 *   port=<LDAP port as an integer>
 *   logindn=<LDAP administrator DN>
 *   loginpassword=<LDAP administrator password>
 *   basedn=<The 'Base DN' for the LDAP. This can be an empty string.>
 *   connectionsecurity=<Connection security is PLAIN, STARTTLS, or SSL>
 *   timeout=<Maximum timeout to establish a LDAP connection. Default=5000 milliseconds>
 *   readtimeout=<Maximum timeout for retrieving data from LDAP. Default=30000 milliseconds>
 *   storetimeout=<Maximum timeout for writing data into LDAP. Default=60000 milliseconds>
 *
 */
public class NASHLdapPublisher extends BasicLdapPublisher implements ICustomPublisher{


    //private static final long serialVersionUID = -584431431033065114L;
    private static final Logger log = Logger.getLogger(NASHLdapPublisher.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	// Defines a version reference. Allows for automatic upgrading of properties.
	public static final float LATEST_VERSION = 1;
	
	
//	// A new 'property' for this publisher.
//	protected static final String VALIDCPOIDS = "validcpoids";
//    private final ArrayList<String> listOfValidCPs = new ArrayList<String>();


    //
    // Public Methods


    /**
     * The set of valid 'properties' for this publisher. Used by the GUI to check the entry of properties.
     */
    @Override
    public Set<String> getDeclaredPropertyNames() {
        final Set<String> set = new TreeSet<>();
        set.add(HOSTNAMES);
        set.add(PORT);
        set.add(BASEDN);
        set.add(LOGINDN);
        set.add(LOGINPASSWORD);
        set.add(TIMEOUT);
        set.add(READTIMEOUT);
        set.add(STORETIMEOUT);
//        set.add(VALIDCPOIDS);
        set.add(CONNECTIONSECURITY);
        return set;
    }


    /**
     * Method called to all newly created ICustomPublishers to set it up with
     * saved configuration.
     * 
     * @param properties The properties to load.
     */
    @Override
    public void init(Properties properties) {
        
        // Call the super to set the common properties.
        super.init( properties);
        
//        // Set the valid CP Oids for this Publisher
//        if (properties.getProperty(VALIDCPOIDS) != null) {
//            // Pass the CP Oids values that will be processed by this publisher. Use the separator ";"
//            String[] oids = properties.getProperty(VALIDCPOIDS).split(";");
//            for (String s : oids) {
//                listOfValidCPs.add( s);
//            }
//        } else {
//            // Set to a empty list.
//            listOfValidCPs.clear();
//        }
         
    }


	public NASHLdapPublisher(){
		super();
	}



//	/**
//	 * Publishes certificate in LDAP, if the certificate is not revoked. If the certificate is revoked, nothing is done
//	 * and the publishing is counted as successful (i.e. returns true).
//	 * 
//	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#storeCertificate
//	 */    
//	public boolean storeCertificate( AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, 
//	                                 int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, 
//	                                 long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException{
//		if (log.isTraceEnabled()) {
//			log.trace(">storeCertificate(username="+username+")");
//		}
//
//		// This publisher is for end-entity certificates only
//        if (type == CertificateConstants.CERTTYPE_ENDENTITY) {
//            if (log.isDebugEnabled()) {
//                log.debug("Publishing end user certificate to first available server of " + getHostnames());
//            }
//
//            if (status == CertificateConstants.CERT_REVOKED) {
//                // Call separate script for revocation
//                revokeCertificate(admin, incert, username, revocationReason, userDN);
//
//            } else if (status == CertificateConstants.CERT_ACTIVE) {
//                // Only publish active certificates
//
//                // As this publisher is specifically for NASH, check the CP OID matches a a valid OID value
//                boolean isValidCP = false;
//                String valueOfCPOid = "";
//                List<ASN1ObjectIdentifier> cpOidsInCert;
//                try {
//                    // Get the CP OID from the certificate
//                    cpOidsInCert = com.keyfactor.util.CertTools.getCertificatePolicyIds( incert);
//                } catch (IOException e) {
//                    String msg = "Could not extract the Certificate Policy OID from certificate and as such will not attempt to publish.";
//                    log.error(msg, LogRedactionUtils.getRedactedException(e));
//                    // Return true to ignore this certificate and remove from queue.
//                    return true;            
//                }
//                // Check if the CP OID in the certificate a valid OID for this publisher
//                if ((cpOidsInCert != null) && (cpOidsInCert.size() > 0) && (listOfValidCPs.contains(cpOidsInCert.get(0).toString()))) {
//                    // Take a copy of the first CP OID value from the certificate for later use.
//                    valueOfCPOid = cpOidsInCert.get(0).toString();
//                    isValidCP = true;
//                }
//
//                if (!isValidCP) {
//                    String msg = "Certificate cannot be published as it does not contain a valid NASH Certificate Policy OID.";
//                    log.error(msg);
//                    // Return true to ignore this certificate and remove from queue.
//                    return true;
//                }
//
//                // Setup the LDAP connection
//                int ldapVersion = LDAPConnection.LDAP_V3;
//                LDAPConnection lc = createLdapConnection();
//
//                // Construct the LDAP DN for this certificate holder
//                final String dn;
//                final String certdn;
//                try {
//                    // Extract the users DN from the cert.
//                    certdn = CertTools.getSubjectDN(incert);
//                    dn = constructLDAPDN(certdn, userDN);
//                    if (log.isDebugEnabled()) {
//                        log.debug("LDAP DN for user " +username +" is '" + LogRedactionUtils.getSubjectDnLogSafe(dn) +"'");
//                    }
//                } catch (Exception e) {
//                    String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "certificate");
//                    log.error(msg, LogRedactionUtils.getRedactedException(e));
//                    // Return true to ignore this certificate and remove from queue.
//                    return true;
//                }
//
//                // Check if the LDAP entry is already present. If so, we will update it with the new certificate.
//                // Note: This method does not strictly search, but performs look-up the LDAP node using the Certificate's Subject DN 
//                // with the BaseDN appended.
//                LDAPEntry oldEntry = searchOldEntity(username, ldapVersion, lc, certdn, userDN, null);
//
//                // The following code needs to support creating a new LDAP entry, or modifying an existing LDAP entry.
//                
//                LDAPEntry newEntry = null;
//                ArrayList<LDAPModification> modSet = new ArrayList<LDAPModification>();
//                LDAPAttributeSet attributeSet = null;
//                String attribute = null;
//                String objectclass = null;
//    			
//    			if (oldEntry != null) {
//    			    // Previous LDAP entry exists.
//    			    // Prepare updated attributes (except userCertificate) for the current LDAP entry. 
//    				modSet = getModificationSet(oldEntry, certdn, valueOfCPOid, incert);
//    			} else {
//    			    // Prepare a new LDAP entry
//    				objectclass = getUserObjectClass(); // just used for logging
//    				attributeSet = getAttributeSet(incert, getUserObjectClass(), certdn, valueOfCPOid);
//    			}
//
//    			// Now add the userCertificate attribute
//    			try {
//    				attribute = getUserCertAttribute();
//    				LDAPAttribute certAttr = new LDAPAttribute( attribute, incert.getEncoded());
//    				if (oldEntry != null) {
//    				    // Perform an LDAP ADD operation. If the cert already exists, an exception will be thrown. This is dealt with 
//    				    // in the exception handler below. 
//    				    modSet.add(new LDAPModification(LDAPModification.ADD, certAttr));                        
//    				    if (log.isDebugEnabled()) {
//    				        log.debug("Adding certificate into existing LDAP entry; " + username + ": " + LogRedactionUtils.getSubjectDnLogSafe(dn));
//    				    }
//    				} else {
//    				    // Add the userCertificate to the new LDAP entry
//    					attributeSet.add(certAttr);
//    					if (log.isDebugEnabled()) {
//    						log.debug("Adding certificate into new LDAP entry; " + username + ": " + LogRedactionUtils.getSubjectDnLogSafe(dn));
//    					}
//    				}
//    			} catch (CertificateEncodingException e) {
//    				String msg = intres.getLocalizedMessage("publisher.errorldapencodestore", "certificate");
//    				log.error(msg, LogRedactionUtils.getRedactedException(e));
//                    // Return true to ignore this certificate and remove from queue.
//                    return true;
//    			}
//
//    			// Perform an update to at least one of the LDAP servers. The assumption here is that LDAP replication will update 
//    			// other LDAPs in a HA environment.
//    			Iterator<String> servers = getHostnameList().iterator();
//    			boolean connectionFailed;
//    			do {
//    			    connectionFailed = false;
//    			    String currentServer = servers.next();
//    			    try {
//    			        TCPTool.probeConnectionLDAP(currentServer, Integer.parseInt(getPort()), getConnectionTimeOut());	// Avoid waiting for halfdead-servers
//    			        lc.connect(currentServer, Integer.parseInt(getPort()));
//    			        // Execute a STARTTLS handshake if it was requested.
//    			        if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
//    			            if (log.isDebugEnabled()) {
//    			                log.debug("STARTTLS to LDAP server "+currentServer);
//    			            }
//    			            lc.startTLS();
//    			        }
//    			        // authenticate to the server
//    			        lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes(StandardCharsets.UTF_8), ldapBindConstraints);
// 
//    			        // Add or modify the existing LDAP entry
//    			        if (oldEntry != null ) {
//    			            LDAPModification[] mods = new LDAPModification[modSet.size()]; 
//    			            mods = (LDAPModification[])modSet.toArray(mods);
//    			            String oldDn = oldEntry.getDN();
//    			            if (log.isDebugEnabled()) {
//    			                log.debug("Writing modification to DN: " + LogRedactionUtils.getSubjectDnLogSafe(oldDn));
//    			            }
//    			            lc.modify(oldDn, mods, ldapStoreConstraints);
//    			            String msg = intres.getLocalizedMessage("publisher.ldapmodify", "GOOD", LogRedactionUtils.getSubjectDnLogSafe(oldDn));
//    			            log.info(msg);
// 
//    			        } else {
//    			            // Create the new LDAP entry
//    			            
//    			            // Check if the intermediate parent node is present, and if it is not
//    			            // we can create missing LDAP nodes.
//    			            if(getCreateIntermediateNodes()) {
//                                createIntermediateNodes(lc, dn);
//    			            }
//
//    			            // Lets try adding the new LDAP entry
//    			            newEntry = new LDAPEntry(dn, attributeSet);
//    			            if (log.isDebugEnabled()) {
//    			                log.debug("Adding DN: " + LogRedactionUtils.getSubjectDnLogSafe(dn));
//    			            }
//    			            lc.add(newEntry, ldapStoreConstraints);
//    			            String msg = intres.getLocalizedMessage("publisher.ldapadd", "GOOD", LogRedactionUtils.getSubjectDnLogSafe(dn));
//    			            log.info(msg);
//    			        }
//    			    } catch (LDAPException e) {
//    			        connectionFailed = true;
//    			        
//    			        // If multiple certificates are allowed per entity, and the certificate is already published, 
//    			        // an exception will be thrown. Catch this type of exception and just log an informational message.
//    			        if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
//    			            final String msg = intres.getLocalizedMessage("publisher.certalreadyexists", CertTools.getFingerprintAsString(incert),
//    			                    LogRedactionUtils.getSubjectDnLogSafe(dn), LogRedactionUtils.getRedactedMessage(e.getMessage()));
//    			            log.info(msg);
//    			        } else if (servers.hasNext()) {
//    			            log.warn("Failed to publish to " + currentServer + ". Trying next in list.");
//    			        } else {
//    			            String msg = intres.getLocalizedMessage("publisher.errorldapstore", "certificate", attribute, objectclass,
//    			                    LogRedactionUtils.getSubjectDnLogSafe(dn), LogRedactionUtils.getRedactedMessage(e.getMessage()));
//    			            log.error(msg, LogRedactionUtils.getRedactedException(e));
//    			            throw new PublisherException(msg);            
//    			        }
//    			    } finally {
//    			        // disconnect with the server
//    			        try {
//    			            lc.disconnect(ldapDisconnectConstraints);
//    			        } catch (LDAPException e) {
//    			            String msg = intres.getLocalizedMessage("publisher.errordisconnect");
//    			            log.error(msg, e);
//    			        }
//    			    }
//    			} while (connectionFailed && servers.hasNext()) ;
//            } else {
//                String msg = intres.getLocalizedMessage("publisher.notpublwithstatus", Integer.valueOf(status));
//                log.error(msg);        	
//            }
//
//        } else {
//            String msg = intres.getLocalizedMessage("publisher.notpubltype", Integer.valueOf(type));
//            log.error(msg);
//            //throw new PublisherException(msg);                      
//        }
//
//		if (log.isTraceEnabled()) {
//			log.trace("<storeCertificate()");
//		}
//		return true;
//	}
//
//
//	/**
//	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#storeCRL
//	 * CRL publication is not supported by the publisher.
//	 */    
//	public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException{
//			String msg = "Publishing of CRLs is not permitted.";
//			log.error(msg);        	
//            // Return true to ignore this CRL and remove from queue.
//            return true;
//	}
//
//	   /**
//     * Revokes a certificate, which means for LDAP that we may remove the certificate or the whole user entry.
//     * 
//     * @param cert The certificate to be revoked.
//     * @param username Username of end entity owning the certificate.
//     * @param reason reason for revocation from RevokedCertInfo, RevokedCertInfo.NOT_REVOKED if not revoked.
//     * @param userDN if an DN object is not found in the certificate use object from user data instead.
//     */ 
//	@Override
//    public void revokeCertificate(AuthenticationToken admin, Certificate cert, String username, int reason, String userDN) throws PublisherException {
//        if (log.isTraceEnabled()) {
//            log.trace(">revokeCertificate()");
//        }
//        // Check first if we should do anything then revoking
//        boolean removecert = getRemoveRevokedCertificates();
//        boolean removeuser = getRemoveUsersWhenCertRevoked();
//        if ( (!removecert) && (!removeuser) ) {
//            if (log.isDebugEnabled()) {
//                log.debug("The configuration for the publisher '" + getDescription() + "' does not allow removing of certificates or users.");
//            }
//            return;
//        }
//        if (removecert) {
//            if (log.isDebugEnabled()) {
//                log.debug("Removing user certificate from ldap");
//            }
//        }
//        if (removeuser) {
//            if (log.isDebugEnabled()) {
//                log.debug("Removing user entry from ldap");
//            }
//        }
//
//        int ldapVersion = LDAPConnection.LDAP_V3;
//        LDAPConnection lc = createLdapConnection();
//
//        final String dn;
//        final String certdn;
//        try {
//            // Extract the users DN from the cert.
//            certdn = CertTools.getSubjectDN(cert);
//            dn = constructLDAPDN(certdn, userDN);
//        } catch (Exception e) {
//            String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "certificate");
//            log.error(msg, LogRedactionUtils.getRedactedException(e));
//            throw new PublisherException(msg);            
//        }
//
//        // Extract the users email from the cert.
//        String email = DnComponents.getEMailAddress(cert);
//
//        // Check if the entry is already present, we will update it with the new certificate.
//        final LDAPEntry oldEntry;
//
//        ArrayList<LDAPModification> modSet = null;
//
//        if (!CertTools.isCA(cert)) {
//            oldEntry = searchOldEntity(username, ldapVersion, lc, certdn, userDN, email);
//            if (log.isDebugEnabled()) {
//                log.debug("Removing end user certificate from first available server of " + getHostnames());
//            }
//            if (oldEntry != null) {          
//                if (removecert) {
//                    // Get the current set of certificates
//                    LDAPAttribute oldAttr = oldEntry.getAttribute(getUserCertAttribute());
//                    if (oldAttr != null) {
//                        modSet = getModificationSet(oldEntry, certdn, null, false, true, null, cert);
//                        // Remove the revoked cert from the attribute
//                        try {
//                            oldAttr.removeValue(cert.getEncoded());
//                        } catch (CertificateEncodingException e) {
//                            // Exception should not happen!
//                            String msg = "Unexpected certificate encoding issue. Cannot remove the certificate from LDAP.";
//                            log.error(msg);
//                            return;
//                        }
//
//                        // Check if there are remaining certificates to keep
//                        if ( oldAttr.size() >= 1) {
//                            // Update the LDAP entry
//                            modSet.add(new LDAPModification(LDAPModification.REPLACE, oldAttr));
//                            // Even if 'removeuser' is enabled, lets overwrite this to prevent the user being deleted.
//                            removeuser = false;
//                        } else {
//                            // Delete the userCertificate attribute as no certificate remains.
//                            LDAPAttribute attr = new LDAPAttribute(getUserCertAttribute());
//                            modSet.add(new LDAPModification(LDAPModification.DELETE, attr));
//                        }
//                    } else {
//                        // No userCertificate attribute, nothing to do.
//                        String msg = intres.getLocalizedMessage("publisher.inforevokenocert");
//                        log.info(msg);
//                        return;
//                    }                   
//                }
//            } else {
//                // The LDAP DN doesn't exist, nothing to do.
//                String msg = intres.getLocalizedMessage("publisher.errorrevokenoentry");
//                log.warn(msg);
//                return;
//            }
//        } else  {
//            oldEntry = null;
//            // Removal of CA certificate isn't support because of object class restrictions
//            if (log.isDebugEnabled()) {
//                log.debug("Not removing CA certificate from first available server of " + getHostnames() + ", because of object class restrictions.");
//            }
//            return;
//        }
//
//        // Try all the listed servers
//        final Iterator<String> servers = getHostnameList().iterator();
//        boolean isConnectionNotDone = true;
//        if (log.isDebugEnabled() && (oldEntry == null)) {
//            log.debug("Not modifying LDAP entry because there is no existing entry.");                      
//        }
//        while ( oldEntry!=null && isConnectionNotDone && servers.hasNext()) {
//            isConnectionNotDone = false;
//            String currentServer = servers.next(); 
//            if (log.isDebugEnabled()) {
//                log.debug("currentServer: "+currentServer);
//            }
//            try {
//                TCPTool.probeConnectionLDAP(currentServer, Integer.parseInt(getPort()), getConnectionTimeOut());    // Avoid waiting for halfdead-servers
//                lc.connect(currentServer, Integer.parseInt(getPort()));
//                // Execute a STARTTLS handshake if it was requested.
//                if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
//                    if (log.isDebugEnabled()) {
//                        log.debug("STARTTLS to LDAP server "+currentServer);
//                    }
//                    lc.startTLS();
//                }
//                // authenticate to the server
//                lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes(StandardCharsets.UTF_8), ldapBindConstraints);
//                // Add or modify the entry
//                if (modSet != null && getModifyExistingUsers()) {
//                    if (removecert) {
//                        LDAPModification[] mods = new LDAPModification[modSet.size()]; 
//                        mods = (LDAPModification[])modSet.toArray(mods);
//                        lc.modify(oldEntry.getDN(), mods, ldapStoreConstraints);                    
//                        if (log.isDebugEnabled()) {
//                            log.debug("Removing revoked certificate (SN: "+CertTools.getSerialNumberAsString(cert)+") from the LDAP entry at DN="+LogRedactionUtils.getSubjectDnLogSafe(dn));                        
//                        }
//                    }
//                    if (removeuser) {
//                        lc.delete(oldEntry.getDN(), ldapStoreConstraints);                  
//                        if (log.isDebugEnabled()) {
//                            log.debug("Deleting the LDAP entry at DN="+LogRedactionUtils.getSubjectDnLogSafe(dn));                        
//                        }
//                   }
//                    String msg = intres.getLocalizedMessage("publisher.ldapremove", LogRedactionUtils.getSubjectDnLogSafe(dn));
//                    log.info(msg);
//                } else {
//                    if (log.isDebugEnabled()) {
//                        if (modSet == null) {
//                            log.debug("Not modifying LDAP entry because we don't have anything to modify.");                        
//                        }
//                        if (!getModifyExistingUsers()) {
//                            log.debug("Not modifying LDAP entry because we're not configured to do so.");                       
//                        }
//                    }
//                }
//            } catch (LDAPException e) {
//                isConnectionNotDone = true;
//                if (servers.hasNext()) {
//                    log.warn("Failed to publish to " + currentServer + ". Trying next in list.");
//                } else {
//                    String msg = intres.getLocalizedMessage("publisher.errorldapremove", LogRedactionUtils.getSubjectDnLogSafe(dn));
//                    log.error(msg, LogRedactionUtils.getRedactedException(e));
//                    throw new PublisherException(msg);            
//                }
//            } finally {
//                // disconnect with the server
//                try {
//                    lc.disconnect(ldapDisconnectConstraints);
//                } catch (LDAPException e) {
//                    String msg = intres.getLocalizedMessage("publisher.errordisconnect");
//                    log.error(msg, e);
//                }
//            }
//        }
//        if (log.isTraceEnabled()) {
//            log.trace("<revokeCertificate()");
//        }
//    }

	 /** 
     * Implemtation of UpgradableDataHashMap function upgrade. 
     */
    @Override
    public void upgrade() {
        log.trace(">upgrade");
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade
            String msg = intres.getLocalizedMessage("publisher.upgrade", Float.valueOf(getVersion()));
            log.info(msg);
                
            data.put(VERSION, Float.valueOf(LATEST_VERSION));
        }
        log.trace("<upgrade");
    }

    /**
     * 
     * @return true if this publisher type shouldn't be editable
     */
    @Override
    public boolean isReadOnly() {
        return false;
    }

    //
    // Protected methods   
	
	 /**
     * Creates intermediate nodes to host an LDAP entry at <code>dn</code>.
     * @param lc Active LDAP connection
     * @param dn Distinguished name
     * @throws PublisherException
     */
    protected void createIntermediateNodes(LDAPConnection lc, String dn) throws PublisherException {
	    
	    // Get the parent node
        final String parentDN = DnComponents.getParentDN(dn);
        if (parentDN==null || parentDN.isBlank()) {
            // We can't get the parent DN, log error and return.
            log.warn( "Cannot get the parent node for this DN="+LogRedactionUtils.getSubjectDnLogSafe(dn));
            return;
        }
       try {
            lc.read(parentDN, ldapSearchConstraints);
            // Successfully read this parent node, lets return.
            return;
        } catch(LDAPException e) {
            if(e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                // Recursively try again till we find a valid node.
                createIntermediateNodes(lc, parentDN);
                
                // Lets create this node
                LDAPAttributeSet attrSet;
                LDAPEntry entry;
                
                final String rdn = LdapTools.getFirstDNComponent(parentDN);
                final String field = new String(rdn.substring(0, rdn.indexOf('=')));
                final String value = new String(rdn.substring(rdn.indexOf('=') + 1));
                
                attrSet = new LDAPAttributeSet();
                attrSet.add(getObjectClassAttribute(field));
                attrSet.add(new LDAPAttribute(field.toLowerCase(), value));
                entry = new LDAPEntry(parentDN, attrSet);

                try {
                    lc.add(entry, ldapStoreConstraints);
                    if (log.isDebugEnabled()) {
                        String msg = intres.getLocalizedMessage("publisher.ldapaddedintermediate", "", LogRedactionUtils.getSubjectDnLogSafe(parentDN));
                        log.debug(msg);
                    }
                } catch(LDAPException e1) {
                    String msg = intres.getLocalizedMessage("publisher.ldapaddedintermediate", "ERROR", LogRedactionUtils.getSubjectDnLogSafe(parentDN));
                    log.error(msg, LogRedactionUtils.getRedactedException(e1));
                    throw new PublisherException(msg);            
                }
            }
        }

	}



	
    /**
     * Returns an LDAPAttribute initialized with the LDAP object class
     * definition that corresponds to a DN <code>field</code>.
     * <p>The only allowed fields are </code>O</code> (organization),
     * <code>OU</code> (organizationalUnit), </code>DC</code> (domain), </code>C</code> (country), </code>L</code> (locality), and
     * </code>ST</code> (locality).</p>
     * Note: Based upon LdapPublisher but enhanced.
     *
     * @param field A DN field (case-insensitive). Only <code>O</code> and
     * <code>OU</code> are allowed. 
     * @return LDAPAttribute initialized with the LDAP object class definition
     * that corresponds to a DN <code>field</code>.
     */
    protected LDAPAttribute getObjectClassAttribute(String field) {
        final String lowCaseField = field.toLowerCase();
        if(lowCaseField.equals("o")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "organization" });
        } else if(lowCaseField.equals("ou")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "organizationalUnit" });
        } else if(lowCaseField.equals("dc")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "domain" });
        } else if(lowCaseField.equals("c")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "country" });
        } else if(lowCaseField.equals("l") || lowCaseField.equals("st")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "locality" });
        } else {
            String msg = intres.getLocalizedMessage("publisher.ldapintermediatenotappropriate", field);
            log.warn(msg);
            return new LDAPAttribute("objectclass");
        }
    }


    /**
     * Creates an LDAPAttributeSet.
     *
     * @param cert the certificate to use or null if no cert involved.
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param email email address for entry, or null
     * @param extra if we should add extra attributes except the objectclass to the attributeset.
     * @param person true if this is a person-entry, false if it is a CA.
     * @param password, users password, to be added into SecurityObjects, and AD
     * @param extendedinformation, for future use...
     *
     * @return LDAPAtributeSet created...
     */
    @Override
    protected LDAPAttributeSet getAttributeSet(Certificate cert, String objectclass, String dn, String email, boolean extra, boolean person,
                                               String password, ExtendedInformation extendedinformation) {
		// Call the super first.
        LDAPAttributeSet attributeSet = super.getAttributeSet(cert, objectclass, dn, email, extra, person, password, extendedinformation);
		
        // Add the additional attributes for NASH
        // These only apply to End Entitiy certs
        if (person) {
        
            // Will need to get 'dc' from DN.
            // Note that the 'dc' attribute is non-standard and the LDAP schema will need this 'dc' included as an optional attribute.
            String[] attributesFromDN    = { "dc"}; 
            attributeSet.addAll(getAttributesFromDN(dn,  attributesFromDN));
        

            // Update (or add) the following; employeeType, employeeNumber. 
            // Will not fail the publication event if something here goes wrong

            // EmployeeType is the CP OID value
            // Extract the CP OID from the cert
            List<ASN1ObjectIdentifier> cpOidsInCert;
            try {
                // Get the CP OID from the certificate
                cpOidsInCert = com.keyfactor.util.CertTools.getCertificatePolicyIds( cert);
                attributeSet.add(new LDAPAttribute("employeeType", cpOidsInCert.get(0).toString()));
            } catch (IOException e) {
                String msg = "Could not extract the Certificate Policy OID from certificate and as such will not publish the 'employeeType' attribute.";
                log.warn(msg, LogRedactionUtils.getRedactedException(e));
            }

            // EmployeeNumber has the RA number. The RA number is in a special certificate extension.
            ASN1Primitive ans = CertTools.getExtensionValue( (X509Certificate) cert, "1.2.36.73665175.1.10009");
            if (ans != null) {
                ASN1IA5String raNumber = ASN1IA5String.getInstance(ans);
                if (raNumber != null) {
                    attributeSet.add(new LDAPAttribute("employeeNumber", raNumber.getString()));
                }
            } else {
                String msg = "Could not extract the RA Number from certificate and as such will not publish the 'employeeNumber' attribute.";
                log.warn(msg);
            }
        }
		return attributeSet;
	} // getAttributeSet


    /**
     * Creates an LDAPModificationSet.
     *
     * @param oldEntry the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param email email address for entry, or null
     * @param extra if we should add extra attributes except the objectclass to the
     *        modificationset.
     * @param person true if this is a person entry, false if it is a CA.
     * @param password, users password, to be added into SecurityObjects, and AD
     * @param cert the Certificate we are publishing, or null
     *
     * @return List of LDAPModification created...
     */
    @Override
    protected ArrayList<LDAPModification> getModificationSet(LDAPEntry oldEntry, String dn, String email, boolean extra,
                                                             boolean person, String password, Certificate cert) {

        // Call the super
        ArrayList<LDAPModification> modSet = super.getModificationSet(oldEntry, dn, email, extra, person, password, cert);
        
        if (person) {
            // Include all the updates to the LDAP attributes for an existing entry
            // Will assume that the existing LDAP entry has 'cn' and 'sn' already set.
            // Update (or add) the following; dc, employeeType, employeeNumber. 
            // Will not fail the publication event if something here goes wrong


            // Set the 'dc' attribute to the Healthcare Id, which is in DN as a 'dc'. 
            // There are multiple 'dc' entries in the DN, we just want the first one.
            String[] attributesFromDN    = {"dc"}; 
            modSet.addAll(getModificationSetFromDN(dn, oldEntry, attributesFromDN));

            // EmployeeType is the CP OID value
            // Extract the CP OID from the cert
            List<ASN1ObjectIdentifier> cpOidsInCert;
            try {
                // Get the CP OID from the certificate
                cpOidsInCert = com.keyfactor.util.CertTools.getCertificatePolicyIds( cert);
                LDAPAttribute attr = new LDAPAttribute("employeeType", cpOidsInCert.get(0).toString());
                modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
            } catch (IOException e) {
                String msg = "Could not extract the Certificate Policy OID from certificate and as such will not publish the 'employeeType' attribute.";
                log.warn(msg, LogRedactionUtils.getRedactedException(e));
            }

            // EmployeeNumber has the RA number. The RA number is in a special certificate extension.
            ASN1Primitive ans = CertTools.getExtensionValue( (X509Certificate) cert, "1.2.36.73665175.1.10009");
            if (ans != null) {
                ASN1IA5String raNumber = ASN1IA5String.getInstance(ans);
                if (raNumber != null) {
                    LDAPAttribute attr = new LDAPAttribute("employeeNumber", raNumber.getString());
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
                }
            } else {
                String msg = "Could not extract the RA Number from certificate and as such will not publish the 'employeeNumber' attribute.";
                log.warn(msg);
            }
       
        }
		return modSet;
	} // getModificationSet

	
//	 /**
//     * Constructs the LDAP DN for a certificate to be published by adding the Base DN (if not empty) to the Certificate's Subject DN.
//     * This replaces the code in LdapPublisher which allowed for a custom order of DN fields, which is not generally required.
//     * @param certDN Subject DN from the certificate.
//     * @param userDataDN * Not used *
//     * @return The computed LDAP DN.
//     */
//    @Override
//   protected String constructLDAPDN(String certDN, String userDataDN){
//        if (log.isDebugEnabled()) {
//            log.debug("DN in certificate '" + LogRedactionUtils.getSubjectDnLogSafe(certDN) + "'.");
//        }
//         
//        // Build the LDAP DN and add BaseDN (if it exists)
//        String retval = certDN + (this.getBaseDN().trim().equals("") ? "" : ","+this.getBaseDN()); 
//        if (log.isDebugEnabled()) {
//            log.debug("DN in certificate '" + LogRedactionUtils.getSubjectDnLogSafe(certDN) + "; Constructed LDAP DN: " + LogRedactionUtils.getSubjectDnLogSafe(retval) );
//        }
//        return retval;  
//    }




}
