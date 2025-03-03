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
package org.ejbca.ui.web.admin.mypreferences;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.ejb.EJBException;
import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.faces.model.ListDataModel;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.OAuth2AccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;

import com.keyfactor.util.CertTools;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;



/**
 * To use Yubico WebAuth library, the following additions are required for the build.xml file:
 *   - Compiling:
 *          <path location="${ejbca.home}/lib/ext/webauthn/webauthn-server-core-2.5.0.jar"/>
 *          <path location="${ejbca.home}/lib/ext/webauthn/jackson-core-2.16.1.jar"/>
 *          <path location="${ejbca.home}/lib/ext/webauthn/cbor-4.5.3.jar"/>
 *          <path location="${ejbca.home}/lib/ext/webauthn/cose-java-1.1.0.jar"/>
 *   - Build:
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="webauthn-server-core-2.5.0.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="yubico-util-2.5.0.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="cbor-4.5.3.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-dataformat-cbor-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-core-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-databind-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-dataformat-yaml-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-datatype-jdk8-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-datatype-jsr310-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="jackson-annotations-2.16.1.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="numbers-1.8.2.jar"/>
 *          <zipfileset prefix="WEB-INF/lib" dir="${ejbca.home}/lib/ext/webauthn" includes="cose-java-1.1.0.jar"/>
 *
 *
 */

/**
 * JavaServer Faces Managed Bean for managing MyPreferences.
 * Session scoped and will cache the user preferences.
 *
 */
@Named("myWebAuthnRegMBean")
@SessionScoped
public class MyWebAuthnRegMBean extends BaseManagedBean implements Serializable {
    public static final String keyNameForRegisteredCredentials = "webauthn.credentials"; 

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SignSessionLocal signSession;


    
    /*
     * A class that needs to be implemented to work with the Yubico library.
     * Methods will read/write the EJBCA database (UserData table)
     */
    
    private class EjbcaCredentialRepository4Registration implements com.yubico.webauthn.CredentialRepository{
        
        // Need the actual database Username in order to store WebAuthn credential information into the database.
        final private String databaseUsernameInternal;
        
        EjbcaCredentialRepository4Registration( String username){
            databaseUsernameInternal = username;
        }

        
        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String arg0) {
            // Not used in Registrations
            return null;
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String userName) {
            ByteArray ba = new ByteArray( userName.getBytes());
            return Optional.of(ba);
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            String s = new String( userHandle.getBytes());
            return Optional.of(s);
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray arg0, ByteArray arg1) {
            // Not used in Registrations.
            return Optional.empty();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            // Used to detect if the same Credential ID has already been used and recorded in the database.
            // This is most unlikely, so ignoring. Worse case it that we over-write a previous entry.
            // Returning an empty set, as a null causes an error in Yubico library.
            return new java.util.HashSet<RegisteredCredential>();
        }
        
        /*
         * Update the DB with new WebAuthn credential information. Additional meta-data will also be included.
         * Note: Data stored using a Map object (with basic java objects in the Map) can be stored.
         */
        public boolean updateEndEntityWithWebAuthnCredential( ByteArray credentialId, ByteArray publicKeyCose, 
                long signatureCount, java.security.cert.Certificate certIssuedFromPublicKey) {
            
            // Create a Map to store the Credential values. Map objects can be serialised within EJBCA
            final java.util.LinkedHashMap<String, Object> mapCredential = new java.util.LinkedHashMap<String, Object>();
            mapCredential.put( "PublicKeyCose", publicKeyCose.getBase64() );
            mapCredential.put( "SignatureCount", signatureCount);
            mapCredential.put( "CreationDate", new java.util.Date().getTime());
            //mapCredential.put( "Certificate", certInB64);
            mapCredential.put( "CertFingerPrint", CertTools.getFingerprintAsString(certIssuedFromPublicKey));
            mapCredential.put( "CertExpiry", CertTools.getNotAfter(certIssuedFromPublicKey).getTime());

            // Get the User from DB
            EndEntityInformation eeInfo = endEntityAccessSession.findUser(databaseUsernameInternal);
            if ( eeInfo == null) {
                log.error("The user '"+databaseUsernameInternal+"' cannot be found. Nothing will be stored.");
                return false;
            }
            
            // Get the User's extended information
            ExtendedInformation exInfo = eeInfo.getExtendedInformation();
            // If null, create a new one. Should rarely be required.
            if (exInfo ==null) {
                exInfo=new ExtendedInformation();
                eeInfo.setExtendedInformation(exInfo);
               log.info("Creating new ExtendedInformation for User="+databaseUsernameInternal);
            }
            
            // Get a reference to the raw data objects
            // Note, this will not ever be null.
            java.util.LinkedHashMap<Object,Object> mapRawData = exInfo.getRawData();
            
            // Check for existing WebAuthn Credentials
            // Note: These will be a Map which is supported by the XML serialization
            
            java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapWebAuthnCredentials = (java.util.LinkedHashMap<String,java.util.Map<String,Object>>)mapRawData.get(keyNameForRegisteredCredentials);
            if (mapWebAuthnCredentials == null) {
                // Create a new Map of credential data strings
                mapWebAuthnCredentials = new java.util.LinkedHashMap<String,java.util.Map<String,Object>>();
                // Store the set of RegisteredCredentials into the ExtendedInformation of the User
                mapRawData.put(keyNameForRegisteredCredentials, mapWebAuthnCredentials);
            }
            
            // Add the new WebAuthnCredential (which is a Map) to the exiting set of credentials (which is also a Map).
            // The key will be the CredentialId (in base 64)
            mapWebAuthnCredentials.put( credentialId.getBase64(), mapCredential);
            
            // Save the updated information
            try { 
                // Using special Authentication Token in case current User does not have permission. 
                //endEntityManagementSession.changeUser( getAdmin(), eeInfo, false);
                endEntityManagementSession.changeUser( new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - New WebAuthn credential")), eeInfo, false);
            } catch (NoSuchEndEntityException | CADoesntExistsException | ApprovalException | CertificateSerialNumberException | IllegalNameException | CustomFieldException | AuthorizationDeniedException | EndEntityProfileValidationException | WaitingForApprovalException e) {
                log.error("Could not save credential data for User="+databaseUsernameInternal);
                return false;
            }
            
            log.info("End-entity updated with WebAuthn credential data. User="+databaseUsernameInternal+" Total credentials saved: "+mapWebAuthnCredentials.size());
            return true;
        }
        
        
        /*
         * This method retrieves the Map object containing the WebAuthn credential information from the DB
         * for this user. The caller will need to know how to read/process the information. 
         */
        public java.util.LinkedHashMap<String,java.util.Map<String,Object>> getWebAuthnCredentialsForEndEntity() {
            
            // Get the User from DB
            EndEntityInformation eeInfo = endEntityAccessSession.findUser(databaseUsernameInternal);
            if ( eeInfo == null) {
                log.error("The user '"+databaseUsernameInternal+"' cannot be found. Nothing will be returned.");
                return null;
            }

            // Get the User's extended information
            ExtendedInformation exInfo = eeInfo.getExtendedInformation();
            // If null, then there isn't any data to return
            if (exInfo ==null) {
                log.info("The user '"+databaseUsernameInternal+"' does not have ExtendedInformation. Nothing will be returned.");
                return null;
            }
            
            // Get a reference to the raw data objects
            // Note, this will not ever be null.
            java.util.LinkedHashMap<Object,Object> mapRawData = exInfo.getRawData();

            // Check for existing WebAuthn Credentials
            // Note: These will be a Map which is supported by the XML serialization
            
            java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapWebAuthnCredentials = (java.util.LinkedHashMap<String,java.util.Map<String,Object>>)mapRawData.get(keyNameForRegisteredCredentials);
            if (mapWebAuthnCredentials == null) {
                log.info("The user '"+databaseUsernameInternal+"' does not have any WebAuthn credentials stored.");
                return null;
            }
            
            return mapWebAuthnCredentials;
        }
        
        /*
         * This method retrieves the 'PublicKeyCredentialDescriptor' for the user. This reads the EndEntity's extended 
         * information from the DB and extracts the WebAuthn CredentialId and associated PublicKey.
         * Used to prevent the user recording another credential on the same token.
         */
        public java.util.Set<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> getPublicKeyCredentialDescriptors(){
            final java.util.HashSet<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> setReturn = new java.util.HashSet<com.yubico.webauthn.data.PublicKeyCredentialDescriptor>();

            final java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapTemp = getWebAuthnCredentialsForEndEntity();
            if (mapTemp == null) {
                return setReturn;
            }

            for (String s : mapTemp.keySet()) {
                // The CrentialId is the key value (in Base64)
                final com.yubico.webauthn.data.PublicKeyCredentialDescriptor pkcd = com.yubico.webauthn.data.PublicKeyCredentialDescriptor.builder()
                        .id(ByteArray.fromBase64(s))
                        .type( com.yubico.webauthn.data.PublicKeyCredentialType.PUBLIC_KEY)
                        .build();

                setReturn.add( pkcd);
            }
            return setReturn;
        }
        
        public boolean deleteWebAuthnCredentialForEndEntity( String credentialId) {
            // Get the User from DB
            EndEntityInformation eeInfo = endEntityAccessSession.findUser(databaseUsernameInternal);
            if ( eeInfo == null) {
                log.error("The user '"+databaseUsernameInternal+"' cannot be found. Nothing can be updated.");
                return false;
            }
            
            // Get the User's extended information
            ExtendedInformation exInfo = eeInfo.getExtendedInformation();
            // Should not be null. If null, then exit.
            if (exInfo ==null) {
               log.error("No ExtendedInformation for User="+databaseUsernameInternal+". Nothing can be updated.");
               return false;
            }
            
            // Get a reference to the raw data objects
            // Note, this will not ever be null.
            java.util.LinkedHashMap<Object,Object> mapRawData = exInfo.getRawData();
            
            // Get existing WebAuthn Credentials
            java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapWebAuthnCredentials = (java.util.LinkedHashMap<String,java.util.Map<String,Object>>)mapRawData.get(keyNameForRegisteredCredentials);
            // Should not be null. If null, then exit.
            if (mapWebAuthnCredentials == null) {
                log.error("No WebAuthn credentials for User="+databaseUsernameInternal+". Nothing can be updated.");
                return false;
            }
            
            // Delete the WebAuthn credential
            mapWebAuthnCredentials.remove( credentialId);
            
            // Save the updated information
            try { 
                // Using special Authentication Token in case current User does not have permission. 
                endEntityManagementSession.changeUser( new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - Removing WebAuthn credential")), eeInfo, false);
            } catch (NoSuchEndEntityException | CADoesntExistsException | ApprovalException | CertificateSerialNumberException | IllegalNameException | CustomFieldException | AuthorizationDeniedException | EndEntityProfileValidationException | WaitingForApprovalException e) {
                log.error("Could not save credential data for User="+databaseUsernameInternal);
                return false;
            }
            
            log.info("End-entity updated with WebAuthn credential data. User="+databaseUsernameInternal+" Total credentials saved: "+mapWebAuthnCredentials.size());
            return true;
        }
    }
    
    private static final long serialVersionUID = 2L;
    private static final Logger log = Logger.getLogger(MyWebAuthnRegMBean.class);
    private static final SecureRandom random = new SecureRandom();
    // Stu 21JAN25. Setting the hostname to be that used in the global 'web.property' file.
    public static final String HOSTNAME_WEBAUTHN = org.ejbca.config.WebConfiguration.getHostName();
    public static final String SESSION_ATTRIBUTE_WEBAUTHN_PKCO = "webauthn.pkco";
    public static final String OAUTH_PROVIDER_NAME = "EJBCA WebAuthn Login";
    
    // The username in the DB for the current logged-in Administrator. 
    // It could be blank in some cases when using a 3rd-party OAuth provider. In this case
    // the WebAuthn Registration process is not available as any credential information cannot
    // be saved into the DB.
    // This field is set in the PostConstruct.
    final private String databaseUsername;
    
    // Support code/logic for the Yubico library.
    // Instantiated in the PostConstruct.
    final private EjbcaCredentialRepository4Registration ejbcaCredentialRepository;


    // The 3rd line on the page is available to report any errors to the User.
    private String errorText = "";
    

    // Holds the Registration request 'publicKeyCredentialCreationOptions' in JSON
    private String pkco  = "''";  // Need the default to be empty JS string to keep the JS syntax in order.
   

    // pkc is shorthand for PublicKeyCredential. The response from a Registration event is a PublicKeyCredential
    // which is then converted to JSON and then converted to a string.
    private String pkc = "";
    

    public static com.yubico.webauthn.data.RelyingPartyIdentity rpIdentity = com.yubico.webauthn.data.RelyingPartyIdentity.builder()
            .id(HOSTNAME_WEBAUTHN) // Set this to a parent domain that covers all subdomains
                                  // where users' credentials should be valid
            .name("EJBCA")
            .build();





    public MyWebAuthnRegMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR);
        
        // For WebAuthn Registrations, the Administrator must have a database 'username' as this will be used to store 
        // the WebAuth credential information. Note the when using 3rd-party OAuth, the Administrator may not have an account.
        // The 'EjbcaWebBeanImpl class has determined the Username in the DB.
        databaseUsername =  ((EjbcaWebBeanImpl)getEjbcaWebBean()).getDatabaseUsername();

        // Set up the EjbcaCredentialRepository4Registration class 
        ejbcaCredentialRepository = new EjbcaCredentialRepository4Registration(databaseUsername);
   }
    
    

    /*
     * User has clicked the Register button
     */
    public void clickRegister() {
        // Initiate the web browser to do WebAuthn registration
        processRegistrationRequest();    
    }

    /**
     * Trigger the Web-browser to start a WebAuthn registration request. This involves:
     * 1. Set up the 'PublicKeyCredentialCreationOptions' data
     * 2. Set the 'pkco' variable in the javascript. This will trigger the browser to start a WebAuthn registration process.
     * 3. Save information into the web-session which is used later as part of the verifications.
     */
    public void processRegistrationRequest()  {
            
      // Create the RelyingParty
      final com.yubico.webauthn.RelyingParty rp = com.yubico.webauthn.RelyingParty.builder()
              .identity(rpIdentity)
              .credentialRepository(ejbcaCredentialRepository)
              .build();

       // Create the UserIdentity
       // Use the current logged-in admin
      final com.yubico.webauthn.data.UserIdentity user = com.yubico.webauthn.data.UserIdentity.builder()
                .name( databaseUsername)
                .displayName( databaseUsername)
                .id( ejbcaCredentialRepository.getUserHandleForUsername(databaseUsername).get())
                .build();
 
        // Create a random Challenge. 
        final byte[] randomBytes = new byte[32];
        random.nextBytes(randomBytes);
        final com.yubico.webauthn.data.ByteArray baChallenge = new com.yubico.webauthn.data.ByteArray(randomBytes);
        
        // Create the PublicKeyCredentialCreationOptions which is the WebAuthn Registration request data.
        final com.yubico.webauthn.data.PublicKeyCredentialCreationOptions request = com.yubico.webauthn.data.PublicKeyCredentialCreationOptions.builder()
                .rp(rpIdentity)
                .user(user)
                .challenge(baChallenge)
                .pubKeyCredParams( java.util.Collections.unmodifiableList(java.util.Arrays.asList(
                        com.yubico.webauthn.data.PublicKeyCredentialParameters.ES256,    // EC is more common for WebAuthn tokens.
                        com.yubico.webauthn.data.PublicKeyCredentialParameters.RS256     // RSA key required to support Win Hello.
                      )))
                .authenticatorSelection( com.yubico.webauthn.data.AuthenticatorSelectionCriteria.builder()
                        .residentKey( com.yubico.webauthn.data.ResidentKeyRequirement.DISCOURAGED)                   // Non-resident keys are quick, with unlimited storage!
                        .userVerification( com.yubico.webauthn.data.UserVerificationRequirement.REQUIRED )           // UV required - 2 factor
                        //.authenticatorAttachment( com.yubico.webauthn.data.AuthenticatorAttachment.CROSS_PLATFORM) // For physical security Keys
                        //.authenticatorAttachment( com.yubico.webauthn.data.AuthenticatorAttachment.PLATFORM)       // For internal device keys. 
                        .build())
                .attestation(com.yubico.webauthn.data.AttestationConveyancePreference.DIRECT)
                // Using excludeCredentials to prevent a User storing multiple credentials on the same token.
                .excludeCredentials( ejbcaCredentialRepository.getPublicKeyCredentialDescriptors())
                .build();
        
                
        // Send the pkco to the client
        // Note: Some  data in base64Url strings will need converting by the javascript to ArraySource
        try {
            pkco = request.toCredentialsCreateJson();
            log.info("WebAuthn registration data being sent to client: "+pkco);

            // Save the request in the session. This will be used for response verification purposes
            final HttpServletRequest httpServletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            httpServletRequest.getSession(true).setAttribute(SESSION_ATTRIBUTE_WEBAUTHN_PKCO, request);


        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            log.error(e);
            internalError("The WebAuthn registration request could not be generated.");
        }
    }


    /**
     * Handle the WebAuthn registration response. The response is in a hidden input field 'pkc' within the Form.
     * The following steps are involved:
     * 1. Verification of the response data. Yubico library handles most of this.
     * 2. Check that 2-factor is being used (ie., the token along with a PIN)
     * 3. Issue a certificate using the public key in the WebAuthn credential.
     * 4. Save credential data into the DB
     * 5. Update access controls for the new certificate.
     */
    public void processRegistrationResponse()  {
        
        // Clear the 'pkco' variable in javascript to prevent further triggering of the WebAuthn Registration process.
        pkco  = "''";
        
        // Validate the registration response.
        final String publicKeyCredentialJson = pkc;     // publicKeyCredential from client
        log.info("Response from WebAuthn registration: "+publicKeyCredentialJson);
        
        // Clear the hidden input field on the page.
        pkc = "";
        
        // Validate the token response
        // Using YUBICO source from WebAuthn project
        final com.yubico.webauthn.data.PublicKeyCredential<com.yubico.webauthn.data.AuthenticatorAttestationResponse, com.yubico.webauthn.data.ClientRegistrationExtensionOutputs> regoResponse;
        try {
            regoResponse = com.yubico.webauthn.data.PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredentialJson);
            
            // To validate the response, we need the RelyingParty and the Request
            final com.yubico.webauthn.RelyingParty rp = com.yubico.webauthn.RelyingParty.builder()
                    .identity(rpIdentity)
                    .credentialRepository(ejbcaCredentialRepository)
                    .allowOriginPort(true) // Ignore the port value
                    // TODO: Need to add trust sources. Allowing untrusted tokens is not good practice.
                    .allowUntrustedAttestation(true)
                    .build();

           
            // The 'request' is required as part of validation process. The 'request' data was saved in the web-session
            final HttpServletRequest httpServletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            final com.yubico.webauthn.data.PublicKeyCredentialCreationOptions request = 
                    (com.yubico.webauthn.data.PublicKeyCredentialCreationOptions)httpServletRequest.getSession(true).getAttribute(SESSION_ATTRIBUTE_WEBAUTHN_PKCO);
            if ( request == null) {
                throw new Exception( "The 'request' data was not in the session, and as such the response is not verifiable.");
            }
            // Remove the session attribute
            httpServletRequest.getSession(true).removeAttribute(SESSION_ATTRIBUTE_WEBAUTHN_PKCO);
           
            final com.yubico.webauthn.RegistrationResult result;
            try {
                result = rp.finishRegistration( com.yubico.webauthn.FinishRegistrationOptions.builder()
                    .request(request)  // The PublicKeyCredentialCreationOptions from session
                    .response( regoResponse)
                    .build());
            } catch (com.yubico.webauthn.exception.RegistrationFailedException e) { 
                throw new Exception( e);

            }
            
 
            // Check UV flag
            // Note: Yubico probably checks this, but just in case
            if ( ! result.isUserVerified() ) {
                internalError("The new WebAuthn token does not support User Verification. Please try again. with another token.");
                return;
            }
            
            // Issue a certificate for the PublicKey for this new WebAuthn credential 
            // Convert the public key into java-base public key
            // Need the CBOR and COSE libraries for this.
            java.security.cert.Certificate certIssuedFromPublicKey = null;
            try {
                final com.upokecenter.cbor.CBORObject cborObj =  com.upokecenter.cbor.CBORObject.DecodeFromBytes(  result.getPublicKeyCose().getBytes());
                final COSE.OneKey coseKey = new COSE.OneKey( cborObj);
                final java.security.PublicKey pubKey = coseKey.AsPublicKey();
                
                //log.info("PublicKey algorithm for the WebAuthn token: "+pubKey.getAlgorithm());
                
                // Create a Simple Request for the User and PublicKey
                // Note: Using a random password in the request.
                final SimpleRequestMessage simpleReq = new SimpleRequestMessage( pubKey, databaseUsername, new AllPrintableCharPasswordGenerator().getNewPassword(15, 20));
               
                // Get an AuthencationToken
                final AlwaysAllowLocalAuthenticationToken authtoken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - Issuing WebAuthn certificate"));
                
                // Issue certificate
                final X509ResponseMessage response = (X509ResponseMessage) signSession.createCertificateIgnoreStatus( authtoken,
                        simpleReq, X509ResponseMessage.class, /* ignorePassword*/true);
                if (response.getStatus() == ResponseStatus.SUCCESS){
                    certIssuedFromPublicKey = response.getCertificate();
               }
                else {
                    log.error("Certificate request failed: " + response.getFailText() );
                    internalError("A certificate for the new WebAuthn credential could not be issued. Please contact a System Administrator.");
                   return;
                }
            } catch (Exception e) {
                // Any exception to return with an error message
                log.error(e);
                internalError("A certificate for the new WebAuthn credential could not be issued. Please contact a System Administrator.");
                return;
            }

            
            // The verification passed!
            // Save the new credential
            boolean bEEupdated = ejbcaCredentialRepository.updateEndEntityWithWebAuthnCredential( result.getKeyId().getId(), result.getPublicKeyCose(), result.getSignatureCount() , certIssuedFromPublicKey );
            if (!bEEupdated) {
                internalError("The new WebAuthn credential was not saved due to an error. Please contact a System Administrator.");
                return;
            }
            
            
//            // Get configuration data regarding WebAuthn Login
//            OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
//            OAuthKeyInfo oAuthKeyInfo = oAuthConfiguration.getOauthKeyByLabel(OAUTH_PROVIDER_NAME);
// 
            

            // The User's WebAuthn credentials saved. Now add the certificate details to the same Access Role this Admin already has.
            // Get some certificate details that are required later.
            String sCertSerialNum = CertTools.getSerialNumberAsString(certIssuedFromPublicKey);
            int iCaId = endEntityAccessSession.findByUsername(databaseUsername).getCaId();
                     
            // Find Roles that the current logged in User is a member of:
            List<org.cesecore.roles.Role> roles = roleSession.getRolesAuthenticationTokenIsMemberOf(getAdmin());
            for ( org.cesecore.roles.Role role : roles) {
                //log.info("Current user belongs to role: "+role.getName());
     
                // Create a new RoleMember based upon the newly issued certificate
                org.cesecore.roles.member.RoleMember roleMember = new RoleMember( 
                        org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                        iCaId,
                        RoleMember.NO_PROVIDER,
                        org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                        AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                        sCertSerialNum,
                        role.getRoleId(),
                        "WebAuthn credential for "+databaseUsername
                        );
                //OAuth config and the current User's name.
//                org.cesecore.roles.member.RoleMember roleMember = new RoleMember(OAuth2AuthenticationTokenMetaData.TOKEN_TYPE,
//                        RoleMember.NO_ISSUER, oAuthKeyInfo.getInternalId(), OAuth2AccessMatchValue.CLAIM_SUBJECT.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
//                        currentLoggedInUsername, role.getRoleId(), null);

//                log.info( "RoleMember ID is "+roleMember.getId());
                try {
                    // Check if the User details are already added to this Role as we don't want to duplicate.
                    // Should not happen as we are using serial number matching.
                    boolean bNewRoleMember = true;
                    List<org.cesecore.roles.member.RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(
                            new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Searching Members of Role before adding access to a new WebAuthn credential")), 
                            role.getRoleId());
                    for (org.cesecore.roles.member.RoleMember rm : roleMembers) {
                        if (rm.isSameAs(roleMember)){
                            bNewRoleMember = false;
                            log.info("The WebAuthn User '"+databaseUsername+"' is already assigned to the role '"+role.getName()+"'.");
                            break;
                        }
                    }
                    
                    if (bNewRoleMember) {
                        // Add the new RoleMember to the Role.
                        roleMember = roleMemberSession.persist(
                                new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - Adding WebAuthn credential to Role")), 
                                roleMember);
                        log.info("Added the WebAuthn User '"+databaseUsername+"' to the role '"+role.getName()+"'.");
                    }
                } catch (AuthorizationDeniedException e) {
                    internalError("The new WebAuthn credential was not assigned into a role. This may prevent access to the site.");
                    log.error("Failed to add new Member to a Role. Details: "+e.getMessage()); 
                    return;
                }
            }
            
        } catch (Exception e) {
            internalError("The WebAuthn registration process was not successful. Please contact a System Administrator.");
            log.error( "The WebAuthn registration response could not be processed or validated. Further details: "+e.getMessage());
            return;
        }
    }


    //
    // The following methods are used do display credential data on the page.
    //
    
    // As the credential data is in the DB, we can take a temporary cache of the data to be more efficient.
    private java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapTempCacheOfCredentials;
    
    public ListDataModel<String> getCredentials() {
        
        // This method is called first on the page, so setup the temp cache.
        mapTempCacheOfCredentials = ejbcaCredentialRepository.getWebAuthnCredentialsForEndEntity();

        // Grab all the Credential IDs. These are the 'key' entries in the map
        java.util.ArrayList<String> listCredentialIDs = new java.util.ArrayList<String>();
        if (mapTempCacheOfCredentials != null) {
            for (String s : mapTempCacheOfCredentials.keySet()) {
                listCredentialIDs.add(s);
            }
        }
        return new ListDataModel<>(listCredentialIDs);
    }

    public String getSignatureCount( String credentialId) {
        // Assume the temporary cache of data
        if (mapTempCacheOfCredentials != null && mapTempCacheOfCredentials.containsKey( credentialId) ) {
            if ( mapTempCacheOfCredentials.get(credentialId).containsKey("SignatureCount")) {
                return ""+(long)mapTempCacheOfCredentials.get(credentialId).get("SignatureCount"); 
            }
        }
        return "";
    }
    
    public String getCreationDate( String credentialId) {
        // Assume the temporary cache of data
        long lTime = 0;
        if (mapTempCacheOfCredentials != null && mapTempCacheOfCredentials.containsKey( credentialId) ) {
            if ( mapTempCacheOfCredentials.get(credentialId).containsKey("CreationDate")) {
                lTime = (long)mapTempCacheOfCredentials.get(credentialId).get("CreationDate"); 
            }
        }

        if (lTime <= 0) return "";
       
        // Make it a Date
        java.util.Date date = new java.util.Date();
        date.setTime(lTime);
        
        //Get a string representation
        return date.toString();
    }

    public String getAssertionDate( String credentialId) {
        // Assume the temporary cache of data
        long lTime = 0;
        if (mapTempCacheOfCredentials != null && mapTempCacheOfCredentials.containsKey( credentialId) ) {
            if ( mapTempCacheOfCredentials.get(credentialId).containsKey("AssertionDate")) {
                lTime = (long)mapTempCacheOfCredentials.get(credentialId).get("AssertionDate"); 
            }
        }

        if (lTime <= 0) return "";
       
        // Make it a Date
        java.util.Date date = new java.util.Date();
        date.setTime(lTime);
        
        //Get a string representation
        return date.toString();
    }
    
    public String getCertFingerPrint( String credentialId) {
        // Assume the temporary cache of data
        if (mapTempCacheOfCredentials != null && mapTempCacheOfCredentials.containsKey( credentialId) ) {
            if ( mapTempCacheOfCredentials.get(credentialId).containsKey("CertFingerPrint")) {
                return (String)mapTempCacheOfCredentials.get(credentialId).get("CertFingerPrint"); 
            }
        }
        return "";
    }
    
    public String getCertExpiryDate( String credentialId) {
        // Assume the temporary cache of data
        long lTime = 0;
        if (mapTempCacheOfCredentials != null && mapTempCacheOfCredentials.containsKey( credentialId) ) {
            if ( mapTempCacheOfCredentials.get(credentialId).containsKey("CertExpiry")) {
                lTime = (long)mapTempCacheOfCredentials.get(credentialId).get("CertExpiry"); 
            }
        }

        if (lTime <= 0 ) return "";
       
        // Calc the days remmaining
        java.util.Date dateNow = new java.util.Date();
        lTime = lTime - dateNow.getTime() ;

        // Expired?
        if (lTime <= 0) return "Expired";

        // Convert to days
        lTime = lTime / (1000*3600*24);
        
        //Get a string representation
        return ""+lTime;
    }

    
    // Show the currently logged-in DB Username on 'mywebauth.xhtml' page. 
    public String getCurrentLoggedInUsername() {
        return databaseUsername;
    }


    // If the User has a valid DB account, then we can allow WebAuthn Registrations.
    public boolean hasValidDbUsername() {
       return (databaseUsername != null && databaseUsername.length()>0);
    }


    // Display an error to the User
    private void internalError(final String logMessage) {
        log.error(logMessage);
        setErrorText("ERROR: "+logMessage);
        
    }

    
    public String getViewCertlink( String credentialId) {
        // Get fingerprint of cert
        if (mapTempCacheOfCredentials != null && mapTempCacheOfCredentials.containsKey( credentialId) ) {
            if ( mapTempCacheOfCredentials.get(credentialId).containsKey("CertFingerPrint")) {
                String sCertFP =  (String)mapTempCacheOfCredentials.get(credentialId).get("CertFingerPrint"); 
                
                // Get cert details
                java.security.cert.Certificate cert = certificateStoreSession.findCertificateByFingerprint(sCertFP);
                if (cert==null) return "";
                
                // Raise a new tab to view cert
                String link;
                try {
                    link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                            + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
                            + "viewcertificate.xhtml?certsernoparameter="
                            + java.net.URLEncoder.encode(CertTools.getSerialNumberAsString(cert)+ "," + CertTools.getIssuerDN(cert), "UTF-8");
                } catch (final UnsupportedEncodingException e) {
                    throw new EJBException(e);
                }
                return "window.open('" + link + "', 'ViewCertAction', 'width=800,height=800,scrollbars=yes,toolbar=no,resizable=yes').focus()";
                
                
            }
        }
        return "";
    }
    
    
    public boolean renderDeleteButton(String credentialId) {
        // Check if this credential is currently logged in
        if ( getCertFingerPrint( credentialId).equalsIgnoreCase( this.getEjbcaWebBean().getCertificateFingerprint())) {
            return false;
        }
        return true;
    }

    public void actionDeleteCredentialStart( String credentialId) {
        // Setting the 'credentialRowSelected' will trigger the confirmation alert.
        credentialRowSelected = credentialId;
    }
    
    public void actionDeleteCredentialReset() {
        // Clear the row selected by User
        credentialRowSelected=null;
    }
    
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    public void actionDeleteCredentialConfirm( ) {
        log.info("Deleting WebAuthn Credential ID="+credentialRowSelected+" by user="+databaseUsername); 
        
        // Grab some details before deleting.
        String sCertFingerprint = getCertFingerPrint( credentialRowSelected);
        
        
        // Delete the selected credential from the User's DB entry.
        ejbcaCredentialRepository.deleteWebAuthnCredentialForEndEntity( credentialRowSelected);
        
        // Revoke the certificate, if not expired.
        // Note: The WebAuthn credential won't be able to authenticate after deleting, but still good practice to also revoke
        // the associated certificate.
        org.cesecore.certificates.certificate.CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(sCertFingerprint);
        if( CertTools.getNotAfter( cdw.getCertificate()).after( new java.util.Date())) {
            try {
                certificateStoreSession.setRevokeStatus(
                        new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - Revoking WebAuthn certificate")), 
                        cdw, 
                        new java.util.Date(), 
                        new java.util.Date(), 
                        org.cesecore.certificates.crl.RevocationReasons.CESSATIONOFOPERATION.getDatabaseValue());
            } catch (CertificateRevokeException | AuthorizationDeniedException e) {
                log.error("Failed to revoke WebAuthn credential. Cert fingerprint="+sCertFingerprint);
            }
        }
        
        // Remove any Access that was based upon the serial number of this certificate.
        // Note: Useful to clean up any entries that were automatically added during the Registration process.
        String sSerialNum = CertTools.getSerialNumberAsString( cdw.getCertificate() );
        int iCaId = endEntityAccessSession.findByUsername(databaseUsername).getCaId();
        
        // Check through all Roles for a match
        List<org.cesecore.roles.Role> roles = roleSession.getAuthorizedRoles(
                new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Searching all Roles before removing a WebAuthn credential access"))
                );
        for ( org.cesecore.roles.Role role : roles) {
            
            // Get the Members for this Role
            try {
                List<org.cesecore.roles.member.RoleMember> roleMembers;
                roleMembers = roleMemberSession.getRoleMembersByRoleId(
                        new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Searching Members in Role before removing a WebAuthn credential access")), 
                        role.getRoleId());
                for (org.cesecore.roles.member.RoleMember rm : roleMembers) {
                    // Find any Members that match the User's certificate
                    // Match is based upon the Cert's serialnumber and Issuing CA reference.
                    if ( rm.getTokenMatchValue().equalsIgnoreCase(sSerialNum)
                            && rm.getTokenMatchKey()==org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue()
                            && rm.getTokenIssuerId()==iCaId
                       ) {
                        // Match found. Remove the Member
                        roleMemberSession.remove(
                                new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - Removing WebAuthn credential from Role")), 
                                rm.getId()
                                );
                    }
                }
            } catch (AuthorizationDeniedException e) {
                log.error("Failed to remove access for certificate with serial number="+sSerialNum+" from role="+role.getRoleName());
            }
        }        
       
        // Clear the row selected by User
        credentialRowSelected = null;
    }


//    private void redirectToAdminweb() throws IOException {
//        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
//        ec.redirect(ec.getRequestContextPath());
//    }

    
    
    // Normal Getter and Setters...
    
    public String getErrorText() {
        return errorText;
    }

    public void setErrorText(String errorText) {
        this.errorText = errorText;
    }

    public String getPkco() {
        return pkco;
    }

    public void setPkco(String pkco) {
        this.pkco = pkco;
    }
    
    public String getPkc() {
        return pkc;
    }

    public void setPkc(String pkc) {
        this.pkc = pkc;
        // Check if thereis WebAuthn Registration response to process.
        if ( (pkc!=null) && (!pkc.equals(""))) {
            processRegistrationResponse();
        }
    }
    
    private String credentialRowSelected = null;
    
    public boolean isDeleteStarted() {
        return (credentialRowSelected != null);
    }
    
    public String getCredentialRowSelected() {
        return credentialRowSelected;
    }
    
    
    public String getCredentialRowSelectedIssuedAt() {
        return getCreationDate( credentialRowSelected);
    }

    public String getCredentialRowSelectedLastUsed() {
        return getAssertionDate( credentialRowSelected);
    }

    public String getCredentialRowSelectedExpiresIn() {
        String s = getCertExpiryDate( credentialRowSelected);
        if (!s.contains("Expired")) {
            s += " days";
        }
        return s;
    }

    public String getCredentialRowSelectedCertFingerprint() {
        return getCertFingerPrint( credentialRowSelected);
    }
}
