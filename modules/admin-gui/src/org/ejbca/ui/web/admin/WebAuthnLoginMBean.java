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
package org.ejbca.ui.web.admin;


import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import java.util.Optional;
import java.util.Set;


import jakarta.ejb.EJB;
import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Named;

import jakarta.servlet.http.HttpServletRequest;


import org.apache.log4j.Logger;

import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;

import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.nimbusds.jose.util.Base64URL;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.exception.AssertionFailedException;

import COSE.CoseException;

/**
 * Bean used to display a login page.
 */
@Named("webAuthnLoginMBean")
@SessionScoped
public class WebAuthnLoginMBean extends BaseManagedBean implements Serializable {

    /*
     * A class that needs to be implemented to work with the Yubico library.
     * Methods will read/write the EJBCA database (UserData table)
     */
   private class EjbcaCredentialRepository4Assertion implements com.yubico.webauthn.CredentialRepository{
        
       final private String databaseUsername;
        
        public EjbcaCredentialRepository4Assertion( String userName) {
            databaseUsername = userName;
        }

        
        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String notused) {
            // Note: Using the 'username' field and not the parameter.
            final java.util.Set<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> setReturn = new java.util.HashSet<PublicKeyCredentialDescriptor>();
            
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

        /*
         * Get the 'RegisteredCredential' information from the DB for this User and CredentialId reference.
         */
        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            
            java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapTemp = getWebAuthnCredentialsForEndEntity();
            if (mapTemp == null) {
                return Optional.empty();
            }
            
            String sCredentialId = credentialId.getBase64();
            
            if ( mapTemp.containsKey(sCredentialId)) {
                // This CredentialId does exist.
                ByteArray pubKeyCose = ByteArray.fromBase64( (String)mapTemp.get(sCredentialId).get("PublicKeyCose"));
                long signatureCount = (long)mapTemp.get(sCredentialId).get("SignatureCount");

                com.yubico.webauthn.RegisteredCredential rc =  com.yubico.webauthn.RegisteredCredential.builder()
                        .credentialId( credentialId)
                        //.userHandle( getUserHandleForUsername( sUserName).get())
                        .userHandle( userHandle) // Return what was passed in to avoid a verification error
                        .publicKeyCose( pubKeyCose)
                        .signatureCount( signatureCount)
                        .build();
                     
                return Optional.of(rc);
            } else {
                // CredentialId is not known by this user.
                return Optional.empty();
            }
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            // Only used in registrations.
            return new java.util.HashSet<RegisteredCredential>();
        }
        
        /*
         * Update the DB with the latest 'Signature Count' and 'Assertion Date' for this WebAuthn credential. It is also useful to return the
         * fingerprint of the associated certificate, which will be used for the 'psuedo' certificate authentication.
         * Any errors will return a null. 
         */
        @SuppressWarnings("finally")
        public String updateEndEntityWithWebAuthnAndReturnCertificateFingerPrint( ByteArray credentialId, long signatureCount) {

            // Get the User information from DB
            final EndEntityInformation eeInfo = endEntityAccessSession.findUser(databaseUsername);
            if ( eeInfo == null) {
                log.error("The user '"+databaseUsername+"' cannot be found. Nothing will be stored.");
                return null;
            }
            
            // Get the User's extended information
            final ExtendedInformation exInfo = eeInfo.getExtendedInformation();
            // If null, then this is an error
            if (exInfo ==null) {
               log.error("ExtendedInformation doesn't exist for User="+databaseUsername);
               return null;
            }
            
            // Get a reference to the raw data objects
            // Note, this should not ever be null.
            final java.util.LinkedHashMap<Object,Object> mapRawData = exInfo.getRawData();
            
            // Check for existing WebAuthn Credentials
            // Note: These will be a Map which is supported by the XML serialization
            
            final java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapWebAuthnCredentials = (java.util.LinkedHashMap<String,java.util.Map<String,Object>>)mapRawData.get( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.keyNameForRegisteredCredentials);
            if (mapWebAuthnCredentials == null) {
                // An error if null
                log.error("WebAuthn credentials doesn't exist for User="+databaseUsername);
                return null;
            }
            
            //   Update existing WebAuthn records
            // The key will be the CredentialId (in base 64)
            final String sCredentialId = credentialId.getBase64();
            if (!mapWebAuthnCredentials.containsKey(sCredentialId)) {
                // Credential doesn't exit. This should not happen
                log.error("The provided credentialId doesn't exist for User="+databaseUsername);
                return null;
            }
            
            final java.util.LinkedHashMap<String, Object> mapCredential = (java.util.LinkedHashMap<String,Object>)mapWebAuthnCredentials.get( sCredentialId);
            // Update SignatureCount
            log.info("Updating SignatureCount to "+signatureCount);
            mapCredential.put( "SignatureCount", signatureCount);
            mapCredential.put( "AssertionDate", new java.util.Date().getTime());

            // Get the cert associated with this CredentialId
            String sCertFingerprint = (String)mapCredential.get("CertFingerPrint");
            
            if (sCertFingerprint != null) {
                // Check the publickey in the cert matches the publickey for this Credential. If this does not match,
                // then the 'psuedo' certificate authentication is not permitted.
                // Get the actual certificate
                X509Certificate certificate = (X509Certificate) certificateStoreLocal.findCertificateByFingerprint(sCertFingerprint);
                if ( certificate != null) {

                    try {
                        log.debug("WebAuthn cert="+CertTools.getPEMCertificate( certificate.getEncoded()));
                    } catch (CertificateEncodingException e) {
                        // Ignore
                    }

                    java.security.PublicKey pkCert = certificate.getPublicKey();
                    
                    // Get the Credential's publickey. Should always exist.
                    ByteArray pubKeyCose = ByteArray.fromBase64( (String)mapCredential.get("PublicKeyCose"));
                    
                    // Need to convert format.
                    com.upokecenter.cbor.CBORObject cborObj =  com.upokecenter.cbor.CBORObject.DecodeFromBytes(  pubKeyCose.getBytes());
                    try {
                        COSE.OneKey coseKey = new COSE.OneKey( cborObj);
                        java.security.PublicKey pubKey = coseKey.AsPublicKey();
                        
                        // The two Public Keys should match
                        if ( !Arrays.equals(pubKey.getEncoded(), pkCert.getEncoded()) ) {
                            // Not a match. This certificate fingerprint will have to be ignored
                            log.info("The certificate for this WebAuthn credential does not have a matching public key. Will continue without it.");
                            sCertFingerprint = null;
                        } else {
                            log.info("The public key for this credential is a match with the certificate.");
                        }
                    } catch (CoseException e) {
                        sCertFingerprint = null;
                        log.error("Failed to convert the PublicKeyCose for this credential. Cannot convert the certificate. Details: "+e.getMessage());
                        return null;
                    }
                 } else {
                    // Cannot find the actual certificate. Should not happen!
                    log.error("No certificate for this WebAuthn credential. This authentication is rejected.");
                    return null;
                }
            } else {
                // No certificate reference. Should not happen, but we can continue with normal OAuth type login.
                log.warn("No certificate fingerprint for this WebAuthn credential. This authentication will get rejected.");
                return null;
            }
            
            // Save the updated information
            try { 
                endEntityManagementSession.changeUser( new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal - WebAuthn login success")), eeInfo, false);
            } catch (NoSuchEndEntityException | CADoesntExistsException | ApprovalException | CertificateSerialNumberException | IllegalNameException | CustomFieldException | AuthorizationDeniedException | EndEntityProfileValidationException | WaitingForApprovalException e) {
                log.warn("Could not update the WebAuthn signature count value for User="+databaseUsername);
                //return false;
            } finally {
                return sCertFingerprint;

            }
         }
        
        
        private java.util.LinkedHashMap<String,java.util.Map<String,Object>> getWebAuthnCredentialsForEndEntity() {
            
            // Get the User from DB
            EndEntityInformation eeInfo = endEntityAccessSession.findUser(databaseUsername);
            if ( eeInfo == null) {
                log.error("The user '"+databaseUsername+"' cannot be found. Nothing will be returned.");
                return null;
            }

            // Get the User's extended information
            ExtendedInformation exInfo = eeInfo.getExtendedInformation();
            // If null, then there isn't any data to return
            if (exInfo ==null) {
                log.info("The user '"+databaseUsername+"' does not have ExtendedInformation. Nothing will be returned.");
                return null;
            }
            
            // Get a reference to the raw data objects
            // Note, this will not ever be null.
            java.util.LinkedHashMap<Object,Object> mapRawData = exInfo.getRawData();

            // Check for existing WebAuthn Credentials
            // Note: These will be a Map which is supported by the XML serialization
            
            java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapWebAuthnCredentials = (java.util.LinkedHashMap<String,java.util.Map<String,Object>>)mapRawData.get( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.keyNameForRegisteredCredentials);
            if (mapWebAuthnCredentials == null) {
                log.info("The user '"+databaseUsername+"' does not have any WebAuthn credentials stored.");
                return null;
            }
            
            return mapWebAuthnCredentials;
        }
        
        public java.util.List<String> getCredentialsCreationDates( ){
            java.util.ArrayList<String> listReturn = new java.util.ArrayList<String>();
            
            java.util.LinkedHashMap<String,java.util.Map<String,Object>> mapTemp = getWebAuthnCredentialsForEndEntity();
            if (mapTemp == null) {
                return listReturn;
            }
            
            for (String s : mapTemp.keySet()) {
                long lCreationDate = (long)mapTemp.get(s).get("CreationDate"); 
                listReturn.add(""+lCreationDate);
            }
            
            return listReturn;
         }
        
    }

    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(WebAuthnLoginMBean.class);
    private static final SecureRandom random = new SecureRandom();
    private static final String ADMIN_PAGE = "/ejbca/adminweb/";
    
    // Store OAuth codes and associated data
    // Entries are to be one-time use only.
    private static final java.util.concurrent.ConcurrentHashMap<String, java.util.HashMap<String, Object>> mapCodes =
            new java.util.concurrent.ConcurrentHashMap<String, java.util.HashMap<String, Object>>();
    
    private String firstHeader = "EJBCA WebAuthn Login";
    private String secondHeader = "";
    private String text = "Use your WebAuthn token to login into EJBCA.";

    private EjbcaWebBean ejbcaWebBean;
    

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreLocal;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSessionLocal;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;




    // The Username entered by the person logging in via the WebAuthn login page.
    // Note: This data cannot be trusted until the WebAuthn login completes. The validation will prove the Username value at
    // that time of validation. 
     private String username="";
    
    
    // Public Key Credential Options. This is sent to the WebClient to prepare for WebAuthn login.
    private String pkco  = "''"; // Need the default to be empty JS string to keep the JS syntax in order.

    // Public Key Credential. This is the AuthenticatorAssertionReponse from the WebClient after WebAuthn login
    private String pkc = "";
    
    // The 'redirect_uri' parameter provided in the OAuth request. This is the URL to use once the OAuth authentication completes.
    private String sRedirectUri = null;

    // The 'state' parameter provided in the OAuth request. This must me returned back to the client unmodified.
    private String sState = null;

 
    /**
     * Invoked when login.xhtml is rendered. 
     * Get some parameters that are passed in by the OAuth handler. 
     */
    @SuppressWarnings("unchecked")
    public void onLoginPageLoad() throws Exception {
        log.info("onPageLoad");
        ejbcaWebBean = getEjbcaErrorWebBean();
        HttpServletRequest servletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        ejbcaWebBean.initialize_errorpage(servletRequest);
        
        // Get the 'redirect_uri' and 'state' parameters from the query string. 
        // Note: Parameters should only exist in the GET method
        if ( servletRequest.getMethod().equalsIgnoreCase("GET")) {
            String redirectUri = servletRequest.getParameter("redirect_uri");
            if (redirectUri != null) {
                
                // TODO: A user could tamper with the redirect uri. Should we check the redirect uri????
                // The URI could be checked to be the EJBCA Admin Page or the RA login page?

                // Only set a value once (ie., prevent a User tampering upon subsequent web requests)
                sRedirectUri = redirectUri;
                log.debug("Setting the redirect URI="+redirectUri);
            }
            
            // Get the 'state' value from the query string.
            // If a person tampers with this data, then the OAuth process will get aborted. No checking required.
            String state = servletRequest.getParameter("state");
            if  (state != null) {
                sState = state;
            }
       }
    }
    

    public void setupPkco() {
        
        // Do nothing unless the User has entered a userName
        if (username==null || username.equals("")) {
            pkco = "''";
            return;
        }
        
        // Local copy of username
        final String userName = username;
        
        final EjbcaCredentialRepository4Assertion  ejbcaCredentialRepository= new EjbcaCredentialRepository4Assertion(userName);
        
        // Create the RelyingParty
        final com.yubico.webauthn.RelyingParty rp = com.yubico.webauthn.RelyingParty.builder()
                .identity( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.rpIdentity)
                .credentialRepository(ejbcaCredentialRepository)
                .build();
        
        final com.yubico.webauthn.AssertionRequest request = rp.startAssertion( com.yubico.webauthn.StartAssertionOptions.builder()
                //.username(userName)
                //.userHandle( ejbcaCredentialRepository.getUserHandleForUsername( userName))
                
                // Must use empty UserName in order to validate Non-Resident keys
                .username("")
                .userVerification( com.yubico.webauthn.data.UserVerificationRequirement.REQUIRED)
                .build()
                );
        
       
        // Send the pkco to the client
        // Note: Some  data in base64Url strings will need converting by the javascript to ArraySource
        try {
            pkco = request.toCredentialsGetJson();
            log.info("WebAuthn assertion data being sent to client: "+pkco);

            // Save the request in the session. This will be used for response verification purposes
            final HttpServletRequest httpServletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            httpServletRequest.getSession(true).setAttribute( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.SESSION_ATTRIBUTE_WEBAUTHN_PKCO, request);


        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            log.error(e);
            internalError("The WebAuthn registration request could not be generated.");
            pkco="''";
        }
        
        return;
    }

 
public boolean validateLogin( final String publicKeyCredentialJson, final String userName) {
    // Note: Validation is going to be based on the userName value that is passed in. Any change by the User after this point
    // will be ignored. If validation is successful, then the userName value is confirmed and trusted.
    
    // Get data from the seesion
    final HttpServletRequest httpServletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
    final com.yubico.webauthn.AssertionRequest request = (com.yubico.webauthn.AssertionRequest)httpServletRequest.getSession(true).getAttribute( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.SESSION_ATTRIBUTE_WEBAUTHN_PKCO);
    
    if (request == null ) {
        log.error("Cannot validate WebAuthn token response because the session data was not present.");
        internalError("Login failed.");
        // invalidate the session
        //httpServletRequest.getSession(true).invalidate();
        return false;
    }
    
    // Clear the session data
    httpServletRequest.getSession(true).removeAttribute( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.SESSION_ATTRIBUTE_WEBAUTHN_PKCO);    

    try {
        // Validate the response
        // using YUBICO source from WebAuthn project
        com.yubico.webauthn.data.PublicKeyCredential<com.yubico.webauthn.data.AuthenticatorAssertionResponse, com.yubico.webauthn.data.ClientAssertionExtensionOutputs> assertionResponse;
        assertionResponse = com.yubico.webauthn.data.PublicKeyCredential.parseAssertionResponseJson( publicKeyCredentialJson);

        final EjbcaCredentialRepository4Assertion  ejbcaCredentialRepository = new EjbcaCredentialRepository4Assertion (userName);

        // To validate the response, we need the RelyingParty and the Request
         final  com.yubico.webauthn.RelyingParty rp = com.yubico.webauthn.RelyingParty.builder()
                .identity(org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.rpIdentity)
                .credentialRepository(ejbcaCredentialRepository)
                .allowOriginPort(true) // Ignore the port value
                .validateSignatureCounter( true)
                .build();

        final com.yubico.webauthn.AssertionResult result = rp.finishAssertion( com.yubico.webauthn.FinishAssertionOptions.builder()
                .request(request)  // The PublicKeyCredentialRequestOptions from session data
                .response(assertionResponse)
                .build());

            if (result.isSuccess()) {
 
                // At this point, the login is successful. We can also trust the 'userName' value is correct.

                // Check UV flag
                // Note: Yubico probably checks this, but just making sure the User Verification was used (ie., a PIN entered)
                if ( ! result.isUserVerified() ) {
                    log.error("The new WebAuthn token did not support User Verification. Username="+userName);
                    return false;
                }
               
                // Update the DB as this was a valid login. While int he DB, get the associated certificate's fingerprint
                final String sCertFingerPrint = ejbcaCredentialRepository.updateEndEntityWithWebAuthnAndReturnCertificateFingerPrint( result.getCredentialId(), result.getSignatureCount());
                
                // If no certificate data, then we can fail out.
                if ( sCertFingerPrint==null || sCertFingerPrint.equals("")) {
                    log.error("The new WebAuthn token is not associated with a valid certificate. Usernmae="+userName);
                    return false;
                }
                
                // Any other tests??? 
                
                // Generate the Access Token, and respond accordingly.
                doOAuthAuthorizationResponse(userName, sCertFingerPrint);
                
                return true;
            }
    } catch (IOException | AssertionFailedException e) {
        log.error(e);
        //internalError("Login failed.");
        return false;
    }
    return false;
}


    public void clickLoginLink()  {
        if ( (username == null) || (username.equals("")) ){
            internalError("Username cannot be blank.");
            return;
        }

        // Trigger the Web Client to do WebAuthn login
        setupPkco();
        return;
     }
    
    public void doOAuthAuthorizationResponse( final String userName, final String certFingerPrint) throws IOException {
        // Note: Validation is to have proved the value of userName, and the associated certificate fingerprint. 

        try {
            // Create the OAuth Access Token, which will be stored temporary into a static 'map'. The Access Token request 
            // will then release this token. 

            // We need to sign access token with managementCA key
            // TODO: Making some assumptions here like "ManagementCA" and "signKey"
            // TODO: Add issue and expire time/date to protect the JWT from mis-use.
            final CAToken caToken = caSession.getCAInfoInternal( -1, "ManagementCA", true ).getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSessionLocal.getCryptoToken(caToken.getCryptoTokenId());

            // To allow psuedo certifiate authentication, include the certificate into the 'sub' field of the JWT
            // To ensure 'psuedo' certificat auth, put a special prefix to signal this.
            final String sSubject = "#Certificate="+certFingerPrint;

            final PrivateKey privKey =  cryptoToken.getPrivateKey( "signKey");
            final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"" + "ManagementCA"+ "\",\"typ\":\"JWT\"}", "{\"sub\":\"" 
                    + sSubject + "\", \"aud\":\"" + "internal" + "\",\"iss\":\"EJBCAWebAuthnOAuthProvider\""
                    +"}",
                    privKey);

            // Save the Access Token in  a Map
            final java.util.HashMap<String, Object> mapCodeData = new java.util.HashMap<String, Object>();
            mapCodeData.put("token", token);

            // Include the current time so we can timeout the access token.
            mapCodeData.put("created", new java.util.Date().getTime());

            // Generate a 'code' value. Using the password generator, but could use any random code or GUID generator.
            final String sCode = new AllPrintableCharPasswordGenerator().getNewPassword(15, 20);

            synchronized( mapCodes) {
                // There should never be a duplicate 'code' at the same time in the Map, but abort if it occurs as this is safer
                if (mapCodes.containsKey(sCode)) {
                    throw new IOException("Duplicate 'code' detected.");
                }

                // Save the access token and other data to a temporary static map, using the 'code' value as the key.
                mapCodes.put(sCode, mapCodeData);
            }

            // Redirect the browser. Add the 'state' and 'code' parameters to the redirect url.
            // We should have a redirect uri that was passed in by the OAuth request.
            if ( sRedirectUri == null) {
                // Redirect to Admin page.
                this.redirect(ADMIN_PAGE, "code", sCode, "state", (sState==null?"":sState) );
                //FacesContext.getCurrentInstance().getExternalContext().redirect( ADMIN_PAGE );
            } else {
                log.debug("Redirecting to URI="+sRedirectUri);
                // Redirect to the reference provided by the OAuth request.
                this.redirect(sRedirectUri, "code", sCode, "state", (sState==null?"":sState) );
                //FacesContext.getCurrentInstance().getExternalContext().redirect( sRedirectUri);
            }
        } catch (CryptoTokenOfflineException e) {
            //log.error("Failure to generate the Access Token. Details: "+e.getMessage());
            throw new IOException(e);
        }
     }

    
    public void cancel() throws IOException {
        // Clear the session for good security
        HttpServletRequest httpRequest = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        httpRequest.getSession(true).invalidate();

        // Redirect to Admin page which will re-display the list of OAuth providers.
        FacesContext.getCurrentInstance().getExternalContext().redirect( ADMIN_PAGE );

    }
//    private void replaceHttpHeaders(String urls) {
//        HttpServletResponse httpResponse = (HttpServletResponse)FacesContext.getCurrentInstance().getExternalContext().getResponse();
//        String header = httpResponse.getHeader("Content-Security-Policy");
//        header = header.replace("form-action 'self'", "form-action " + urls + "'self'");
//        httpResponse.setHeader("Content-Security-Policy", header);
//        httpResponse.setHeader("X-Content-Security-Policy", header);
//    }
    
    private String encodeToken(final String headerJson, final String payloadJson, final PrivateKey key) {
        final StringBuilder sb = new StringBuilder();
        sb.append(Base64URL.encode(headerJson).toString());
        sb.append('.');
        sb.append(Base64URL.encode(payloadJson).toString());
        if (key != null) {
            final byte[] signature = sign(sb.toString().getBytes(StandardCharsets.US_ASCII), key);
            sb.append('.');
            sb.append(Base64URL.encode(signature).toString());
        } else {
            sb.append('.');
        }
        return sb.toString();
    }

    private byte[] sign(final byte[] toBeSigned, final PrivateKey key) {
        try {
            return KeyTools.signData(key, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, toBeSigned);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }
    

    //
    // Support functions
    //
    
     /**
     * without access to template, we have to fetch the CSS manually
     *
     * @return path to admin web CSS file
     **/
    public String getCssFile() {
        try {
            return ejbcaWebBean.getBaseUrl() + "/" + ejbcaWebBean.getCssFile();
        } catch (Exception e) {
            // This happens when EjbcaWebBeanImpl fails to initialize.
            // That is already logged in EjbcaWebBeanImpl.getText, so log at debug level here.
            final String msg = "Caught exception when trying to get stylesheet URL, most likely EjbcaWebBean failed to initialized";
            if (log.isTraceEnabled()) {
                log.debug(msg, e);
            } else {
                log.debug(msg);
            }
            return "exception_in_getCssFile";
        }
    }
    
    private void internalError(final String errorMessage) {
        log.warn("Error occurred during WebAuthn login. Details: "+errorMessage);
        firstHeader = ejbcaWebBean.getText("ERROR");
        //secondHeader = ejbcaWebBean.getText("INTERNALERROR");
        secondHeader = errorMessage;
    }


    public void processAccessToken() throws IOException {
        
        // Not checking redirect_uri.or grant_type. Will assume that the EJBCA code is not
        // going to send bad data here!
        
        final FacesContext facesContext = FacesContext.getCurrentInstance();
        final jakarta.faces.context.ExternalContext externalContext = facesContext.getExternalContext();

        externalContext.setResponseContentType("application/json");
        externalContext.setResponseCharacterEncoding("UTF-8");
        
        String sJsonResponse = "";
        
        // Get the OAuth configuration
        final OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        final OAuthKeyInfo oAuthKeyInfo = oAuthConfiguration.getOauthKeyByLabel( org.ejbca.ui.web.admin.mypreferences.MyWebAuthnRegMBean.OAUTH_PROVIDER_NAME);

        // Get the 'code', 'client_id' & 'client_secret' values from the request
        final HttpServletRequest httpRequest = (HttpServletRequest)externalContext.getRequest();
        final String sCode = httpRequest.getParameter("code");
        final String sClient = httpRequest.getParameter("client_id");
        final String sSecret = httpRequest.getParameter("client_secret");
        
        boolean bOK = true;
        sJsonResponse = "\"error\":\"invalid_grant\"";

        if ( sClient == null || !sClient.equals( oAuthKeyInfo.getClient()) ) {
            bOK = false;
            log.error("Request for OAuth access token has incorrect Client value.");
            sJsonResponse = "\"error\":\"invalid_client\"";
        }
        if ( sSecret == null || !sSecret.equals( oAuthKeyInfo.getClientSecretAndDecrypt()) ) {
            bOK = false;
            log.error("Request for OAuth access token has incorrect Client Secret value.");
            sJsonResponse = "\"error\":\"invalid_client\"";
        }
        
        // Before checking 'code' values, lets clean up expired codes.
        // Note: mapCodes should be thread safe.
        mapCodes.forEach(( k, v ) -> {
            // Is the created time older than 10 minutes.
            if ( (long)v.get("created") + 600000 < new java.util.Date().getTime() ) {
                // Too old...delete the entry
                mapCodes.remove(k);
            }
        });
        
        if ( bOK &&  sCode != null && mapCodes.containsKey(sCode)  ) {
            // Return the access token
            
            // Get the map data, and delete the code entry (one time use only)
            java.util.HashMap<String, Object> mapCodeData = mapCodes.remove(sCode);
            
            // A successful response...
            externalContext.setResponseStatus(200);
            sJsonResponse = "{\"access_token\":\""+mapCodeData.get("token")+"\",\"token_type\":\"bearer\"}";
            
            
        } else {
            // Error
            log.error("Request for OAuth access token has incorrect Code or some other error.");
            externalContext.setResponseStatus(400);
        }
        
        externalContext.getResponseOutputWriter().write(sJsonResponse);
        facesContext.responseComplete();
    }
    
    
    //
    // Getter and Setters
    //
    
    
    public String getPkc() {
        return pkc;
    }


    public void setPkc(String pkc) {
        
        if (pkc==null || pkc.equals("")) {
            return;
        }
        
        log.debug("Assertion response received: "+pkc);
        
        // Get the UserName provided. This is untrusted data until the validation checks occur.
        // Local copy of username in case there are attempts to change it.
        final String userName = username;

        try {
            if (!validateLogin(pkc, userName)) {
                internalError("Login failed. Check the Username entry and that you have a valid token for this User.");
            }
        } finally {
            // Clear request and response data
            pkco = "''";
            pkc="";
            username="";
            //log.info("Cleared data");        
        }
    }
    
    
    public String getPkco() {
        return pkco;
    }


    
    /**
     * @return the general error which occurred, or welcome header
     */
    public String getFirstHeader() {
        return firstHeader;
    }

    /**
     * @return error message generated by application exceptions, or welcome text
     */
    public String getSecondHeader() {
        return secondHeader;
    }

    /**
     * @return help text to show below message
     */
    public String getText() {
        return text;
    }
    
    public String getUsername() {
        return username;
    }
    public void setUsername( String entry) {
        // Trim to clean up the data entry. The page will also do validation on this entry too.
        username = entry.trim();
    }

    


}
