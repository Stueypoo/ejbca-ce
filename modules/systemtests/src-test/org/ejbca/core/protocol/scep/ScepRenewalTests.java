package org.ejbca.core.protocol.scep;

import static org.junit.Assert.*;

//
// NOTES:
//
// Addd this class to the SystemTest build file.
// To run tests, use "ant test:runweb". Note that EJBCA must be in 'Non-Production' mode. 
//
// These tests do assume that the "ManagementCA" exists. Other tests create their own CA as part of the testing, and
// a similar approach could be implemented.
//
// The SCEP Configuration will be created if it does not exist.
//

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ScepRenewalTests extends ScepTestBase {
    private static final Logger log = Logger.getLogger(ScepRenewalTests.class);

    
    // Assumes a ManagementCA exists
    private static final String scepAlias = "ManagementCA";
    private static final String resourceScep = "publicweb/apply/scep/" + scepAlias + "/pkiclient.exe";

    private static ScepConfiguration scepConfiguration;
    
    private final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolScepHttpTest"));
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    // User#1. This is the main test user
    private static final String userName1 = "ScepUserSelfTest";
    private static final String userDN1 = "C=AU,O=SelfTest,CN=" + userName1;
    private static X509Certificate certUser1_First = null;
    private static X509Certificate certUser1_Second = null;
    private static KeyPair kpUser1_First = null;
    private static KeyPair kpUser1_Second = null;

    // User#2. Used for one test case.
    private static final String userName2 = "ScepUser2SelfTest";
    private static final String userDN2 = "C=SE,O=PrimeKey,CN=" + userName2;

    private static String httpBaseUrl = "";
    private static boolean bScepConfigAdded = false;
    
    // Details for the CA
    private static X509Certificate certCA = null;
    private static int iCAID;
    
    private Random rand = new Random();
    private String senderNonce = null;
    private String transId = null;

    
    private boolean bRunSetUpOnce = false;
    @Before
    public void setUp() throws Exception {
        if (!bRunSetUpOnce) {
            bRunSetUpOnce = true;
            CryptoProviderTools.installBCProviderIfNotAvailable();

            // Check ManagementCA exists
            CAInfo cainfo = caSessionRemote.getCAInfo(admin, scepAlias);
            if (cainfo == null) {
                fail("The ManagementCA needs to exist for these tests");
            }
            iCAID = cainfo.getCAId();
            certCA = (X509Certificate)cainfo.getCertificateChain().get(0);

            scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
            if (!scepConfiguration.aliasExists(scepAlias)){
                scepConfiguration.addAlias(scepAlias);
                globalConfigSession.saveConfiguration(admin, scepConfiguration);
                bScepConfigAdded = true;
            }
            String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
            String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
            httpBaseUrl = "http://" + httpHost + ":" + httpPort+"/ejbca/"+resourceScep;
        }
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void test_01_CACapsIncludesRenewal() throws Exception {
        // Check that CA capability response includes 'Renewal'
        try {
            byte[] ba = this.sendGetCACapsRequest("", 200); // Note that the Scep ALias in the URL selects the CA.
            String s = new String( ba);
            assertTrue("The CA Caps is to include 'Renewal'.",s.contains("Renewal"));
            
        } catch (IOException e) {
            fail("IO exception not expected."+e.getMessage());
        }
        
    }

    
    @Test
    public void test_02_GetCACertUsingScepAlias() throws Exception {
        // Check the Scep Alias can be used to associate the CA with the same name.
        // This is not strictly a Renewal test, but an assumed change that has been implemented (Issue#419). The
        // idea of this change is that the CA can be selected using the Scep Alias rather that including the CA Name 
        // in the 'message' string within the SCEP URL.
        // Note: The tests below assume that this change is implemented.
        
        // Check correct CA Cert is returned. Code based upon ProtocolScepHttpTest.java
        URL url = new URL(httpBaseUrl+ "?operation=GetCACert");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-x509-ca-cert; charset=UTF-8"
        assertEquals("application/x-x509-ca-cert", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        
        // Get the CA cert
        X509Certificate certReturned = CertTools.getCertfromByteArray(respBytes, X509Certificate.class);
        // Check that we got the right cert back
        assertTrue("Cert returned was not the ManagementCA.", certReturned.getSubjectDN().getName().equals(certCA.getSubjectDN().getName()));
    }
    
    
    @Test
    public void test_03_SetupUserWithPasswordAuth() throws Exception {
        // Setup a test User#1 to get a certificate using SCEP, but will use password authentication
        
        //Create the User#1
        this.createScepUser(userName1, userDN1, iCAID);
        
        // Generate 1st test key for User1
        try {
            kpUser1_First = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpUser1_First, BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, null, null);
        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);

       
        // Get the User's first certificate
        certUser1_First = getUserCertFromScepResponse( baScepResp, certCA, kpUser1_First);
        assertNotNull("User#1 certificate should have been issued.", certUser1_First);
        
        assertTrue("User#1 cert should contain '"+userName1+"'.",certUser1_First.getSubjectDN().getName().contains(userName1));
    }

    @Test
    public void test_04_RenewalAttempt_TooEarly() throws Exception {
        // Test that a SCEP renewal will fail if the User has a fresh certificate.
        // There is a wait time of 10% of cert validity before a renewal can be performed.
        
        // Generate 2nd test key for User1
        try {
            kpUser1_Second = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        // Create a SCEP renewal message. The request is signed by the first key/cert.
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpUser1_Second, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpUser1_First, certUser1_First);

        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        String res = getFailedScepResponse( baScepResp);
        assertEquals("SCEP response should be Unauthorised.","23",res); // Not a well known published error code???
     
    }
 

    @Test
    public void test_05_RenewalAttempt_BadSignature() throws Exception {
        // Test that a SCEP renewal will fail if signed with the wrong key. This
        // is to demonstrate that the P7 signature is verified correctly.
        
        // Generate a different key for User1
        KeyPair kpBad = null;
        try {
            kpBad = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        // Create a SCEP renewal message. Will sign with the 2nd key, but provide the first certificate.
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpUser1_Second, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpBad, certUser1_First);

        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        String res = getFailedScepResponse( baScepResp);
        assertEquals("SCEP response should be BadMessageCheck.","1",res); 
    }
  
    @Test
    public void test_06_RenewalWithClientAuth() throws Exception {
        // Test that a SCEP renewal will be permitted using certificate authentication
        // For this test to work, we need to bypass the 10% wait interval. This can be done
        // by setting the Last SCEP renewal time to the value "0" in the User's extended information.
        
        org.cesecore.certificates.endentity.ExtendedInformation exInfo = new org.cesecore.certificates.endentity.ExtendedInformation();
        exInfo.setCustomData(org.ejbca.core.ejb.ca.sign.SignSessionBean.LASTSCEPRENEWAL, "0");
        EndEntityInformation data = new EndEntityInformation(userName1, userDN1, iCAID, null, "sceptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, exInfo);

        // Reset the status because it gets changed to NEW.
        data.setStatus(EndEntityConstants.STATUS_GENERATED );
        endEntityManagementSession.changeUser(admin, data, false);
        
        // Reuse 2nd test key for User1 which was generated already.
       
        // Create a SCEP renewal message
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpUser1_Second, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpUser1_First, certUser1_First);

        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        // Get the User's second certificate
        certUser1_Second = getUserCertFromScepResponse( baScepResp, certCA, kpUser1_First);
        assertNotNull("User#1 certificate should have been issued.", certUser1_Second);
        
        assertTrue("User#1 cert should contain '"+userName1+"'.",certUser1_Second.getSubjectDN().getName().contains(userName1));
    
    }

    

    @Test
    public void test_07_RenewalAttemptAfterRenewal_TooEarly() throws Exception {
        // Test that a SCEP renewal will fail if the User has recently performed a renewal
        // just another check on the 10% wait interval will continue to apply after the 
        // previous renewal.
        
        // Generate temp test key for User1
        KeyPair pkKey;
        try {
            pkKey= KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        // Create a SCEP renewal message
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, pkKey, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpUser1_First, certUser1_First);

        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        String res = getFailedScepResponse( baScepResp);
        assertEquals("SCEP response should be Unauthorised.","23",res); // Not a well known published error code???
     
    }
  

    @Test
    public void test_08_RenewalAttempt_RevokedCert() throws Exception {
        // Test that a SCEP renewal will fail if signed by revoked cert.
        
        // Generate test key for User1
        KeyPair kpKey = null;
        try {
            kpKey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        
        // We need to set the User to allow the renewal without waiting for to 10% wait time
        org.cesecore.certificates.endentity.ExtendedInformation exInfo = new org.cesecore.certificates.endentity.ExtendedInformation();
        exInfo.setCustomData(org.ejbca.core.ejb.ca.sign.SignSessionBean.LASTSCEPRENEWAL, "0");
        EndEntityInformation data = new EndEntityInformation(userName1, userDN1, iCAID, null, "sceptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, exInfo);

        // Reset the status because it gets changed to NEW.
        data.setStatus(EndEntityConstants.STATUS_GENERATED );
        endEntityManagementSession.changeUser(admin, data, false);
        
        // Revoke the user's second cert
        endEntityManagementSession.revokeCert(admin, certUser1_Second.getSerialNumber(),certUser1_Second.getIssuerDN().getName(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        
        
        // Create a SCEP renewal message and sign with the 2nd key/cert
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpKey, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpUser1_Second, certUser1_Second);

        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        String res = getFailedScepResponse( baScepResp);
        assertEquals("SCEP response should be Unauthorised.","23",res); 
    }

    @Test
    public void test_09_RenewalAttempt_WrongStatus() throws Exception {
        // Test that a SCEP renewal will fail if the User is not at GENERATED status.
        // The GENERATED state indicate that the User has at least one cert. Any other state
        // should be a concern and we don't wish to allow Renewals unless GENERATED state.
        
        // Generate test key for User1
        KeyPair kpTest = null;
        try {
            kpTest = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        
        // We need to set the User to allow the renewal without waiting for minimum time
        org.cesecore.certificates.endentity.ExtendedInformation exInfo = new org.cesecore.certificates.endentity.ExtendedInformation();
        exInfo.setCustomData(org.ejbca.core.ejb.ca.sign.SignSessionBean.LASTSCEPRENEWAL, "0");
        EndEntityInformation data = new EndEntityInformation(userName1, userDN1, iCAID, null, "sceptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, exInfo);

        
        // Note: Status will be changed to NEW.
        endEntityManagementSession.changeUser(admin, data, false);
        
        // Create a SCEP renewal message. Use 1st key/cert.
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpTest, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpUser1_First, certUser1_First);

        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        String res = getFailedScepResponse( baScepResp);
        assertEquals("SCEP response should be Unauthorised.","2",res); 
    }


    @Test
    public void test_10_RenewalAttemp_WrongUserCert() throws Exception {
        // Check a renewal can't be performed using a certificate belonging to another User. 
        // Setup a test User#2 to get a certificate using SCEP. Use password authentication.
        
        //Create the User#2
        this.createScepUser(userName2, userDN2, iCAID);
        KeyPair kpUser2 = null;
       
        // Generate key for User2
        try {
            kpUser2 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        final byte[] msgBytesUser2 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN2, kpUser2, BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, null, null);
        // Send message with GET
        byte[] baScepResp = sendScep(true, msgBytesUser2, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        X509Certificate certUser2 = null;
        certUser2 = getUserCertFromScepResponse( baScepResp, certCA, kpUser2);

        
        // Now renewal attempt for User#1, but sign with User#2
        // Generate test key for User1
        KeyPair kpTest = null;
        try {
            kpTest = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        
        // We need to set the User to allow the renewal without waiting for minimum time
        org.cesecore.certificates.endentity.ExtendedInformation exInfo = new org.cesecore.certificates.endentity.ExtendedInformation();
        exInfo.setCustomData(org.ejbca.core.ejb.ca.sign.SignSessionBean.LASTSCEPRENEWAL, "0");
        EndEntityInformation data = new EndEntityInformation(userName1, userDN1, iCAID, null, "sceptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, exInfo);

        
        // Note:Status will be changed to NEW.
        endEntityManagementSession.changeUser(admin, data, false);
        
        
        
        // Create a SCEP renewal message for User#1, but sign with User#2
        final byte[] msgBytesUser1 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, userDN1, kpTest, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, kpUser2, certUser2);

        // Send message with GET
       baScepResp = sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", baScepResp);
        
        String res = getFailedScepResponse( baScepResp);
        assertEquals("SCEP response should be Unauthorised.","23",res); 
        
        
    }
    
    
    @Test
    public void test_99_CleanUp() throws Exception {
        // remove users and other configuration
        try {
            endEntityManagementSession.deleteUser(admin, userName1);
            log.debug("deleted user: " + userName1);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.deleteUser(admin, userName2);
            log.debug("deleted user: " + userName2);
        } catch (Exception e) {
            // NOPMD: ignore
        }

        if (bScepConfigAdded) {
            scepConfiguration.removeAlias(scepAlias);
            globalConfigSession.saveConfiguration(admin, scepConfiguration);
        }
    
    }

    @Override
    protected String getResourceScep() {
        return resourceScep;
    }

    @Override
    protected String getTransactionId() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected X509Certificate getCaCertificate() {
        return certCA;
    }

    
    private byte[] genScepRequest( String digestoid, String userDN, KeyPair kpCSR, String signatureProvider, 
            ASN1ObjectIdentifier wrappingAlg, ASN1ObjectIdentifier encryptionAlg, KeyPair kpSigner, X509Certificate certSigner) throws
    IOException, CMSException, OperatorCreationException, CertificateException {
        ScepRequestGenerator gen = new ScepRequestGenerator();
        gen.setKeys(kpCSR, signatureProvider);
        gen.setDigestOid(digestoid);
        byte[] msgBytes = null;
        // Create a transactionId
        byte[] randBytes = new byte[16];
        this.rand.nextBytes(randBytes);
        byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
        transId = new String(Base64.encode(digest));
        
        // Sender certificate could be self-generated or provided (for the case of renewals)
        X509Certificate senderCertificate = null;
        KeyPair kpUseToSign = null;
        if ( certSigner == null) {
          senderCertificate = CertTools.genSelfCert("CN=SenderCertificate", 24 * 60 * 60 * 1000, null,
                kpCSR.getPrivate(), kpCSR.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
          kpUseToSign = kpCSR;
        } else {
            senderCertificate=certSigner;
            kpUseToSign = kpSigner;
        }
        
        // CA Cert should exist
        assertNotNull( certCA);
        
         msgBytes = gen.generateCertReq(userDN, "foo123", transId, certCA, senderCertificate, kpUseToSign.getPrivate(), wrappingAlg, encryptionAlg);
         assertNotNull(msgBytes);
 
         senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertTrue(nonceBytes.length == 16);
        return msgBytes;
    }
    
    
    protected X509Certificate getUserCertFromScepResponse(byte[] retMsg,  
                                                            X509Certificate caCertToUse, KeyPair key)
                    throws CMSException, OperatorCreationException, NoSuchProviderException, CRLException, InvalidKeyException, NoSuchAlgorithmException,
                    SignatureException, CertificateException {

        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        
        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();
        
        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();
        
        // --Fail info
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // No failInfo on this success message
        assertNull(attr);

        // --Message type
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
        assertNotNull(attr);

        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1String str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);

        // --Success status
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        assertEquals(ResponseStatus.SUCCESS.getStringValue(), str.getString());
        // First we extract the encrypted data from the CMS enveloped data
        // contained
        // within the CMS signed data
        final CMSProcessable sp = s.getSignedContent();
        final byte[] content = (byte[]) sp.getContent();
        final CMSEnvelopedData ed = new CMSEnvelopedData(content);
        final RecipientInformationStore recipients = ed.getRecipientInfos();
        @SuppressWarnings("rawtypes")
        Store certstore;

        Collection<RecipientInformation> c = recipients.getRecipients();
        assertEquals(c.size(), 1);
        Iterator<RecipientInformation> riIterator = c.iterator();
        byte[] decBytes = null;
        RecipientInformation recipient = riIterator.next();
        AlgorithmIdentifier wrapAlg = recipient.getKeyEncryptionAlgorithm();
        // Was it the expected key wrapping algo from the server?
        log.debug("Key encryption algorithm from the server is: " + wrapAlg.getAlgorithm().getId());

        JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(key.getPrivate());
        rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
        // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM, 
        // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known 
        // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
        rec.setMustProduceEncodableUnwrappedKey(true);            
        decBytes = recipient.getContent(rec);
        String encAlg = ed.getContentEncryptionAlgorithm().getAlgorithm().getId();
        // Was it the expected encryption algo from the server?
        log.debug("Encryption algorithm from the server is: " + encAlg);

        // This is yet another CMS signed data
        CMSSignedData sd = new CMSSignedData(decBytes);
        // Get certificates from the signed data
        certstore = sd.getCertificates();

        // We got a reply with a requested certificate
        @SuppressWarnings("unchecked")
        final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
        // EJBCA returns the issued cert and the CA cert (cisco vpn
        // client requires that the ca cert is included)
        //                if (noca) {
        //                    assertEquals(certs.size(), 1);
        //                } else {
        //                    assertEquals(certs.size(), 2);
        //                }

        final Iterator<X509CertificateHolder> it = certs.iterator();
        // Issued certificate must be first
        boolean verified = false;
        boolean gotcacert = false;
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        while (it.hasNext()) {
            X509Certificate retcert = jcaX509CertificateConverter.getCertificate(it.next());
            log.info("Got cert with DN: " + retcert.getSubjectDN().getName());

            return retcert;

            //                    // check the returned certificate
            //                    String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
            //                    if (CertTools.stringToBCDNString(userDN).equals(subjectdn)) {
            //                        // issued certificate
            //                        assertEquals(CertTools.stringToBCDNString(userDN), subjectdn);
            //                        assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getIssuerDN(retcert));
            //                        retcert.verify(caCertToUse.getPublicKey());
            //                        assertTrue(checkKeys(key.getPrivate(), retcert.getPublicKey()));
            //
            //                        verified = true;
            //                    } else {
            //                        // ca certificate
            //                        assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getSubjectDN(retcert));
            //                        gotcacert = true;
            //                    }
        }
        //                assertTrue(verified);
        //                if (noca) {
        //                    assertFalse(gotcacert);
        //                } else {
        //                    assertTrue(gotcacert);
        //                }

        return null;
    }

    
    protected String getFailedScepResponse(byte[] retMsg)
                    throws CMSException, OperatorCreationException, NoSuchProviderException, CRLException, InvalidKeyException, NoSuchAlgorithmException,
                    SignatureException, CertificateException {

        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);

        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();

        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();

        // --Get PKI status
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        
        ASN1String str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        // Expecting a FAILURE
        assertEquals(ResponseStatus.FAILURE.getStringValue(), str.getString());

        // --Fail info
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // Expect a fail info
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        return str.getString();

//        // --Message type
//        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
//        assertNotNull(attr);
//
//        values = attr.getAttrValues();
//        assertEquals(values.size(), 1);
//        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
//        String messageType = str.getString();
//        assertEquals("3", messageType);
//
//
//        return null;
    }

    

}
