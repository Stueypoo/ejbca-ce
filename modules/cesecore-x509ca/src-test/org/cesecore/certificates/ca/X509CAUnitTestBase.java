/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import static org.junit.Assert.assertNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Base class for X509CAUnitTest and X509CAPartitionedCrlUnitTest
 * 
 * @version $Id$
 */
public class X509CAUnitTestBase {

    /** Subject DN for test CA objects */
    protected static final String CADN = "CN=TEST";
    /** This will be an empty list of custom certificate extensions */
    protected final AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

    public X509CAUnitTestBase() {
        CryptoProviderTools.installBCProvider();
    }

    protected static X509CA createTestCA(CryptoToken cryptoToken, final String cadn) throws CertificateParsingException,
            InvalidAlgorithmParameterException, CryptoTokenOfflineException, InvalidAlgorithmException, OperatorCreationException, CertIOException {
        return createTestCA(cryptoToken, cadn, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, null, null);
    }

    protected static X509CA createTestCA(CryptoToken cryptoToken, final String cadn, final String sigAlg, Date notBefore, Date notAfter)
            throws InvalidAlgorithmParameterException, CryptoTokenOfflineException, InvalidAlgorithmException, CertificateParsingException,
            OperatorCreationException, CertIOException {
        cryptoToken.generateKeyPair(getTestKeySpec(sigAlg), CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair(getTestKeySpec(sigAlg), CAToken.SOFTPRIVATEDECKEYALIAS);
        // Create CAToken
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, CAToken.SOFTPRIVATESIGNKEYALIAS);

        CAToken caToken = new CAToken(cryptoToken.getId(), caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        caToken.setSignatureAlgorithm(sigAlg);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        x509ca.setCAToken(caToken);
        // A CA certificate
        final PublicKey publicKey = cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        final PrivateKey privateKey = cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        X509Certificate cacert = SimpleCertGenerator.forTESTCaCert()
                .setSubjectDn(cadn)
                .setIssuerDn(cadn)
                .setValidityDays(10)
                .setPolicyId("1.1.1.1")
                .setIssuerPrivKey(privateKey)
                .setEntityPubKey(publicKey)
                .setKeyUsage(keyusage)
                .setPrivateKeyNotBefore(notBefore)
                .setPrivateKeyNotAfter(notAfter)
                .setSignatureAlgorithm(sigAlg)
                .setLdapOrder(true)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .generateCertificate();                
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
    }

    /** @return a new empty soft auto-activated CryptoToken */
    protected static CryptoToken getNewCryptoToken() {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        CryptoToken cryptoToken;
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(
                    SoftCryptoToken.class.getName(), cryptoTokenProperties, null, 17, "CryptoToken's name");
        } catch (NoSuchSlotException e) {
            throw new IllegalStateException("Attempted to find a slot for a soft crypto token. This should not happen.", e);
        }
        return cryptoToken;
    }

    /** @return Algorithm name for test key pair */
    protected static String getTestKeyPairAlgName(String algName) {
        if (algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA) ||
            algName.equals(AlgorithmConstants.SIGALG_ED25519) ||
            algName.equals(AlgorithmConstants.SIGALG_ED448) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA) ||
            algName.equals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA) ||
            algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1) ||
            algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1)) {
            return algName;
        } else {
            return "SHA256withRSA";
        }
    }

    protected static String getTestKeySpec(String algName) {
        if (algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA)) {
            return "brainpoolp224r1";
        } else if (algName.equals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA)) {
            return "prime256v1";
        } else if (algName.equals(AlgorithmConstants.SIGALG_ED25519)) {
            return AlgorithmConstants.KEYALGORITHM_ED25519;
        } else if (algName.equals(AlgorithmConstants.SIGALG_ED448)) {
            return AlgorithmConstants.KEYALGORITHM_ED448;
        } else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1)) {
            return "2048"; // RSA-PSS required at least 2014 bits
        } else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1)) {
            return "2048"; // RSA-PSS required at least 2014 bits
        } else if (algName.equals(AlgorithmConstants.SIGALG_MLDSA65)) {
            return AlgorithmConstants.KEYALGORITHM_MLDSA65;
        } else if (algName.equals(AlgorithmConstants.SIGALG_FALCON512)) {
            return AlgorithmConstants.KEYALGORITHM_FALCON512;
        } else {
            return "1024"; // Assume RSA
        }
    }

}
