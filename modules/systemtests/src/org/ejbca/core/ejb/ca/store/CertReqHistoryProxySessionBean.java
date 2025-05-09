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
package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.List;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.ca.store.CertReqHistory;

/**
 *
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertReqHistoryProxySessionBean implements CertReqHistoryProxySessionRemote {

    @EJB
    private CertReqHistorySessionLocal certReqHistorySession;

    @Override
    public void removeCertReqHistoryData(String certFingerprint) {
        certReqHistorySession.removeCertReqHistoryData(certFingerprint);     
    }

    @Override
    public CertReqHistory retrieveCertReqHistory(BigInteger certificateSN, String issuerDN) {
        return certReqHistorySession.retrieveCertReqHistory(certificateSN, issuerDN);
    }

    @Override
    public void addCertReqHistoryData(Certificate cert, EndEntityInformation endEntityInformation) {
        certReqHistorySession.addCertReqHistoryData(cert, endEntityInformation);  
    }

    @Override
    public List<CertReqHistory> retrieveCertReqHistory(String username) {
        return certReqHistorySession.retrieveCertReqHistory(username);
    }
    
    
    
}
