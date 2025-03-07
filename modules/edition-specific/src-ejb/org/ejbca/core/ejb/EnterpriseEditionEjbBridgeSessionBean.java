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
package org.ejbca.core.ejb;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

/**
 * JEE5 EJB lookup helper for Community Edition EJBs.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EnterpriseEditionEjbBridgeSessionBean implements EnterpriseEditionEjbBridgeSessionLocal {

    @Override
    public <T> T getEnterpriseEditionEjbLocal(Class<T> localInterfaceClass, String modulename) {
        return null; // NOOP in community edition
    }
    
    @Override
    public boolean isRunningEnterprise() {
        return false;
    }

    @Override
    public void requestClearEnterpriseAuthorizationCaches() {
        // NOOP in community edition
    }
}
