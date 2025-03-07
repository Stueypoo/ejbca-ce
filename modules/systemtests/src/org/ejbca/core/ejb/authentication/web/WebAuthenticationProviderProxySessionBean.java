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
package org.ejbca.core.ejb.authentication.web;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiConstants;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class WebAuthenticationProviderProxySessionBean implements WebAuthenticationProviderProxySessionRemote {

    private static final long serialVersionUID = -9088862258434588872L;

    @EJB
    private WebAuthenticationProviderSessionLocal authenticationProvider;
    
    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {  
        return authenticationProvider.authenticate(subject);
    }

}
