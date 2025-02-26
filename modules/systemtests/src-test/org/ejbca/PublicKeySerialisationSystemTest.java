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
package org.ejbca;

import static org.junit.Assert.fail;

import java.io.EOFException;
import java.io.StreamCorruptedException;

import jakarta.ejb.EJBException;

import org.cesecore.util.EjbRemoteHelper;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 * Test to check the deserialisation over JNDI of keys that appeared in BC 1.51
 */
@Ignore
public class PublicKeySerialisationSystemTest {

    private PublicKeySerialisationSystemTestSessionRemote publicKeySerialisationSystemTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            PublicKeySerialisationSystemTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testGetPublicKey() {
        try {
            publicKeySerialisationSystemTestSession.getKey();
            fail("Deserialisation over JNDI appears to work.");
        } catch (EJBException e) {
            if (e.getCausedByException() instanceof EOFException) {
                // NOPMD: This is as expected after the update to BC 1.51 this happens on JBoss6
            } else if(e.getCausedByException() instanceof StreamCorruptedException) {
                // NOPMD: This is as expected after the update to BC 1.51, this happens on JBoss7
            } else {
                throw e;
            }
        }
    }

}
