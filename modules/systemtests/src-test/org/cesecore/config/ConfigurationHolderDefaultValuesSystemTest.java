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
package org.cesecore.config;

import org.cesecore.configuration.ConfigurationHolderProxySessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Assert;
import org.junit.Test;

/**
 * Functional tests to check that the ConfigurationHolder can find its values when deployed in the AS.  
 * 
 * @version $Id$
 * 
 */
public class ConfigurationHolderDefaultValuesSystemTest {
    
    ConfigurationHolderProxySessionRemote configurationHolderProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationHolderProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    @Test
    public void testDefaultValues() {
        // NOTE: Difference between CESeCore and EJBCA
        Assert.assertEquals("h2", configurationHolderProxySession.getDefaultValue("database.name"));
    }

    @Test
    public void testNonExistingValue() {
        Assert.assertNull("A value that does not exist in defaultvalues.properties should be null", configurationHolderProxySession.getDefaultValue("xyz.abc"));
    }

}
