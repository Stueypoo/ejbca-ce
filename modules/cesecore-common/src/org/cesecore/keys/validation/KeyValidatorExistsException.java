/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import jakarta.xml.ws.WebFault;

import com.keyfactor.CesecoreException;

/**
 * An exception thrown when someone tries to store a KeyValidator that already exists.
 *
 * @version $Id$
 */
@WebFault
public class KeyValidatorExistsException extends CesecoreException {

    private static final long serialVersionUID = 4159925465395318657L;

    /**
     * Creates a new instance.
     */
    public KeyValidatorExistsException() {
        super();
    }

    /**
     * Creates a new instance with the specified detail message.
     * @param message the detail message.
     */
    public KeyValidatorExistsException(final String message) {
        super(message);
    }
}
