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
package org.ejbca.util.validator;

import java.math.BigInteger;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;


/**
 * Validates that no negative numbers can be set for a Rsa Key Validator.
 * 
 */
@FacesValidator("noNegativeNumbersValidator")
public class NoNegativeNumbersValidator implements Validator<Object> {
    
    /** Localization of log and error messages. */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(NoNegativeNumbersValidator.class);
    
    @Override
    public void validate(FacesContext context, UIComponent component, Object object) throws ValidatorException {
        if (null != object){
            final BigInteger integerValue;
            if (object instanceof  Integer ){
                integerValue = BigInteger.valueOf((int) object);
            } else if(object instanceof Long) {
                integerValue = BigInteger.valueOf((long) object);
            } else {
                integerValue = (BigInteger) object; 
            }
            if (integerValue.compareTo(BigInteger.ZERO ) == -1) {
                final String field = (String) component.getAttributes().get("fieldName");
                final String message = intres.getLocalizedMessage("validator.error.set_key_validator_values_gui", integerValue, field);
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
            }
        }
    }
}

