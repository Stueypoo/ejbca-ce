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

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import org.apache.commons.lang.CharSetUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * JSF validator that check that fields do no contain any ASCII control characters.
 * Newlines and tabs are allowed, though. 
 *
 */
@FacesValidator("multiLineFreeTextValidator")
public class MultiLineFreeTextValidator implements Validator<Object> {
    private static final Logger log = Logger.getLogger(MultiLineFreeTextValidator.class);

    private static final String CONTROL_CHARS = "\u0000-\u0008\u000B\u000C\u000E-\u001F"; // all characters from 0x00-0x1F except 09 (tab), 0A (line feed) and 0D (carriage return)

    @Override
    public void validate(final FacesContext facesContext, final UIComponent uIComponent, final Object object) throws ValidatorException {
        final String textFieldValue = (String) object;
        if (log.isDebugEnabled()) {
            log.debug("Validating component " + uIComponent.getClientId(facesContext) + " with value \"" + textFieldValue + "\"");
        }
        if (textFieldValue != null && CharSetUtils.count(textFieldValue, CONTROL_CHARS) != 0) {
            final String msg = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDCHARS") + "control characters (except for newlines) are not allowed";
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
        }
    }
}
