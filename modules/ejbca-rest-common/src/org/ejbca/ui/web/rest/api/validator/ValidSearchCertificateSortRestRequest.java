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
package org.ejbca.ui.web.rest.api.validator;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import org.apache.commons.lang3.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateSortRestRequest;

/**
 * Validation annotation for input parameter with built-in validator. An input SearchCertificateSortRestRequest is validated for:
 *
 * SearchCertificateSortRestRequest's property attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not blank;</li>
 *     <li>One of SearchCertificateSortRestRequest.CriteriaProperty.</li>
 * </ul>
 *
 * SearchCertificateSortRestRequest's operation attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not blank;</li>
 *     <li>One of SearchCertificateSortRestRequest.SortProperty.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchCertificateSortRestRequest.Validator.class})
@Documented
public @interface ValidSearchCertificateSortRestRequest {

    String message() default "{ValidSearchCertificateSortRestRequest.invalid.sort.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    final class Validator implements ConstraintValidator<ValidSearchCertificateSortRestRequest, SearchCertificateSortRestRequest> {

        @Override
        public void initialize(final ValidSearchCertificateSortRestRequest request) {
        }

        @Override
        public boolean isValid(final SearchCertificateSortRestRequest restRequest, final ConstraintValidatorContext context) {
            if (restRequest != null) {
                final String property = restRequest.getProperty();
                final String operation = restRequest.getOperation();
                if (StringUtils.isNotBlank(property)) {
                    final SearchCertificateSortRestRequest.SortProperty criteriaProperty = SearchCertificateSortRestRequest.SortProperty.resolveCriteriaProperty(property.trim());
                    if (criteriaProperty == null) {
                        ValidationHelper.addConstraintViolation(context, "{ValidSearchCertificateSortRestRequest.invalid.property.unknown}");
                        return false;
                    }
                }
                if (StringUtils.isNotBlank(operation)) {
                    final SearchCertificateSortRestRequest.SortOperation criteriaOperation = SearchCertificateSortRestRequest.SortOperation.resolveCriteriaOperation(operation.trim());
                    if (criteriaOperation == null) {
                        ValidationHelper.addConstraintViolation(context, "{ValidSearchCertificateSortRestRequest.invalid.operation.unknown}");
                        return false;
                    }
                }
            }
            return true;
        }
    }
}
