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
package org.ejbca.ui.web.rest.api.io.request;

import java.util.ArrayList;
import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.ws.rs.core.Response;

import org.cesecore.certificates.certificate.CertificateConstants;
import org.ejbca.core.model.era.RaCertificateSearchRequestV2;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateCriteriaRestRequestList;
import org.ejbca.ui.web.rest.api.validator.ValidSearchCertificatePagination;
import org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateSortRestRequest;


import static org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestUtil.parseDateFromStringValue;

/**
 * JSON input for a certificate search V2 containing multiple search criteria and pagination.
 *
 * @see org.ejbca.ui.web.rest.api.io.request.Pagination
 *
 * The properties of this class has to be valid.
 *
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateCriteriaRestRequestList
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateCriteriaRestRequest
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateSortRestRequest
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificatePagination
 */
public class SearchCertificatesRestRequestV2 implements SearchCertificateCriteriaRequest {

    @Schema(description = "Pagination." )
    @ValidSearchCertificatePagination
    private Pagination pagination;

    @Schema(description = "Sort." )
    @ValidSearchCertificateSortRestRequest
    private SearchCertificateSortRestRequest sort = null;

    @Schema(description = "A List of search criteria." )
    @ValidSearchCertificateCriteriaRestRequestList
    @Valid
    private List<SearchCertificateCriteriaRestRequest> criteria = new ArrayList<>();

    public Pagination getPagination() {
        return pagination;
    }

    public void setPagination(Pagination pagination) {
        this.pagination = pagination;
    }

    public SearchCertificateSortRestRequest getSort() {
        return sort;
    }

    public void setSort(SearchCertificateSortRestRequest sort) {
        this.sort = sort;
    }

    @Override
    public List<SearchCertificateCriteriaRestRequest> getCriteria() {
        return criteria;
    }

    public void setCriteria(List<SearchCertificateCriteriaRestRequest> criteria) {
        this.criteria = criteria;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchCertificatesRestRequestBuilderV2 builder() {
        return new SearchCertificatesRestRequestBuilderV2();
    }

    public static class SearchCertificatesRestRequestBuilderV2 {
        private Pagination pagination;
        private SearchCertificateSortRestRequest orderBy;
        private List<SearchCertificateCriteriaRestRequest> criteria;

        private SearchCertificatesRestRequestBuilderV2() {
        }

        public SearchCertificatesRestRequestBuilderV2 pagination(final Pagination pagination) {
            this.pagination = pagination;
            return this;
        }

        public SearchCertificatesRestRequestBuilderV2 orderBy(final SearchCertificateSortRestRequest request) {
            this.orderBy = request;
            return this;
        }

        public SearchCertificatesRestRequestBuilderV2 criteria(final List<SearchCertificateCriteriaRestRequest> criteria) {
            this.criteria = criteria;
            return this;
        }

        public SearchCertificateCriteriaRequest build() {
            final SearchCertificatesRestRequestV2 result = new SearchCertificatesRestRequestV2();
            result.setPagination(pagination);
            result.setSort(orderBy);
            result.setCriteria(criteria);
            return result;
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SearchCertificatesRestRequestConverterV2 converter() {
        return new SearchCertificatesRestRequestConverterV2();
    }

    public static class SearchCertificatesRestRequestConverterV2 {

        public RaCertificateSearchRequestV2 toEntity(final SearchCertificatesRestRequestV2 restRequest) throws RestException {
            if(restRequest.getCriteria() == null || restRequest.getCriteria().isEmpty()) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
            }
            final RaCertificateSearchRequestV2 raRequest = new RaCertificateSearchRequestV2();
            if(restRequest.getPagination() == null) {
                // Enables count rows only.
                raRequest.setPageNumber(-1);
            }
            final Pagination pagination = restRequest.getPagination();
            if (pagination != null) {
                raRequest.setMaxResults(pagination.getPageSize());
                raRequest.setPageNumber(pagination.getCurrentPage());
            }
            final SearchCertificateSortRestRequest orderBy = restRequest.getSort();
            if (orderBy != null) {
                raRequest.setOrderProperty(orderBy.getProperty());
                raRequest.setOrderOperation(orderBy.getOperation());
            }
            raRequest.setEepIds(new ArrayList<>());
            raRequest.setCpIds(new ArrayList<>());
            raRequest.setCaIds(new ArrayList<>());
            raRequest.setStatuses(new ArrayList<>());
            raRequest.setRevocationReasons(new ArrayList<>());
            for(final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest : restRequest.getCriteria()) {
                final SearchCertificateCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchCertificateCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchCertificateCriteriaRestRequest.getProperty());
                if(criteriaProperty == null) {
                    throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
                }
                final String criteriaValue = searchCertificateCriteriaRestRequest.getValue();
                final SearchCertificateCriteriaRestRequest.CriteriaOperation criteriaOperation = SearchCertificateCriteriaRestRequest.CriteriaOperation.resolveCriteriaOperation(searchCertificateCriteriaRestRequest.getOperation());
                switch (criteriaProperty) {
                    case SERIAL_NUMBER: {
                        raRequest.setSerialNumberSearchStringFromDec(criteriaValue);
                        raRequest.setSerialNumberSearchStringFromHex(criteriaValue);
                        break;
                    }
                    case SUBJECT_DN: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raRequest.setSubjectDnSearchExact(true);
                        }
                        raRequest.setSubjectDnSearchOperation(criteriaOperation.name());
                        raRequest.setSubjectDnSearchString(criteriaValue);
                        break;
                    }
                    case SUBJECT_ALT_NAME: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raRequest.setSubjectAnSearchExact(true);
                        }
                        raRequest.setSubjectAnSearchOperation(criteriaOperation.name());
                        raRequest.setSubjectAnSearchString(criteriaValue);
                        break;
                    }
                    case USERNAME: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raRequest.setUsernameSearchExact(true);
                        }
                        raRequest.setUsernameSearchOperation(criteriaOperation.name());
                        raRequest.setUsernameSearchString(criteriaValue);
                        break;
                    }
                    case QUERY: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raRequest.setSubjectDnSearchExact(true);
                            raRequest.setSubjectAnSearchExact(true);
                            raRequest.setUsernameSearchExact(true);
                            raRequest.setExternalAccountIdSearchExact(true);
                        }
                        raRequest.setSubjectDnSearchString(criteriaValue);
                        raRequest.setSubjectDnSearchOperation(criteriaOperation.name());
                        raRequest.setSubjectAnSearchString(criteriaValue);
                        raRequest.setSubjectAnSearchOperation(criteriaOperation.name());
                        raRequest.setUsernameSearchString(criteriaValue);
                        raRequest.setUsernameSearchOperation(criteriaOperation.name());
                        raRequest.setSerialNumberSearchStringFromDec(criteriaValue);
                        raRequest.setSerialNumberSearchStringFromHex(criteriaValue);
                        raRequest.setExternalAccountIdSearchString(criteriaValue);
                        raRequest.setExternalAccountIdSearchOperation(criteriaOperation.name());
                        break;
                    }
                    case END_ENTITY_PROFILE: {
                        raRequest.getEepIds().add(searchCertificateCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case EXTERNAL_ACCOUNT_BINDING_ID: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raRequest.setExternalAccountIdSearchExact(true);
                        }
                        raRequest.setExternalAccountIdSearchOperation(criteriaOperation.name());
                        raRequest.setExternalAccountIdSearchString(criteriaValue);
                        break;
                    }
                    case CERTIFICATE_PROFILE: {
                        raRequest.getCpIds().add(searchCertificateCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case CA: {
                        raRequest.getCaIds().add(searchCertificateCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case STATUS: {
                        final SearchCertificateCriteriaRestRequest.CertificateStatus certificateStatus = SearchCertificateCriteriaRestRequest.CertificateStatus.resolveCertificateStatusByName(criteriaValue);
                        if(certificateStatus == null) {
                            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
                        }
                        if (certificateStatus == SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_ACTIVE) {
                            raRequest.getStatuses().add(certificateStatus.getStatusValue());
                            // ECA-8578: when searching for active certificates we need to include certificates that are notified about expiration.
                            // Add this automatically to the search conditions.
                            raRequest.getStatuses().add(CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION);
                        }
                        if (certificateStatus == SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_REVOKED) {
                            raRequest.getStatuses().add(certificateStatus.getStatusValue());
                        }
                        if (SearchCertificateCriteriaRestRequest.CertificateStatus.REVOCATION_REASONS().contains(certificateStatus)) {
                            raRequest.getRevocationReasons().add(certificateStatus.getStatusValue());
                        }
                        break;
                    }
                    case ISSUED_DATE: {
                        final long issuedDateLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raRequest.setIssuedAfter(issuedDateLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raRequest.setIssuedBefore(issuedDateLong);
                        }
                        break;
                    }
                    case EXPIRE_DATE: {
                        final long expireDateLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raRequest.setExpiresAfter(expireDateLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raRequest.setExpiresBefore(expireDateLong);
                        }
                        break;
                    }
                    case REVOCATION_DATE: {
                        final long revocationDateLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raRequest.setRevokedAfter(revocationDateLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raRequest.setRevokedBefore(revocationDateLong);
                        }
                        break;
                    }
                    case UPDATE_TIME: {
                        final long updateTimeLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raRequest.setUpdatedAfter(updateTimeLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raRequest.setUpdatedBefore(updateTimeLong);
                        }
                        break;
                    }
                }
            }
            return raRequest;
        }
    }

}
