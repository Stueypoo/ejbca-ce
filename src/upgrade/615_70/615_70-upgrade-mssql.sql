-- New columns in CertificateData are added by the JPA provider if there are sufficient privileges
-- if not added automatically the following SQL statements can be run to add the new columns 
-- ALTER TABLE CertificateData ADD certificateRequest VARCHAR(max);
-- ALTER TABLE NoConflictCertificateData ADD certificateRequest VARCHAR(max);
-- ALTER TABLE Base64CertData ADD certificateRequest VARCHAR(max);
