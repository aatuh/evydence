DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM oidc_authentication_requests) THEN
        RAISE EXCEPTION 'cannot downgrade while OIDC authentication request state is retained';
    END IF;
END $$;
DROP TABLE oidc_authentication_requests;
ALTER TABLE sso_providers DROP CONSTRAINT sso_providers_oidc_request_owner;
