DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM saml_provider_bindings) OR EXISTS (SELECT 1 FROM saml_authentication_requests) OR EXISTS (SELECT 1 FROM saml_assertion_consumptions) THEN
        RAISE EXCEPTION 'cannot downgrade while SAML provider binding or authentication state is retained';
    END IF;
END $$;
DROP TABLE saml_assertion_consumptions;
DROP TABLE saml_authentication_requests;
DROP TABLE saml_provider_bindings;
