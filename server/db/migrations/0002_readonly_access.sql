DO $$
DECLARE
    iam_role              TEXT;
    readonly_role_exists  BOOLEAN;
BEGIN
    -- Try to create a shared readonly role (requires CREATEROLE/SUPERUSER).
    BEGIN
        IF NOT EXISTS (
            SELECT 1
              FROM pg_roles
             WHERE rolname = 'ghapp_readonly'
        ) THEN
            EXECUTE 'CREATE ROLE ghapp_readonly NOLOGIN';
        END IF;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'Skipping ghapp_readonly role creation: role % lacks CREATEROLE/SUPERUSER', current_user;
    END;

    SELECT EXISTS (
        SELECT 1
          FROM pg_roles
         WHERE rolname = 'ghapp_readonly'
    ) INTO readonly_role_exists;

    IF readonly_role_exists THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO ghapp_readonly';
        EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO ghapp_readonly';
        EXECUTE 'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO ghapp_readonly';

        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ghapp_readonly';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO ghapp_readonly';
    END IF;

    -- Grant access to existing IAM users (role membership when possible,
    -- direct grants as fallback).
    FOR iam_role IN
        SELECT rolname
          FROM pg_roles
         WHERE rolname LIKE '%@%'
    LOOP
        IF readonly_role_exists THEN
            BEGIN
                EXECUTE format('GRANT ghapp_readonly TO %I', iam_role);
                CONTINUE;
            EXCEPTION
                WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Cannot grant ghapp_readonly to %, falling back to direct grants', iam_role;
            END;
        END IF;

        BEGIN
            EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', iam_role);
            EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA public TO %I', iam_role);
            EXECUTE format('GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', iam_role);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO %I', iam_role);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO %I', iam_role);
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping direct grants for %: insufficient privilege as %', iam_role, current_user;
        END;
    END LOOP;
END $$;
