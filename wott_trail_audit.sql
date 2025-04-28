DROP FUNCTION IF EXISTS trail_audit(text);
CREATE OR REPLACE FUNCTION trail_audit(text)
RETURNS TABLE (
	username text,
        sessionid text,
--dashboards
        dashboards text,
--objects
        binaries text,
        binaries_overview text,
        applications text,
        applications_overview text,
        systems text,
        systems_overview text,
        users text,
        users_overview text,
        ipaddresses text,
        ipaddresses_overview text,
        hostnames text,
        hostnames_overview text,
        notable_events text,
        client_failures text,
--search
        search text,
--reports
        reports text,
--alerts
        alerts text,
--tools
        alert_rules text,
        notable_event_settings text,
        delivery_options text,
        subscriptions text,
        compliance text,
        license_rationalization text,
        binary_collection text,
        binary_submission text,
        malware_analysis_results text,
        saved_searches text,
        extensions text,
        extension_deployments text,
        external_api_settings text,
--admin
        users_admin_page text,
        custom_groups text,
        sso_groups text,
        retired_systems text,
        intelligence_sources text,
        system_configuration text,
        windows_defender_atp_integration text,
        agent_deployments text,
        antivirus_policy_management text,
        antivirus_quarantine_and_restore text,
--audit data
        audit_timestamp text,
        tenant_name text) 
AS
$BODY$

DECLARE

    audit RECORD;
    audit_timestamp TEXT;
    v_schema alias for $1;
    v_session_id TEXT;
    v_sql TEXT;

BEGIN

    SELECT (to_char(now(),'YYYY-MM-DDThh24:MI:SS.MSZ'))::TEXT INTO audit_timestamp;

    RAISE NOTICE 'Creating Temp Table for : %', v_schema;

    CREATE TEMP TABLE trail_audit (
        username text,
	session_id text,
--dashboards
        dashboards text,
--objects
        binaries text,
        binaries_overview text,
        applications text,
        applications_overview text,
        systems text,
        systems_overview text,
        users text,
        users_overview text,
        ipaddresses text,
        ipaddresses_overview text,
        hostnames text,
        hostnames_overview text,
        notable_events text,
        client_failures text,
--search
        search text,
--reports
        reports text,
--alerts
        alerts text,
--tools
        alert_rules text,
        notable_event_settings text,
        delivery_options text,
        subscriptions text,
        compliance text,
        license_rationalization text,
        binary_collection text,
        binary_submission text,
        malware_analysis_results text,
        saved_searches text,
        extensions text,
        extension_deployments text,
        external_api_settings text,
--admin
        users_admin_page text,
        custom_groups text,
        sso_groups text,
        retired_systems text,
        intelligence_sources text,
        system_configuration text,
        windows_defender_atp_integration text,
        agent_deployments text,
        antivirus_policy_management text,
        antivirus_quarantine_and_restore text,
--audit data
        audit_timestamp text,
        tenant_name text)
    ON COMMIT DROP;

    RAISE NOTICE 'Build records to process for : %', v_schema;

	EXECUTE 'set search_path to ' || v_schema || ';';

        RAISE NOTICE 'Iterating over Users: %', v_schema;

    FOR audit in ( 
        SELECT distinct session_id as s_id from user_audit_trail where created_at > (now() - INTERVAL '7 days'))
        
	LOOP

        v_session_id := audit.s_id::TEXT;
        EXECUTE 'INSERT INTO trail_audit(audit_timestamp,tenant_name)
        VALUES ($1, $2);' USING audit_timestamp, v_schema;
            
	v_sql := 'UPDATE trail_audit SET session_id = ''' || v_session_id || ''' where tenant_name = ''' || v_schema || ''' and session_id is null; 
UPDATE trail_audit SET username = (select distinct(username) from ' || v_schema || '.user_audit_trail where session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || '''; 
UPDATE trail_audit SET dashboards = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/welcome%''and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || '''; 
UPDATE trail_audit SET binaries = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/binaries/binaries'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET binaries_overview = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/binaries/overview%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET applications = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/applications/applications'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET applications_overview = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/applications/overview%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET systems = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/systems/systems'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET systems_overview = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/systems/overview%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET users = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/osusers/osusers'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET users_overview = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/osusers/overview%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET ipaddresses = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/ipaddresses/ipaddresses'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET ipaddresses_overview = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/ipaddresses/overview%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET hostnames = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/hostnames/hostnames'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET hostnames_overview = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/hostnames/overview%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET notable_events = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/notable-events%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET client_failures = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/mishaps/mishaps%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET search = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/search%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET reports = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/reportmanager/%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET alerts = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/messages'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET alert_rules = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/alertrules%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET notable_event_settings = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/notable-event-definitions'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET delivery_options = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/alertoptions'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET subscriptions = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/subscription'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET compliance = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/compliance'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET license_rationalization = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/license_rationalization'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET binary_collection = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/binarymanagement/binary-collections'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET binary_submission = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/binarymanagement/binary-submissions'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET malware_analysis_results = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/binarymanagement/threat-lookups'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET saved_searches = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/saved-searches'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET extensions = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/extensions'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET extension_deployments = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/extension-deployments'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET external_api_settings = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/externalapisettings%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET users_admin_page = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/users'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET custom_groups = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/group'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET sso_groups = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/sso-groups/groups'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET retired_systems = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/systems/retired'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET intelligence_sources = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/intelligence/intelligence-sources'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET system_configuration= (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/admin/systemconfig%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET windows_defender_atp_integration = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/admin/wdatp-integration'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET agent_deployments = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/deployments/deployments'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET antivirus_policy_management = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page = ''/anti-virus'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';
UPDATE trail_audit SET antivirus_quarantine_and_restore = (select count(*) from ' || v_schema || '.user_audit_trail where category = ''page view'' and page like ''/anti-virus-quarantine%'' and session_id = ''' || v_session_id || ''') where session_id = ''' || v_session_id || ''';';

	EXECUTE v_sql;

        END LOOP;

    	RAISE NOTICE 'User Audit Trail Iteration Complete';

	EXECUTE 'copy (select * from trail_audit order by username) TO ''/opt/bin/support/wott_reports/final_result_csv/trail_audit_' || audit_timestamp || '.csv'' DELIMITER '','' CSV HEADER;';

-- RETURN QUERY select * from trail_audit order by username;

END;
$BODY$

LANGUAGE plpgsql VOLATILE
    COST 100;
ALTER FUNCTION trail_audit(TEXT) OWNER TO root;
