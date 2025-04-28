############################################################################
#  wott_agent_audit.sh                                                     #
#  Version:  1.2                                                           #
#  Last Updated:  5/15/19                                                  #
#  Last Updated By:  Matthew Wottrich                                      #
#  Description:  provides stats on Agent activity as reported to a given   #
#                tenant on a Server Cluster                                #
#  Current Support:  5.2.6+                                                #
#  Dependencies:  lftp                                                     #
############################################################################

#Initialize and start Script
VERSION=1.2
BEGIN=$(date +"%s")
LOG_LOCATION="/opt/bin/support/wott_test"    
exec >> $LOG_LOCATION/wott_agent_audit.log 2>&1
echo
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
echo $(date +"%b %d %H:%M:%S"):  wott_agent_audit.sh v$VERSION starting
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#Declare Variables
echo $(date +"%b %d %H:%M:%S"):  Declaring Variables
HOST=$(hostname)
DATE=$(date +%Y-%m-%d)
SFTP_USER=audit
SFTP_PASSWD=$(CI_PASSWORD)
SFTP_HOST=$(CI_PUBLIC_IP)
SFTP_DIR=audit_tenant_results
CSV_DIR=/opt/bin/support/wott_test/final_results
USAGE_CSV=$CSV_DIR/agentUsage_$HOST\_$DATE.csv
VERT_TOTAL_COMPNAMES=0
VERT_TOTAL_GUIDS=0

#Confirm SQL env variables exist
VSQL_TEST=$(vsql -t -c "select 1;" | xargs)
PSQL_TEST=$(psql -t -c "select 1;" | xargs)
if [[ $VSQL_TEST != 1 ]] || [[ $PSQL_TEST != 1 ]]; then
    echo $(date +"%b %d %H:%M:%S"):  ERROR, Environment Variables for vsql/psql not found or incomplete, exiting
    exit 1
fi

#Create results directory
mkdir -p $CSV_DIR

#Clean up previous run's fles
echo $(date +"%b %d %H:%M:%S"):  Cleaning out previous run
find $CSV_DIR -maxdepth 1 -name 'agentUsage_*' -exec rm {} \;

#Iterate Tenants and get total System counts
echo $(date +"%b %d %H:%M:%S"):  Iterating through tenants for total systems on cluster
for i in $(psql -t -c "select CASE when s.tenant_name = 'ziften' then 'ziften_tenant' ELSE s.tenant_name || '_tenant_' || c.siteid END from global.sf_data s left join global.customers c on c.customer_id = s.customer_id where (decommissioned = false or decommissioned is null) order by 1;"); do
    TENANT_COMPNAMES=0
    TENANT_GUIDS=0
    TENANT_COMPNAMES=$(vsql -t -c "select count(distinct(computername)) from $i.systeminventory_fact;" | xargs)
    TENANT_GUIDS=$(vsql -t -c "select count(*) from $i.system_dimension;" | xargs)
    VERT_TOTAL_COMPNAMES=$(($VERT_TOTAL_COMPNAMES+$TENANT_COMPNAMES))
    VERT_TOTAL_GUIDS=$(($VERT_TOTAL_GUIDS+$TENANT_GUIDS))
done

#Create current run's files
echo "agentaudit_timestamp,cluster_appserver,Tenant Name,tenant_totalcompnames,tenant_perctotalcompnames,tenant_totalguids,tenant_perctotalguids,tenant_firstagentseen_timestamp,tenant_lastagentseen_timestamp,tenant_agentdeploymentduration,tenant_compnameslast24hrs,tenant_compnamesfirstseenlast24hrs,tenant_guidslast24hrs,tenant_guidsfirstseenlast24hrs,tenant_compnameslast7days,tenant_compnamesfirstseenlast7days,tenant_guidslast7days,tenant_guidsfirstseenlast7days,tenant_compnameslast30days,tenant_compnamesfirstseenlast30days,tenant_guidslast30days,tenant_guidsfirstseenlast30days" > $USAGE_CSV

#Iterate through tenants
echo $(date +"%b %d %H:%M:%S"):  Iterating through tenants for tenant-specific stats
for i in $(psql -t -c "select CASE when s.tenant_name = 'ziften' then 'ziften_tenant' ELSE s.tenant_name || '_tenant_' || c.siteid END from global.sf_data s left join global.customers c on c.customer_id = s.customer_id where (decommissioned = false or decommissioned is null) order by 1;"); do
    AGENTAUDIT_TIMESTAMP=$(vsql -t -c "select to_char(now(),'YYYY-MM-DDThh:MI:SS.MSZ');" | xargs)
    CLUSTER_APPSERVER=$HOST
    if [[ $i == 'ziften_tenant' ]]; then
        TENANT=$CLUSTER_APPSERVER
    else
        TENANT=$(echo $i | rev | cut -f 3 -d '_' | rev)
    fi
    SCHEMA=$i
    TENANT_TOTAL_COMPNAMES=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.systeminventory_fact;" | xargs)
    if [[ $VERT_TOTAL_COMPNAMES == 0 ]] || [[ $TENANT_TOTAL_COMPNAMES == 0 ]]; then
        TENANT_PERC_COMPNAMES=0
    else
        TENANT_PERC_COMPNAMES=$(awk -v use=$TENANT_TOTAL_COMPNAMES -v total=$VERT_TOTAL_COMPNAMES 'BEGIN {printf "%.2f\n", (use * 100)/total}')
    fi
    TENANT_TOTAL_GUIDS=$(vsql -t -c "select count(*) from $SCHEMA.system_dimension;" | xargs)    
    if [[ $VERT_TOTAL_GUIDS == 0 ]] || [[ $TENANT_TOTAL_GUIDS == 0 ]]; then
        TENANT_PERC_GUIDS=0
    else
        TENANT_PERC_GUIDS=$(awk -v use=$TENANT_TOTAL_GUIDS -v total=$VERT_TOTAL_GUIDS 'BEGIN {printf "%.2f\n", (use * 100)/total}')
    fi
    if [[ $TENANT_TOTAL_GUIDS == 0 ]]; then
        TENANT_FIRSTAGENTSEEN_TIMESTAMP=
    else
        TENANT_FIRSTAGENTSEEN_TIMESTAMP=$(vsql -t -c "select to_char(min(first_seen),'YYYY-MM-DDThh:MI:SS.MSZ') from $SCHEMA.system_dimension;" | xargs)
    fi
    if [[ $TENANT_TOTAL_GUIDS == 0 ]]; then
        TENANT_LASTAGENTSEEN_TIMESTAMP=
    else
        TENANT_LASTAGENTSEEN_TIMESTAMP=$(vsql -t -c "select to_char(max(last_seen),'YYYY-MM-DDThh:MI:SS.MSZ') from $SCHEMA.system_dimension;" | xargs)
    fi
    if [[ $TENANT_TOTAL_GUIDS == 0 ]]; then
        TENANT_AGENTDEPLOYMENTDURATION=N/A
    else
        TENANT_AGENTDEPLOYMENTDURATION=$(vsql -t -c "select (max(last_seen) - min(first_seen)) from $SCHEMA.system_dimension where last_seen <= now();" | xargs)
    fi
    TENANT_COMPNAMES_LAST24H=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.agentstatus_fact where servertime >= (now() - INTERVAL '1 day');" | xargs)
    TENANT_COMPNAMES_FS_LAST24H=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.system_dimension where first_seen >= (now() - INTERVAL '1 day');" | xargs)
    TENANT_GUIDS_LAST24H=$(vsql -t -c "select count(distinct(system_id)) from $SCHEMA.agentstatus_fact where servertime >= (now() - INTERVAL '1 day');" | xargs)
    TENANT_GUIDS_FS_LAST24H=$(vsql -t -c "select count(*) from $SCHEMA.system_dimension where first_seen >= (now() - INTERVAL '1 day');" | xargs)
    TENANT_COMPNAMES_LAST7D=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.agentstatus_fact where servertime >= (now() - INTERVAL '7 days');" | xargs)
    TENANT_COMPNAMES_FS_LAST7D=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.system_dimension where first_seen >= (now() - INTERVAL '7 days');" | xargs)
    TENANT_GUIDS_LAST7D=$(vsql -t -c "select count(distinct(system_id)) from $SCHEMA.agentstatus_fact where servertime >= (now() - INTERVAL '7 days');" | xargs)
    TENANT_GUIDS_FS_LAST7D=$(vsql -t -c "select count(*) from $SCHEMA.system_dimension where first_seen >= (now() - INTERVAL '7 days');" | xargs)
    TENANT_COMPNAMES_LAST30D=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.agentstatus_fact where servertime >= (now() - INTERVAL '30 days');" | xargs)
    TENANT_COMPNAMES_FS_LAST30D=$(vsql -t -c "select count(distinct(computername)) from $SCHEMA.system_dimension where first_seen >= (now() - INTERVAL '30 days');" | xargs)
    TENANT_GUIDS_LAST30D=$(vsql -t -c "select count(distinct(system_id)) from $SCHEMA.agentstatus_fact where servertime >= (now() - INTERVAL '30 days');" | xargs)
    TENANT_GUIDS_FS_LAST30D=$(vsql -t -c "select count(*) from $SCHEMA.system_dimension where first_seen >= (now() - INTERVAL '30 days');" | xargs)
    echo $AGENTAUDIT_TIMESTAMP,$CLUSTER_APPSERVER,$TENANT,$TENANT_TOTAL_COMPNAMES,$TENANT_PERC_COMPNAMES%,$TENANT_TOTAL_GUIDS,$TENANT_PERC_GUIDS%,$TENANT_FIRSTAGENTSEEN_TIMESTAMP,$TENANT_LASTAGENTSEEN_TIMESTAMP,$TENANT_AGENTDEPLOYMENTDURATION,$TENANT_COMPNAMES_LAST24H,$TENANT_COMPNAMES_FS_LAST24H,$TENANT_GUIDS_LAST24H,$TENANT_GUIDS_FS_LAST24H,$TENANT_COMPNAMES_LAST7D,$TENANT_COMPNAMES_FS_LAST7D,$TENANT_GUIDS_LAST7D,$TENANT_GUIDS_FS_LAST7D,$TENANT_COMPNAMES_LAST30D,$TENANT_COMPNAMES_FS_LAST30D,$TENANT_GUIDS_LAST30D,$TENANT_GUIDS_FS_LAST30D >> $USAGE_CSV
    echo $(date +"%b %d %H:%M:%S"):  Tenant $TENANT stats complete
done
echo $(date +"%b %d %H:%M:%S"):  Tenant iteration complete

#Calculate run time
END=$(date +"%s")
RUN_TIME=$(awk -v start=$BEGIN -v finish=$END 'BEGIN {printf "%.2f\n", (finish - start)/60}')
echo $(date +"%b %d %H:%M:%S"):  agent_audit.sh completed in $RUN_TIME minutes 
echo
