import boto3 
import time
import json


def get_findings_from_securityhub(aws_profile_name: str, control_id: str):
    """
    Get all fingings for passed control

    Parameters:
    - aws_profile_name (str): the profile name used to authenticate with AWS
    - control_id (str): the profile name used to authenticate with AWS

    Returns:
    - a page iterator object that can be used to loop through the findings from SecurityHub

    """
    sec_mon = boto3.session.Session(profile_name=aws_profile_name)
    client_sec_mon = sec_mon.client('securityhub')
    paginator = client_sec_mon.get_paginator('get_findings')
    page_iterator = paginator.paginate(
        Filters={
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                },
            ],
            'ComplianceStatus': [
                {
                    'Value': 'FAILED',
                    'Comparison': 'EQUALS'
                },
            ],
            'GeneratorId': [
                {
                    'Value': f'security-control/{control_id.upper()}',
                    'Comparison': 'EQUALS'
                },
            ],
            'WorkflowStatus': [
                {
                    'Value': 'SUPPRESSED',
                    'Comparison': 'NOT_EQUALS'
                },
            ],
        }
    )
    return page_iterator


def check_conditions(account, creation_date, conditions):
    for condition in conditions:
        if (account, creation_date) == condition:
            return True
    return False


# Go to Athena to query CloudTrail logs to find who created this SG
def find_resource_creator_in_cloudtail(aws_profile_name: str, 
                                       found_sgs: list, 
                                       athena_db: str, 
                                       athena_workgroup: str, 
                                       athena_catalog: str, 
                                       conditions: list,
                                       athena_requestparameter_name: str,
                                       athena_eventname_string: str) -> list:
    """
    Enrich findings with audit logs in CloudTrail to identify creators of offending security groups.
    
    Parameters:
    - aws_profile_name (str): The AWS profile name to use for authentication.
    - found_sgs (list): A list of security group findings.
    - athena_db (str): The name of the Athena database.
    - athena_workgroup (str): The name of the Athena workgroup.
    - athena_catalog (str): The name of the Athena catalog.

    Returns:
    - The updated list of security group findings.
    """
    log_archive = boto3.session.Session(profile_name=aws_profile_name)
    client_log_archive = log_archive.client('athena')

    for simple_finding in found_sgs:
        account = simple_finding.get('account_id')
        creation_date = simple_finding.get('creation_date')
        """
        For some combinations of accounts and date we won't be able to effectively (without searching whole archive) find match in CloudTrail logs,
        because in them non-compliant security groups were created before SecurityHub was enabled.
        So in those cases creation_date is not the date when SG was created,
        but only the date when Config rules were created and discovered already existing SGs.
        To optimize Athena compute it makes sense to exlude such SGs from this part of the script.
        """
        if check_conditions(account, creation_date, conditions):
            continue

        else:
            query = f"""SELECT cast(useridentity as json) as json
            FROM
                cloudtrail_logs
            WHERE
                date = '{creation_date}'
                and account = '{account}'
                and requestparameters like '%{simple_finding.get(athena_requestparameter_name)}%'
                and eventname = '{athena_eventname_string}'
            """

            print(query)

            response = client_log_archive.start_query_execution(
                QueryString=query,
                QueryExecutionContext={
                    'Database': athena_db,
                    'Catalog': athena_catalog
                },
                WorkGroup=athena_workgroup,
                ResultReuseConfiguration={
                    'ResultReuseByAgeConfiguration': {
                        'Enabled': True,
                        'MaxAgeInMinutes': 60
                    }
                }
            )

            query_execution_id = response['QueryExecutionId']
            print(f'Query execution ID: {query_execution_id}')

            # Wait for the query to complete
            while True:
                query_execution = client_log_archive.get_query_execution(
                    QueryExecutionId=query_execution_id
                )
                execution_state = query_execution['QueryExecution']['Status']['State']
                
                if execution_state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                    break
                time.sleep(3)

            if execution_state == 'SUCCEEDED':
                print('Query execution successful')

                results = client_log_archive.get_query_results(
                    QueryExecutionId=query_execution_id
                )

                columns = [col['Label'] for col in results['ResultSet']['ResultSetMetadata']['ColumnInfo']]
                for row in results['ResultSet']['Rows'][1:]:
                    data = {}
                    for i, value in enumerate(row['Data']):
                        data[columns[i]] = value.get('VarCharValue', 'None')
                    json_data = json.loads(data.get('json'))
                    simple_finding['principal'] = json_data.get('principalid', 'None')
                    simple_finding['username'] = json_data.get('username', 'None')
                    simple_finding['finding_type'] = 'discovered'
            else:
                print('Query execution failed')

    return found_sgs


def merge_findings_to_csv(filename: str, findings: list):
    with open(filename, 'w') as f:
        f.write(';'.join(findings[0].keys()))
        f.write('\n')
        for row in findings:
            f.write(';'.join(str(x) for x in row.values()))
            f.write('\n')
            