import socket
from shared import get_findings_from_securityhub, merge_findings_to_csv, find_resource_creator_in_cloudtail


def test_connection(hostname, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((hostname, port))
        print(f"Connection to {hostname}:{port} succeeded.")
        sock.close()
        return f"SUCCEEDED"
    except socket.error as e:
        print(f"Connection to {hostname}:{port} failed: {e}")
        return f"FAILED"


# Parse important fields from SecurityHub findings
def pasrse_rds_findings_from_securityhub(page_iterator) -> list:
    """
    Parse security findings from SecurityHub page iterator and return a list of simplified findings.

    Parameters:
    - page_iterator: The page iterator from SecurityHub API.

    Returns:
    - A list of simplified findings.
    """
    simplified_findings = []
    for page in page_iterator:
        for finding_json in page['Findings']:
            finding_json_simple = {
                'account_id': finding_json.get('AwsAccountId'),
                'creation_date': finding_json.get('CreatedAt').split('T')[0].replace('-', '/'),
                # 'region': finding_json.get('Region'),
                'endpoint_id': finding_json['Resources'][0]['Details']['AwsRdsDbInstance'].get('DBInstanceIdentifier', 'None'),
                'cluster_id': finding_json['Resources'][0]['Details']['AwsRdsDbInstance'].get('DBClusterIdentifier', 'None'),
                'endpoint_fqdn': finding_json['Resources'][0]['Details']['AwsRdsDbInstance']['Endpoint'].get('Address'),
                'endpoint_port': finding_json['Resources'][0]['Details']['AwsRdsDbInstance']['Endpoint'].get('Port'),
                'sg_id': finding_json['Resources'][0]['Details']['AwsRdsDbInstance']['VpcSecurityGroups'][0].get('VpcSecurityGroupId'),
                'principal': 'None',
                'username': 'None',
                'finding_id': finding_json.get('Id'),
                'finding_type': 'imported'
            }
            simplified_findings.append(finding_json_simple)
    return simplified_findings


if __name__ == '__main__':
    findings_page_iterator = get_findings_from_securityhub(aws_profile_name='secmon-assume', control_id='RDS.2')
    parsed_findings = pasrse_rds_findings_from_securityhub(page_iterator=findings_page_iterator)
    for finding in parsed_findings:
        finding['connection_status'] = test_connection(finding.get('endpoint_fqdn'), finding.get('endpoint_port'))

    conditions = [
        ('978943420523', '2024/04/12'), ('942075822886', '2024/04/12'), ('769718273857', '2024/04/12'), ('598247635050', '2024/04/12'),
        ('584010328126', '2024/04/12')
        # Add more conditions as needed
    ]

    enriched_findings = find_resource_creator_in_cloudtail(
        aws_profile_name='logarchive-assume',
        found_sgs=parsed_findings,
        athena_db='default',
        athena_workgroup='ct',
        athena_catalog='AwsDataCatalog',
        conditions=conditions,
        athena_requestparameter_name='endpoint_id',
        athena_eventname_string='CreateDBInstance')

    merge_findings_to_csv('nonsecure_rds.csv', enriched_findings)
