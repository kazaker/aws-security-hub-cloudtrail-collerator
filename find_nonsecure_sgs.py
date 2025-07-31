from shared import get_findings_from_securityhub, merge_findings_to_csv, find_resource_creator_in_cloudtail


# Parse important fields from SecurityHub findings
def pasrse_sgs_findings_from_securityhub(page_iterator) -> list:
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
                'sg_id': finding_json['Resources'][0]['Details']['AwsEc2SecurityGroup'].get('GroupId'),
                'sg_name': finding_json['Resources'][0]['Details']['AwsEc2SecurityGroup'].get('GroupName'),
                'vpc_id': finding_json['Resources'][0]['Details']['AwsEc2SecurityGroup'].get('VpcId'),
                'principal': 'None',
                'username': 'None',
                'finding_id': finding_json.get('Id'),
                'finding_type': 'imported'
            }
            simplified_findings.append(finding_json_simple)
    return simplified_findings


if __name__ == '__main__':
    conditions = [
        ('797281126456', '2023/07/28'), ('913099219137', '2023/07/28'), ('256466044624', '2023/07/28'), ('228042795122', '2023/07/28'),
        ('326144215376', '2023/08/04'), ('755477695722', '2023/08/04'), ('821841962462', '2023/08/04'), ('228143847475', '2023/08/04'),
        ('168169373468', '2023/08/08'), ('029091457365', '2023/08/08'), ('297302290031', '2023/08/08'), ('300712256265', '2023/08/08'),
        ('336268092983', '2023/08/08'), ('394859808057', '2023/08/08'), ('423567596319', '2023/08/08'), ('440692546337', '2023/08/08'),
        ('045328249740', '2023/08/08'), ('469360848296', '2023/08/08'), ('502856622653', '2023/08/08'), ('574044457341', '2023/08/08'),
        ('059385202346', '2023/08/08'), ('687998436074', '2023/08/08'), ('994006616099', '2023/08/08'), ('918009714037', '2023/08/18'),
        ('913206223978', '2023/06/01'), ('734426463323', '2024/01/19'), ('789591916199', '2023/12/18')
        # Add more conditions as needed
    ]

    findings_page_iterator = get_findings_from_securityhub(aws_profile_name='secmon-assume', control_id='EC2.19')
    parsed_findings = pasrse_sgs_findings_from_securityhub(page_iterator=findings_page_iterator)
    enriched_findings = find_resource_creator_in_cloudtail(
        aws_profile_name='logarchive-assume',
        found_sgs=parsed_findings,
        athena_db='default',
        athena_workgroup='ct',
        athena_catalog='AwsDataCatalog',
        conditions=conditions,
        athena_requestparameter_name='sg_id',
        athena_eventname_string='AuthorizeSecurityGroupIngress')
    merge_findings_to_csv('nonsecure_sgs_and_their_creators.csv', enriched_findings)

### For my own use
    data_for_dm = {}
    for finding in enriched_findings:
        if finding['finding_type'] == 'discovered':
            if ':' in finding['principal']:
                creator = finding['principal'].split(':')[-1]
            else:
                creator = finding['username']
            if creator in data_for_dm:
                data_for_dm[creator].append(finding['sg_id'])
            else:
                data_for_dm[creator] = [finding['sg_id']]
        else:
            pass
    print(data_for_dm)

    for creator in data_for_dm.keys():
        print(f'''Привет {creator}. Меня зовут Артем, я из команды Security Services.
Сейчас я занимаюсь анализом конфигурации наших AWS аккаунтов, и в процессе нашел несколько Security Groups, который, судя по логам, были созданы тобой.
Проблема с найденными группами в том, что они настроены не слишком безопасно, отрывая доступ к критичным сетевым портам портам (таким как SSH, RDP, FTP и т.д.) для всего Интернета.
Такая конфигурация создает угрозу для нашей инфраструктуры, поэтому хотелось бы попробовать их пофиксить.
Вот список SGs, о которых идет речь:
''')
        for sg in data_for_dm[creator]:
            print(f'- {sg}')
        print(f'в аккаунте <account_ID>')
        print(f'''
Было бы здорово, если бы у тебя получилось посымотреть на них и сделать что-то из следующего:
- удалить их, если они уже не используются;
- настроить их так образом, чтобы ingress правила разрешали доступ только с явно заданных IP адресов;
- посмотреть, подходит ли под твои юзкейсы наши managed prefix lists. Если коротко, эта фича может помочь легко ограничить доступ только с тех адресов, которые принадлежат площадкам JB. Как этим пользоваться, можно прочитать тут - https://youtrack.jetbrains.com/articles/AWS-A-24/AWS-Managed-prefix-lists
- посмотреть, подходит ли под твои юзкейсы сервис Systems Manager. Он позволяет подключаться к EC2 вообще без необходимости создавать ingress правила в SG. Подробнее можно почитать тут - https://youtrack.jetbrains.com/articles/AWS-A-25/AWS-Systems-Manager-SSM
''')
        print('''
#########################################
    ''')