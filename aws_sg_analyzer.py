import boto3
import botocore.exceptions
from botocore.exceptions import ClientError
import csv
import time
from datetime import datetime
import os
from tabulate import tabulate
from art import *
from yaspin import yaspin
import socket
import xlsxwriter
import nmap

# Ignore Boto3 Python deprecation warning
boto3.compat.filter_python_deprecation_warnings()

selected_profile = 'default'
default_region = None
session = None
current_user = None


class bColors:
    Magenta = '\033[95m'
    Blue = '\033[94m'
    Cyan = '\033[96m'
    BrightGreen = '\033[92m'
    BrightYellow = '\033[93m'
    BrightRed = '\033[91m'
    White = '\033[37m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_iana_service_to_port_mapping():
    PortToService = []
    with open('service-names-port-numbers.csv', mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            PortToService.append([row["Service Name"], row["Port Number"], row["Transport Protocol"]])

    return PortToService


def port_scan(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((ip, int(port.split('/')[1])))
    if result == 0:
        print(bColors.BrightGreen + "-- Port {} is open".format(port) + bColors.ENDC)
    elif result == 111 or 11:
        print(bColors.BrightRed + "-- Port {} is closed".format(port) + bColors.ENDC)
    s.close()

def port_scan_nmap(ip, ports):
    results = []
    # initialize the port scanner
    nmScan = nmap.PortScanner()

    for record in ports:
        proto = record.split('/')[0]
        port = record.split('/')[1]

        if proto == 'tcp':
            nmScan.scan(ip, arguments=f'-n -R -sT -Pn -p {port} ')
        elif proto == 'udp':
            nmScan.scan(ip, arguments=f'-n -R -sU -Pn -p {port} ')

        for host in nmScan.all_hosts():
            for proto in nmScan[host].all_protocols():
                lport = nmScan[host][proto].keys()
                for port in lport:
                    #results.append(f"{proto}/{port}/{nmScan[host][proto][port]['state']}")
                    if nmScan[host][proto][port]['state'] == 'open':
                        print(bColors.BrightGreen + f"-- Port {proto}/{port} is {nmScan[host][proto][port]['state']}" + bColors.ENDC)
                    else:
                        print(bColors.BrightRed + f"-- Port {proto}/{port} is {nmScan[host][proto][port]['state']}" + bColors.ENDC)

    #return results

def get_service_name_by_port_number(portNumber, protocol):
    try:
        serviceName = socket.getservbyport(portNumber, protocol)
    except OSError:
        serviceName = "Port used for multiple services/applications"

    return serviceName


def get_service_name_by_port(portNumber, protocol, ianaList):
    serviceName = "-"
    for i in ianaList:
        if i[1] == portNumber and i[2] == protocol:
            serviceName = i[0]

    return serviceName


def get_aws_regions():
    ec2 = session.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    regions.sort()
    return regions


def get_ec2_security_groups_all(regionsList):
    result = []
    for region in regionsList:
        ec2 = session.client('ec2', region_name=region)
        security_groups = ec2.describe_security_groups()
        for sg in security_groups['SecurityGroups']:
            result.append([region, sg['GroupId'], sg['GroupName'], sg['Description']])
    return result


def get_ec2_security_groups_by_region(regionName):
    sgList = []
    ec2 = session.client('ec2', region_name=regionName)
    security_groups = ec2.describe_security_groups()

    for sg in security_groups['SecurityGroups']:

        description = "No description"
        if "Description" in sg:
            description = sg['Description']

        security_group_rules = ec2.describe_security_group_rules(
            Filters=[{"Name": 'group-id', "Values": [sg['GroupId']]}])

        inRulesCount = 0
        outRulesCount = 0

        for r in security_group_rules['SecurityGroupRules']:
            if not r['IsEgress']:
                inRulesCount += 1
            if r['IsEgress']:
                outRulesCount += 1

        network_interfaces = ec2.describe_network_interfaces(Filters=[{"Name": 'group-id', "Values": [sg['GroupId']]}])

        sgList.append([sg['GroupName'], sg['GroupId'], description, inRulesCount, outRulesCount,
                       len(network_interfaces["NetworkInterfaces"])])

    return sgList


def get_ec2_instance_name_by_id(instanceId, region):
    ec2_client = session.client('ec2', region_name=region)
    response = ec2_client.describe_instances(InstanceIds=[instanceId])
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            for tag in instance["Tags"]:
                if tag["Key"] == "Name":
                    return tag["Value"]


def get_ec2_instance_public_ip_by_id(instanceId, region, instanceState="running"):
    ec2_client = session.client('ec2', region_name=region)
    response = ec2_client.describe_instances(InstanceIds=[instanceId])
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "running":
                return instance["PublicIpAddress"]


def get_ec2_security_groups_no_rules_by_region(regionName):
    sgList = []
    ec2 = session.client('ec2', region_name=regionName)
    security_groups = ec2.describe_security_groups()

    for sg in security_groups['SecurityGroups']:

        description = "No description"
        if "Description" in sg:
            description = sg['Description']

        if len(sg['IpPermissions']) == 0 and len(sg['IpPermissionsEgress']) == 0:
            sgList.append(
                [sg['GroupName'], sg['GroupId'], description, len(sg['IpPermissions']), len(sg['IpPermissionsEgress'])])

    return sgList


def get_security_group_name_by_id(sgList, SecurityGroupID):
    for sg in sgList['SecurityGroups']:
        if sg['GroupId'] == SecurityGroupID:
            return sg['GroupName']


def delete_security_group_by_id(regionName, SecurityGroupID):
    ec2 = session.client('ec2', region_name=regionName)
    response = ec2.delete_security_group(GroupId=SecurityGroupID)
    return response


def get_security_group_rules(regionName, sgID, IANA):
    ec2 = session.client('ec2', region_name=regionName)
    sgList = ec2.describe_security_groups()
    security_group_rule = ec2.describe_security_group_rules(Filters=[{"Name": 'group-id', "Values": [sgID]}])
    rulesList = []

    for rule in security_group_rule['SecurityGroupRules']:
        traffic_direction = "-"
        if not rule['IsEgress']:
            traffic_direction = "Inbound"
        if rule['IsEgress']:
            traffic_direction = "Outbound"

        protocol = "-"
        if rule['IpProtocol'] == '-1':
            protocol = "All protocols"
        else:
            protocol = rule['IpProtocol']

        port = "-"
        if rule['ToPort'] == -1:
            port = "All ports"
        else:
            port = rule['ToPort']

        description = "No description"
        if "Description" in rule:
            description = rule['Description']

        if protocol != "All ports" and port != "All ports":
            service_name = get_service_name_by_port(str(port), protocol, IANA)
        else:
            service_name = "All services"

        # Allowed Source (Inbound Rules) or Destination (Outbound Rules)
        SrcDstEndpoint = None
        if 'CidrIpv4' in rule:
            SrcDstEndpoint = rule['CidrIpv4']
        elif 'PrefixListId' in rule:
            SrcDstEndpoint = rule['PrefixListId']
        elif 'ReferencedGroupInfo' in rule:
            SrcDstEndpoint = rule['ReferencedGroupInfo']['GroupId']
            sgName = get_security_group_name_by_id(sgList, SrcDstEndpoint)
            SrcDstEndpoint = 'sg:' + sgName

        rulesList.append(
            [rule['SecurityGroupRuleId'], traffic_direction, protocol, port, description, service_name, SrcDstEndpoint])

    return rulesList


def get_unused_ec2_security_groups_by_region(regionName):
    ec2 = session.client('ec2', region_name=regionName)
    security_groups = ec2.describe_security_groups()

    SGsOnInterfaces = []

    for sg in security_groups['SecurityGroups']:
        network_interfaces = ec2.describe_network_interfaces(Filters=[{"Name": 'group-id', "Values": [sg['GroupId']]}])
        if len(network_interfaces['NetworkInterfaces']) == 0:
            SGsOnInterfaces.append([sg['GroupName'], sg['GroupId']])

    return SGsOnInterfaces


def get_ec2_associated_to_SG(ec2_data_set, SecurityGroupID):
    InstancesAndSecurityGroups = []
    ec2instances = ec2_data_set
    for instance in ec2instances:
        for ins_config in instance['Instances']:
            for sg in ins_config['SecurityGroups']:
                if SecurityGroupID == sg['GroupId']:
                    InstancesAndSecurityGroups.append(ins_config['InstanceId'])
    return InstancesAndSecurityGroups


def get_elb_associated_to_SG(elb_data_set, SecurityGroupID):
    ELBsndSecurityGroups = []
    elbs = elb_data_set
    for lb in elbs['LoadBalancers']:
        if SecurityGroupID in lb['SecurityGroups']:
            ELBsndSecurityGroups.append(lb['LoadBalancerName'])
    return ELBsndSecurityGroups


def get_rds_associated_to_SG(rds_data_Set, SecurityGroupID):
    RDSandSecurityGroups = []
    rds_instances = rds_data_Set
    for rds_ins in rds_instances['DBInstances']:
        for rds_sg in rds_ins['VpcSecurityGroups']:
            if rds_sg['VpcSecurityGroupId'] == SecurityGroupID:
                RDSandSecurityGroups.append(rds_ins['DBInstanceIdentifier'])

    return RDSandSecurityGroups


def get_ds_associated_to_SG(ds_data_set, SecurityGroupID):
    DSandSecurityGroups = []
    directories = ds_data_set
    for directory in directories['DirectoryDescriptions']:
        if directory['VpcSettings']['SecurityGroupId'] == SecurityGroupID:
            DSandSecurityGroups.append(f"{directory['DirectoryId']} ({directory['Name']})")

    return DSandSecurityGroups


def get_elasticache_associated_to_SG(elasticache_data_set, SecurityGroupID):
    ECandSecurityGroups = []
    elasticache_clusters = elasticache_data_set
    for cluster in elasticache_clusters['CacheClusters']:
        for sg in cluster['SecurityGroups']:
            if sg['SecurityGroupId'] == SecurityGroupID:
                ECandSecurityGroups.append(cluster['CacheClusterId'])

    return ECandSecurityGroups


def get_redshift_associated_to_SG(redshift_data_set, SecurityGroupId):
    RedshiftandSecurityGroups = []
    redshift_clusters = redshift_data_set
    for cluster in redshift_clusters['Clusters']:
        for sg in cluster['VpcSecurityGroups']:
            if sg['VpcSecurityGroupId'] == SecurityGroupId:
                RedshiftandSecurityGroups.append(cluster['ClusterIdentifier'])

    return RedshiftandSecurityGroups


def get_opensearch_associated_to_SG(opensearch_data_set, SecurityGroupId):
    OpensearchandSecurityGroups = []
    opensearch_domain_settings = opensearch_data_set
    for item in opensearch_domain_settings['DomainStatusList']:
        for sg in item['VPCOptions']['SecurityGroupIds']:
            if sg == SecurityGroupId:
                OpensearchandSecurityGroups.append(item['DomainName'])
    return OpensearchandSecurityGroups


def get_lambda_associated_to_SG(lambda_data_set, SecurityGroupId):
    LambdaandSecurityGroups = []
    lambda_functions = lambda_data_set
    for fn in lambda_functions['Functions']:
        if 'VpcConfig' in fn:
            if SecurityGroupId in fn['VpcConfig']['SecurityGroupIds']:
                LambdaandSecurityGroups.append(fn['FunctionName'])

    return LambdaandSecurityGroups


def get_SG_attached_to_ec2_instances(regionName, InstanceId):
    InstancesAndSecurityGroups = []
    ec2 = session.client('ec2', region_name=regionName)
    network_interfaces = ec2.describe_network_interfaces(
        Filters=[{"Name": 'attachment.instance-id', "Values": [InstanceId]}])
    for net_interface in network_interfaces['NetworkInterfaces']:
        if net_interface['InterfaceType'] == "interface":
            if "InstanceId" in net_interface['Attachment']:
                for sg in net_interface['Groups']:
                    InstancesAndSecurityGroups.append([sg['GroupName'], sg['GroupId']])

    return InstancesAndSecurityGroups


def get_ec2_instance_public_ip_by_id(instanceId, region):
    ec2_client = session.client('ec2', region_name=region)
    response = ec2_client.describe_instances(InstanceIds=[instanceId])
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "running":
                return instance["PublicIpAddress"]


def generate_detailed_resources_block(excel_wb, excel_ws, start_row, resource_type, data_set):
    for resource_id_or_name in data_set:
        excel_ws.write_row('A' + str(start_row), [resource_type, resource_id_or_name])
        start_row += 1

    return start_row


def generate_security_groups_report_by_region(region):
    # pre-load resources information in region
    EC2_all = session.client('ec2', region_name=region).describe_instances()['Reservations']
    ELB_all = session.client('elbv2', region_name=region).describe_load_balancers()
    RDS_all = session.client('rds', region_name=region).describe_db_instances()
    DS_all = session.client('ds', region_name=region).describe_directories()
    ElastiCache_all = session.client('elasticache', region_name=region).describe_cache_clusters()
    Redshift_all = session.client('redshift', region_name=region).describe_clusters()

    OpenSearch_domains = session.client('opensearch', region_name=region).list_domain_names()
    OpenSearch_domain_names = [domain['DomainName'] for domain in OpenSearch_domains['DomainNames']]
    OpenSearch_all = session.client('opensearch', region_name=region).describe_domains(
        DomainNames=OpenSearch_domain_names)
    Lambda_all = session.client('lambda', region_name=region).list_functions()

    # script_full_path = (os.getcwd() + '/' + os.path.basename(__file__))

    # Reports folder
    folder_name = "Reports"
    if not os.path.exists(f'/{os.getcwd()}/{folder_name}/'):
        os.makedirs(f'/{os.getcwd()}/{folder_name}/')

    if not os.path.exists(f"/{os.getcwd()}/{folder_name}/{aws_session_identity['Account']}/"):
        os.makedirs(f"/{os.getcwd()}/{folder_name}/{aws_session_identity['Account']}/")

    # Generating Region Security Groups Summary
    dt_string = datetime.now().strftime("%d-%m-%YT%H%M%S")
    workbook = xlsxwriter.Workbook(
        f"/{os.getcwd()}/{folder_name}/{aws_session_identity['Account']}/" + region + f' {dt_string}' + '.xlsx')
    worksheet = workbook.add_worksheet()
    worksheet.name = "Summary"

    cell_format = workbook.add_format()
    cell_format.set_font_color('#F8F0E3')
    cell_format.set_fg_color('#003399')
    cell_format.set_font_size(20)

    worksheet.set_column('A:A', 30)
    worksheet.set_column('B:B', 20)
    worksheet.set_column('C:C', 40, workbook.add_format({'text_wrap': True}))
    worksheet.set_column('D:F', 15, workbook.add_format({'center_across': True}))

    worksheet.merge_range("A1:F1", "Summary", cell_format)
    worksheet.merge_range("A2:C2",
                          f"Created by {current_user} for Account ID {aws_session_identity['Account']}",
                          workbook.add_format({'bold': True, 'font_color': 'black'}))

    # Get Security Group info per region.
    sgList = get_ec2_security_groups_by_region(region)

    # Summary worksheet
    if len(sgList) > 0:
        worksheet.add_table(3, 0, len(sgList) + 3, 5, {'columns': [{'header': 'SG Name'},
                                                                   {'header': 'SG Id'},
                                                                   {'header': 'Description'},
                                                                   {'header': 'Inbound Rules'},
                                                                   {'header': 'Outbound Rules'},
                                                                   {'header': 'Associated Resources'}, ]
            , 'style': 'Table Style Light 10'
                                                       })

        # Iterate over the data and write it out row by row.
        row = 5
        for sg_name, sg_id, desc, inbound, outbound, associatedInterfaces in sgList:
            worksheet.write_row('A' + str(row), [sg_name, sg_id, desc, inbound, outbound, associatedInterfaces])
            if len(sg_name) > 31:
                worksheet.write_url('A' + str(row), f"internal:'{sg_name[:31]}'!A1", string=sg_name)
            else:
                worksheet.write_url('A' + str(row), f"internal:'{sg_name}'!A1", string=sg_name)
            row += 1

    # Generating Security Groups Details
    for sg in sgList:
        worksheet_sg = workbook.add_worksheet()
        if len(sg[0]) > 31:
            worksheet_sg.name = sg[0][:31]
        else:
            worksheet_sg.name = sg[0]

        cell_format = workbook.add_format()
        cell_format.set_font_color('#F8F0E3')
        cell_format.set_fg_color('#003399')
        cell_format.set_font_size(20)
        worksheet_sg.merge_range("A1:G1", f'{sg[0]} ({sg[1]})', cell_format)

        worksheet_sg.set_column('A:A', 30)
        worksheet_sg.set_column('B:B', 30, workbook.add_format({'text_wrap': True}))
        worksheet_sg.set_column('C:C', 20)
        worksheet_sg.set_column('D:F', 15, workbook.add_format({'center_across': True}))
        worksheet_sg.set_column('G:G', 30, workbook.add_format({'center_across': True}))

        # Get Security Group Rules Details.
        rulesInfo = get_security_group_rules(allRegions[allRegions.index(region)], sg[1], IANA_DB)

        # Iterate over the data and write it out row by row.
        if len(rulesInfo) > 0:
            worksheet_sg.add_table(2, 0, len(rulesInfo) + 2, 6, {'columns': [{'header': 'SG RuleId'},
                                                                             {'header': 'Description'},
                                                                             {'header': 'Traffic Direction'},
                                                                             {'header': 'Protocol'},
                                                                             {'header': 'Port'},
                                                                             {'header': 'Service Name'},
                                                                             {'header': 'Src/Dst'}, ]
                , 'style': 'Table Style Light 10'
                                                                 })

            row = 4
            for sg_rule_id, traffic_direction, protocol, port, description, service_name, SrcDst in rulesInfo:
                worksheet_sg.write_row('A' + str(row),
                                       [sg_rule_id, description, traffic_direction, protocol, port, service_name,
                                        SrcDst])

                if SrcDst is not None and SrcDst.startswith('sg:'):
                    SrcDst = SrcDst.split(':')[1]
                    worksheet_sg.write_url('G' + str(row), f"internal:'{SrcDst}'!A1", string=SrcDst)

                row += 1

        else:
            cell_format = workbook.add_format()
            cell_format.set_font_color('#C00000')
            cell_format.set_fg_color('#FFCC00')
            cell_format.set_font_size(18)

            row = 3
            worksheet_sg.merge_range(("A" + str(row) + ":B" + str(row)),
                                     "No rules found in this Security Group", cell_format)
            row = 4

        row += 1

        worksheet_sg.merge_range(("A" + str(row) + ":B" + str(row)),
                                 "Associated Resources", cell_format)

        table_start_row = row + 1

        row += 1

        # Get EC2 Instances associated with the security group
        instances = get_ec2_associated_to_SG(EC2_all, sg[1])
        if len(instances) > 0:
            EC2Instances = []
            for instance_id in instances:
                instance_name = get_ec2_instance_name_by_id(instance_id, allRegions[allRegions.index(region)])
                EC2Instances.append(f"{instance_id} ({instance_name})")

            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'EC2', EC2Instances)

        # Get ELBs associated with the security group
        elbs = get_elb_associated_to_SG(ELB_all, sg[1])
        if len(elbs) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'ELB', elbs)

        # Get RDS associated with the security group
        RDS = get_rds_associated_to_SG(RDS_all, sg[1])
        if len(RDS) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'RDS', RDS)

        # Get Directory Service associated with the security group
        DS = get_ds_associated_to_SG(DS_all, sg[1])
        if len(DS) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'Directory Service', DS)

        # Get ElastiCache associated with the security group
        EC = get_elasticache_associated_to_SG(ElastiCache_all, sg[1])
        if len(EC) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'ElastiCache', EC)

        # Get Redshift associated with the security group
        Redshift = get_redshift_associated_to_SG(Redshift_all, sg[1])
        if len(Redshift) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'Redshift', Redshift)

        # Get OpenSearch associated with the security group
        OpenSearch = get_opensearch_associated_to_SG(OpenSearch_all, sg[1])
        if len(OpenSearch) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'OpenSearch', OpenSearch)

        # Get Lambda associated with the security group
        Lambda = get_lambda_associated_to_SG(Lambda_all, sg[1])
        if len(Lambda) > 0:
            row = generate_detailed_resources_block(workbook, worksheet_sg, row, 'Lambda', Lambda)

        # print(str(table_start_row) + "---" + str(row))
        if (row - table_start_row) > 1:
            worksheet_sg.add_table("A" + str(table_start_row) + ":B" + str(row - 1),
                                   {'columns': [{'header': 'Resource Type'},
                                                {'header': 'Resource Name'}]
                                       , 'style': 'Table Style Light 10'})
    workbook.close()


def continue_or_exit_menu_option():
    userOption = input(bColors.Magenta + '''\nEnter (e) to exit or (r) to return to the main menu: ''' + bColors.ENDC)

    if userOption == 'e':
        exit()
    elif userOption == 'r':
        main_action_menu()


def main_action_menu():
    userOption = input(bColors.Magenta + '''\nPlease select one of the following options:
    (1) List security groups in region.
    (2) List security group's rules
    (3) List security groups with no rules.
    (4) List unattached security groups.
    (5) List EC2 instances associated with specific security group.
    (6) List EC2 instances associated with specific security group (+EC2 Port Scan).
    (7) List security groups attached to EC2 instance. 
    (8) Generate Report.
    (9) Exit.

    Option >>>''' + bColors.ENDC)

    if userOption == '1':
        userSubMenuOption = input(bColors.Magenta + '''
    (1) List all security groups in all enabled AWS regions.
    (2) List all security groups in specific AWS region.
    (r) Return to the main menu.

    Option >>> ''' + bColors.ENDC)

        if userSubMenuOption == '1':
            print(bColors.BrightGreen + "\n(1) List all security groups in all enabled AWS regions." + bColors.ENDC)
            print(
                bColors.BrightYellow + "\nThis is will take some time to go through all enabled AWS regions. Hold tight!" + bColors.ENDC)
            with yaspin(text="Loading Security Groups in all AWS Regions...", color="blue") as spinner:
                spinner.start()
                print("\n" +
                      tabulate(get_ec2_security_groups_all(allRegions),
                               headers=["Region", "SG ID", "SG Name", "Description"],
                               tablefmt='grid', maxcolwidths=[25, 30, 30, 50]))
                spinner.stop()
                continue_or_exit_menu_option()

        elif userSubMenuOption == '2':
            print(bColors.BrightGreen + "\n(2) List all security groups in specific AWS region.\n" + bColors.ENDC)
            print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
            counter = 0
            for region in allRegions:
                print("%d. %s" % (counter, region))
                counter += 1
            selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
            print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)
            with yaspin(text=f"Loading Security Groups in {allRegions[selectedRegion]}", color="blue") as spinner:
                spinner.start()
                print("\n" + tabulate(get_ec2_security_groups_by_region(allRegions[selectedRegion]),
                                      headers=["SG Name", "SG ID", "Description", "Inbound Rules (Count)",
                                               "Outbound Rules (Count)", "Associated Interfaces"],
                                      tablefmt='grid', maxcolwidths=[30, 30, 30, 30, 30, 30]))
                spinner.stop()
                continue_or_exit_menu_option()

        elif userSubMenuOption == 'r':
            main_action_menu()

    elif userOption == '2':
        print(bColors.BrightGreen + "\n(2) List security group's rules" + bColors.ENDC)
        print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
        counter = 0
        for region in allRegions:
            print("%d. %s" % (counter, region))
            counter += 1
        selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
        print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)

        print(bColors.BrightGreen + f"Loading Security Groups in {allRegions[selectedRegion]}" + bColors.ENDC)
        sgList = get_ec2_security_groups_by_region(allRegions[selectedRegion])
        counter = 0
        for sg in sgList:
            print("%d. %s (%s)" % (counter, sg[0], sg[1]))
            counter += 1
        selectedSG = int(input(bColors.Magenta + "\nPlease select Security Group from the list:" + bColors.ENDC))

        with yaspin(text="Loading Security Groups Rules...", color="blue") as spinner:
            spinner.start()
            rulesInfo = get_security_group_rules(allRegions[selectedRegion], sgList[selectedSG][1], IANA_DB)
            print("\nTotal Rules (%d) " % len(rulesInfo))
            print("\n" + tabulate(rulesInfo,
                                  headers=["SG RuleId", "Traffic Direction", "Protocol", "Port", "Description",
                                           "Service Name", "Src (In) / Dst (Out)"],
                                  tablefmt='grid', maxcolwidths=[30, 25, 25, 25, 60, 30, 30]))
            spinner.stop()
        continue_or_exit_menu_option()

    elif userOption == '3':
        print(bColors.BrightGreen + "\n(3) List security groups with no rules." + bColors.ENDC)
        print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
        counter = 0
        for region in allRegions:
            print("%d. %s" % (counter, region))
            counter += 1
        selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
        print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)
        sgList = get_ec2_security_groups_no_rules_by_region(allRegions[selectedRegion])
        if len(sgList) > 0:
            with yaspin(text="Loading Security Groups ...", color="blue") as spinner:
                spinner.start()
                print("\n" + tabulate(sgList,
                                      headers=["SG Name", "SG ID", "Description", "Inbound Rules (Count)",
                                               "Outbound Rules (Count)"],
                                      tablefmt='grid', maxcolwidths=[30, 30, 60, 30, 30]))
                spinner.stop()

            deleteSGoption = input(bColors.BrightYellow + "\nDo you want to delete those zero-rules security groups (if yes, type confirm): " + bColors.ENDC)

            if deleteSGoption.lower() == 'confirm':
                for sg in sgList:
                    delete_security_group_by_id(allRegions[selectedRegion], sg[1])
                    print(bColors.Cyan + f"{sg[0]} ({sg[1]}) has been deleted." + bColors.ENDC)

                continue_or_exit_menu_option()
            else:
                continue_or_exit_menu_option()
        else:
            print(bColors.Cyan + f"Great job! We didn't find any security group with no rules in {allRegions[selectedRegion]}" + bColors.ENDC)
            continue_or_exit_menu_option()

    elif userOption == '4':
        print(bColors.BrightGreen + "\n(4) List unattached security groups." + bColors.ENDC)
        print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
        counter = 0
        for region in allRegions:
            print("%d. %s" % (counter, region))
            counter += 1
        selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
        print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)
        data = get_unused_ec2_security_groups_by_region(allRegions[selectedRegion])

        with yaspin(text=f"Loading Unused/Unattached Security Groups in {allRegions[selectedRegion]}",
                    color="blue") as spinner:
            spinner.start()
            print("\n" + tabulate(data, headers=["SG Name", "SG ID"], tablefmt='grid', maxcolwidths=[30, 30]))
            recordsCount = len(data)
            table = [[allRegions[selectedRegion], str(recordsCount)]]
            print("\n" + tabulate(table, headers=["Region", "Un-used SGs (Count)"], tablefmt='grid',
                                  maxcolwidths=[30, 30]))
            spinner.stop()

        continue_or_exit_menu_option()

    elif userOption == '5':
        print(bColors.BrightGreen + "\n(5) List EC2 instances associated with specific security group." + bColors.ENDC)
        print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
        counter = 0
        for region in allRegions:
            print("%d. %s" % (counter, region))
            counter += 1
        selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
        print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)

        with yaspin(text=f"Loading Security Groups in {allRegions[selectedRegion]}", color="blue") as spinner:
            spinner.start()
            sgList = get_ec2_security_groups_by_region(allRegions[selectedRegion])
            counter = 0
            for sg in sgList:
                print("\n%d. %s (%s)" % (counter, sg[0], sg[1]))
                counter += 1
            spinner.stop()

        selectedSG = int(input(bColors.Magenta + "\nPlease select Security Group from the list:" + bColors.ENDC))
        print(bColors.Cyan + "Security Groups ID: %s" % sgList[selectedSG][1] + bColors.ENDC)
        print(bColors.Cyan + "Loading EC2 Instances IDs..." + bColors.ENDC)
        instances = get_ec2_associated_to_SG(
            boto3.client('ec2', region_name=allRegions[selectedRegion]).describe_instances()['Reservations'],
            sgList[selectedSG][1])
        print("%d EC2 instances found attached to Security Group %s" % (len(instances), sgList[selectedSG][1]))
        if len(instances) > 0:
            for instance_id in instances:
                print("%s (%s)" % (get_ec2_instance_name_by_id(instance_id, allRegions[selectedRegion]), instance_id))
        else:
            print(bColors.BrightYellow + "No EC2 instance found attached to Security Group %s" % sgList[selectedSG][
                1] + bColors.ENDC)

        continue_or_exit_menu_option()

    elif userOption == '6':
        userSubMenuOption = input(bColors.Magenta + '''
    (1) Port scanning using Python socket library.
    (2) Port Scanning using Python Nmap (requires root privileges).
    (r) Return to the main menu.

    Option >>> ''' + bColors.ENDC)

        print(
            bColors.BrightGreen + "\n(6) List EC2 instances associated with specific security group (+EC2 Ports Scan)." + bColors.ENDC)
        print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
        counter = 0
        for region in allRegions:
            print("%d. %s" % (counter, region))
            counter += 1
        selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
        print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)

        with yaspin(text=f"Loading Security Groups in {allRegions[selectedRegion]}", color="blue") as spinner:
            spinner.start()
            sgList = get_ec2_security_groups_by_region(allRegions[selectedRegion])
            counter = 0
            for sg in sgList:
                print("\n%d. %s (%s)" % (counter, sg[0], sg[1]))
                counter += 1
            spinner.stop()

        selectedSG = int(input(bColors.Magenta + "\nPlease select Security Group from the list:" + bColors.ENDC))
        print(bColors.Cyan + "Security Groups ID: %s" % sgList[selectedSG][1] + bColors.ENDC)
        rulesInfo = get_security_group_rules(allRegions[selectedRegion], sgList[selectedSG][1], IANA_DB)
        ports = []
        with yaspin(text="Loading Security Groups Rules...", color="blue") as spinner:
            spinner.start()

            for rule in rulesInfo:
                if rule[1] == "Inbound" and rule[3] != "All ports":
                    ports.append(f'{rule[2]}/{rule[3]}')

            if len(rulesInfo) > 0:
                print("\nTotal Rules (%d) " % len(rulesInfo))
            else:
                spinner.stop()
                print(bColors.BrightYellow + "This security group has no defined rules to evaluate." + bColors.ENDC)
                print(
                    bColors.BrightYellow + "Canceling the operation and returning to the main menu in seconds" + bColors.ENDC)
                time.sleep(3)
                return main_action_menu()

            print("\n" + tabulate(rulesInfo,
                                  headers=["SG RuleId", "Traffic Direction", "Protocol", "Port", "Description",
                                           "Service Name", "Src (In) / Dst (Out)"],
                                  tablefmt='grid', maxcolwidths=[30, 25, 25, 25, 60, 30, 30]))
            spinner.stop()

        print(bColors.BrightYellow + "This scan might trigger your security detection tools" + bColors.ENDC)
        print(bColors.BrightYellow + "This is simple port scanning using Python Socket module" + bColors.ENDC)
        print(bColors.BrightYellow + "This scan validates only inbound rules" + bColors.ENDC)
        print(
            bColors.BrightYellow + "This scan validates rules with specific protocol and port number. It will not validate All traffic / Al ports rules." + bColors.ENDC)

        ports = list(dict.fromkeys(ports))
        print(bColors.Cyan + "Loading EC2 Instances IDs..." + bColors.ENDC)
        instances = get_ec2_associated_to_SG(
            boto3.client('ec2', region_name=allRegions[selectedRegion]).describe_instances()['Reservations'],
            sgList[selectedSG][1])
        print("%d EC2 instances found attached to Security Group %s" % (len(instances), sgList[selectedSG][1]))
        if len(instances) > 0:
            for instance_id in instances:
                instanceName = get_ec2_instance_name_by_id(instance_id, allRegions[selectedRegion])
                instancePublicIP = get_ec2_instance_public_ip_by_id(instance_id, allRegions[selectedRegion])
                print(bColors.BOLD + "\nInstance Name: %s" % instanceName + bColors.ENDC)
                print(bColors.BOLD + "Instance Public IP: %s" % (
                    instancePublicIP if instancePublicIP is not None else "No Public IP - Instance is turned off") + bColors.ENDC)
                if instancePublicIP is not None:
                    print("Port scanning in progress...")
                    if userSubMenuOption == '1':
                        for port in ports:
                            port_scan(instancePublicIP, port)
                    elif userSubMenuOption == '2':
                        port_scan_nmap(instancePublicIP, ports)

        else:
            print(bColors.BrightYellow + "No EC2 instance found attached to Security Group %s" % sgList[selectedSG][
                1] + bColors.ENDC)

        continue_or_exit_menu_option()

    elif userOption == '7':
        print(bColors.BrightGreen + "\n(7) List security groups attached to EC2 instance." + bColors.ENDC)
        print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
        counter = 0
        for region in allRegions:
            print("%d. %s" % (counter, region))
            counter += 1
        selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
        print(bColors.Magenta + "\nRegion: %s" % allRegions[selectedRegion] + bColors.ENDC)

        print(bColors.BrightGreen + "Loading EC2 Instances in Region..." + bColors.ENDC)
        EC2_RESOURCE = boto3.resource('ec2', region_name=allRegions[selectedRegion])
        instances = EC2_RESOURCE.instances.all()
        if instances is None:
            counter = 0
            allInstances = []
            instanceName = "iName"
            for instance in instances:
                allInstances.append(instance.id)
                for t in instance.tags:
                    if t['Key'] == 'Name':
                        instanceName = t['Value']

                print("\n%d. %s (%s)" % (counter, instanceName, instance.id))
                counter += 1
            selectedInstance = int(input(bColors.Magenta + "\nPlease select EC2 from the list:" + bColors.ENDC))
            print(bColors.Cyan + f"Instance ID: {allInstances[selectedInstance]}" + bColors.ENDC)
            with yaspin(text="Loading Security Groups ...", color="blue") as spinner:
                spinner.start()
                table = get_SG_attached_to_ec2_instances(allRegions[selectedRegion], allInstances[selectedInstance])
                print("\n" + tabulate(table,
                                      headers=["SG Name", "SG ID"],
                                      tablefmt='grid', maxcolwidths=[30, 30]))
                spinner.stop()
        else:
            print(bColors.Cyan + f"No EC2 instances found in {allRegions[selectedRegion]} region." + bColors.ENDC)

        continue_or_exit_menu_option()

    elif userOption == '8':
        print(bColors.Magenta + "Generating Excel Report(s)..." + bColors.ENDC)

        userSubMenuOption = input(bColors.Magenta + '''
    (1) Generate report for all enabled AWS regions.
    (2) Generate report for specific AWS region.
    (r) Return to the main menu.

    Option >>> ''' + bColors.ENDC)

        if userSubMenuOption == '1':
            # Generating Region Security Groups Summary
            for region in allRegions:
                with yaspin(text=f"Generating report for {region}", color="blue") as spinner:
                    spinner.start()
                    generate_security_groups_report_by_region(region)
                    spinner.ok(" ✔ ")

            continue_or_exit_menu_option()

        elif userSubMenuOption == '2':
            print(bColors.BrightGreen + "Loading AWS Regions..." + bColors.ENDC)
            counter = 0
            for region in allRegions:
                print("%d. %s" % (counter, region))
                counter += 1
            selectedRegion = int(input(bColors.Magenta + "\nPlease select AWS region from the list:" + bColors.ENDC))
            start_time = time.time()
            with yaspin(text=f"Generating report for {allRegions[selectedRegion]}", color="blue") as spinner:
                spinner.start
                generate_security_groups_report_by_region(allRegions[selectedRegion])
                spinner.ok(" ✔ ")
                end_time = time.time()
                execution_time = end_time - start_time
                print("Report Generation Time: " + execution_time)
                print(f"Reports available @ /{os.getcwd()}/Reports/{aws_session_identity['Account']}/")

            continue_or_exit_menu_option()

        elif userSubMenuOption == 'r':
            main_action_menu()

    elif userOption == '9':
        print(bColors.Magenta + "Goodbye!\nExit..." + bColors.ENDC)
        exit()


# ###############################
# Script start
# ###############################
try:
    # ASCII Art
    print(text2art("SecurityGroups++"))

    # Task 0: Checking available aws profiles in ~/.aws/credentials file
    aws_profiles = boto3.Session().available_profiles

    if len(aws_profiles) == 1:
        selected_profile = 'default'
    elif len(aws_profiles) > 1:
        print(bColors.BOLD + bColors.UNDERLINE + "Available AWS Profiles:" + bColors.ENDC)
        for profile in aws_profiles:
            print(f"{profile}")

        selected_profile = input(bColors.Cyan + 'Please type profile name to continue (i.e. default) ->' + bColors.ENDC).strip()

    default_region = boto3.session.Session(profile_name=selected_profile).region_name
    print(bColors.BrightYellow + f'The default aws region for {selected_profile} profile is {default_region}.')
    session = boto3.session.Session(profile_name=selected_profile)

    # Loading AWS Regions in AWS account:
    with yaspin(text="  Getting things ready...", color="magenta") as sp:
        aws_session_identity = session.client("sts").get_caller_identity()

        # Extracting Current User from the STS Get_Caller_Identity()
        userARN = aws_session_identity['Arn'].split(':')[-1]

        if '/' in userARN:
            current_user = userARN.split('/')[-1]
        else:
            current_user = userARN


        # task 1
        time.sleep(1)
        # sp.write(
        #     f"🌩️  Connecting to AWS using the credentials of user ({aws_session_identity['UserId'].split(':')[1]})")
        sp.write(
            f"🌩️  Connecting to AWS using the credentials of user ({current_user})")

        # task 2:
        time.sleep(1)

        sp.write(f"🌩️  Fetching enabled AWS region on your AWS account ({aws_session_identity['Account']})")
        allRegions = get_aws_regions()

        # task 3
        time.sleep(1)
        sp.write("🌩️  Loading IANA Ports to Service Name mapping list...")
        IANA_DB = get_iana_service_to_port_mapping()

        # finalize
        sp.ok("✔")

    # Show main user menu
    main_action_menu()

except ClientError as err:
    print(bColors.BrightRed + "Unexpected error: %s" % err + bColors.ENDC)

