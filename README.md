# AWS Security Group Analyzer
A Python command-line tool to query Security Groups in AWS accounts and easily spot (and decide on) stale, risky, and misconfigured security groups.

AWS security groups are virtual firewalls that control the inbound and outbound traffic for EC2 instances and other AWS resources. They are essential for ensuring the security and compliance of cloud environments. However, if they are not configured properly, they can expose sensitive data, allow unauthorized access, and compromise the integrity of the cloud infrastructure. Misconfigured security groups can result from human errors, lack of visibility, or insufficient policies and procedures. 

Therefore, it is important to follow the best practices for managing and auditing security groups, such as using descriptive names and tags, applying the principle of least privilege, reviewing and updating rules regularly, and using automation tools and services.

AWS Trusted Advisor will warn you about risky security groups, but it doesn’t give full visibility to take quick actions. You will have to dive deeper into configurations and move between consoles to get all the needed information. And here comes the benefit of AWS Security Groups Analyzer, it helps you gather all the needed information about the security groups to accelerate the right decision. It will tell you about stale/unused security groups, AWS resources associated with security groups, security groups with no rules. Also, it takes it to the next level and runs a port scanning against associated EC2 instance to verify the open/closed ports before changing any rule.

## Features
+ Interactive menu to navigate through different options
+ Listing all security group(s) details, including SG Name, SG ID, Description Inbound Rules, Outbound Rules, and Number of associated Interfaces/resources
+ Listing security groups with no defined rules and the ability to remove them.
+ Listing unattached (unused) security groups
+ Listing EC2 instances associated with a specific security group
+ Verify security group rules against actual ports open on EC2 instance using port scanning
  + Port scanning is available through Python socket and Nmap (python-nmap)
  + Nmap port scanning requires running this tool using root privilege (**Nmap is required for this feature to work.**)
+ Listing security groups attached to specific EC2 instance
+ Generating detailed XLSX reports per region that include: [Sample XLSX Report](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/b35ce776d57ac3284167c4081ae88cbf452fedb9/Sample%20Report.xlsx)
  + Summary of the security groups in the region
    + SG Name
    + SG ID
    + SG Description
    + Inbound Rules (count)
    + Outbound Rules (count)
    + Associated Interfaces/resources (count)
  + A page for each security group in the region that includes:
    + Details of the Security Group Rules: SG Rule Id, description, traffic direction, protocol, port, service name (according to IANA database), and source/destination
    + Associated AWS Resources (currently showing the following resources, but more to come):
      + EC2
      + ELB
      + RDS
      + Lambda
      + ElastiCache
      + Redshift
      + OpenSearch
      + Directory Service

![alt text](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/f72414ceaaf1c8dd9d5682204b99e49912cad488/Images/main%20menu.png "Main Actions Menu")

![alt text](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/f72414ceaaf1c8dd9d5682204b99e49912cad488/Images/unattached%20security%20groups.png "List Unattaced Security Groups option")

![alt text](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/f72414ceaaf1c8dd9d5682204b99e49912cad488/Images/EC2%20port%20scanning.png "Attached EC2 instances with port scanning")

![alt text](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/f72414ceaaf1c8dd9d5682204b99e49912cad488/Images/Report%20Summary.png "Report Summary Page")

![alt text](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/f72414ceaaf1c8dd9d5682204b99e49912cad488/Images/Report%20-%20SG%20details.png "Report - Security Group Details")

![alt text](https://github.com/SherifTalaat/AWS-SG-Analyzer/blob/e012ad3e91e0f3ea4b89a6a4a2c2c85a1b68b90e/Images/Report%20Port%20Scan.png "Report - EC2 Port Scan Results")


     
# Installation

## Prerequisites
1. Ensure you have Python 3.7 (preferably 3.10) installed.
2. Ensure you have nmap installed (required for Nmap port scanning)
3. Ensure you have ~/.aws/credentials file configured with a valid region, Access Key ID, and Secret Access Key

## Steps
1. Clone this repository

```
git clone https://github.com/SherifTalaat/AWS-SG-Analyzer.git
cd AWS-SG-Analyzer
```

2. Install the required packages: ```pip install -r requirements.txt```

## Usage
Running the tool:
```python aws_sg_analyzer.py```



# Contributions
Contributions are always welcome! Please open an issue or submit a pull request.

# Copyright
AWS Security Group Analyzer by Sherif Talaat (C) 2023

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/

