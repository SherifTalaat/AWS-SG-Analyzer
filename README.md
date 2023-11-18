# AWS Security Group Analyzer
A Python command-line tool to query Security Groups in AWS accounts and easily spot (and take a decision on) stale, risky, and misconfigured security groups.

## Features
+ Interactive menu to navigate through different options
+ Listing all security group(s) details, including SG Name, SG ID, Description Inbound Rules, Outbound Rules, and Number of associated Interfaces/resources
+ Listing security groups with no defined rules and the ability to remove them.
+ Listing unattached (unused) security groups
+ Listing EC2 instances associated with a specific security group
+ Verify security group rules against actual ports open on EC2 instance using port scanning
  + Port scanning is available through Python socket and Nmap (python-nmap)
  + Nmap port scanning requires running this tool using root privilege 
+ Listing security groups attached to specific EC2 instance
+ Generating detailed XLSX reports per region that include:
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
     
# Installation

## Prerequisites
1. Ensure you have Python 3.10 installed.
2. Ensure you have ~/.aws/credentials file configured with a valid region, Access Key ID, and Secret Access Key

## Steps
1. Clone this repository

```
git clone https://github.com/sheriftalaat/xxx.git
cd xxx
```

2. Install the required packages: ```pip install -r requirements.txt```
. 

## Usage
Running the tool:
```python xxx.py```

# Contributions
Contributions are always welcome! Please open an issue or submit a pull request.

# Copyright
AWS Security Group Analyzer by Sherif Talaat (C) 2023

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/

