import boto3
import datetime
import re

# Specify the AWS region to use
region = 'us-west-2'

# Specify the regular expression to match instance names
instance_name_regex = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$')

# Specify the time range to check for unauthorized launches (24 hours ago)
start_time = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
end_time = datetime.datetime.utcnow()

# Create an EC2 client
ec2_client = boto3.client('ec2', region_name=region)

# Create a CloudTrail client
cloudtrail_client = boto3.client('cloudtrail', region_name=region)

# Define a function to check for unauthorized instance launches
def check_instance_launches():
    # Get the CloudTrail events for the specified time range
    response = cloudtrail_client.lookup_events(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=[{
            'AttributeKey': 'EventName',
            'AttributeValue': 'RunInstances'
        }]
    )
    events = response['Events']

    # Check each event for an unauthorized instance launch
    unauthorized_events = []
    for event in events:
        resources = event['Resources']
        for resource in resources:
            resource_type = resource['ResourceType']
            if resource_type == 'AWS::EC2::Instance':
                instance_id = resource['ResourceName']
                tags = ec2_client.describe_tags(
                    Filters=[{
                        'Name': 'resource-id',
                        'Values': [instance_id]
                    }]
                )['Tags']
                instance_name = ''
                for tag in tags:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                if not instance_name_regex.match(instance_name):
                    unauthorized_events.append(event)
                    break

    return unauthorized_events

# Define a function to remediate unauthorized instance launches
def remediate_instance_launches(events):
    # Terminate the unauthorized instances
    for event in events:
        resources = event['Resources']
        for resource in resources:
            resource_type = resource['ResourceType']
            if resource_type == 'AWS::EC2::Instance':
                instance_id = resource['ResourceName']
                ec2_client.terminate_instances(InstanceIds=[instance_id])
                print(f'Terminated unauthorized instance {instance_id}.')

# Main function
def main():
    # Check for unauthorized instance launches
    unauthorized_events = check_instance_launches()

    # Remediate unauthorized instance launches
    if unauthorized_events:
        remediate_instance_launches(unauthorized_events)
    else:
        print('No unauthorized instance launches detected.')

if __name__ == '__main__':
    main()
