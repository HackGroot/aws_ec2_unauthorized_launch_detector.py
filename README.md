# aws_ec2_unauthorized_launch_detector.py
Detect and remediate unauthorized EC2 launches in AWS.


AWS EC2 Unauthorized Launch Detector

The "aws_ec2_unauthorized_launch_detector.py" script detects and remediates unauthorized EC2 instance launches in AWS. This can help improve the security of AWS accounts by preventing unauthorized instances from being launched.
Prerequisites

Before running the script, you will need to have:

    An AWS account with CloudTrail and EC2 access
    Python 3 installed
    The Boto3 Python library installed

Installation

    Clone the repository:

bash

git clone https://github.com/yourusername/aws-ec2-unauthorized-launch-detector.git

    Install the required Python packages:

pip install boto3

Usage

To use the script, run it with the following command:

python aws_ec2_unauthorized_launch_detector.py

The script will search the CloudTrail logs for "RunInstances" events within the last 24 hours and check the instance name for a valid format. If an unauthorized instance launch is detected, the script will terminate the instance.

You can schedule the script to run at regular intervals using a cron job or an AWS Lambda function.
Security Considerations

    Be sure to store your AWS credentials securely, such as in environment variables or an AWS profile.
    Use IAM policies to restrict access to CloudTrail and EC2 resources.
    Monitor IAM activity and set up alerts for suspicious activity.

Contributing

Contributions to this project are welcome! If you find a bug or have an idea for a new feature, please open an issue or submit a pull request.
