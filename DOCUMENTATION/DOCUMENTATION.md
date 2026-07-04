# AI Threat Detection on AWS 

## CloudTrails Setup

1. **Search for CloudTrail on AWS Console**
   - Navigate to the AWS Management Console
   - Use the search bar to find "CloudTrail"

2. **Create a Trail**

3. **Configure Trail Settings**
   - Use the default trail name: `management-events`

4. **Complete Trail Creation**
   - Click "Create the trail" to finalize setup

---

## GuardDuty Setup

1. **Search for GuardDuty on AWS Console**
   - Navigate to the AWS Management Console
   - Use the search bar to find "GuardDuty"

2. **Select GuardDuty Features**
   - Choose the option: **Enable all GuardDuty features**

3. **Start GuardDuty**
   - Click "Get started" button

4. **Take Advantage of Free Trial**
   - GuardDuty offers a **30-day free trial**

5. **Enable GuardDuty**


---

## SNS Setup


1. **Search for SNS on AWS Console**
   - Navigate to the AWS Management Console
   - Use the search bar to find "SNS" (Simple Notification Service)

2. **Navigate to Topics**
   - In the left pane, click on **Topics**
   - Select **Create a topic**

3. **Choose Topic Type**
   - Select **Standard Type** for regular message delivery

4. **Name Your Topic**

5. **Create the Topic**
   - Keep all other settings at their default values
   - Click "Create topic" to finalize

6. **Create a Subscription**
   - Once the topic is created, click on **Create a subscription**

7. **Configure Subscription Protocol**
   - In the **Protocol** field, select **Email**

8. **Enter Your Email Address**
   - In the **Endpoint** field, enter your email address

9. **Create the Subscription**
   - Make two subscriptions - **Email** and **Phone SMS**

### Email Confirmation - Two Methods

#### Method 1: Direct Confirmation from Email
- **Check your inbox** for a confirmation email from AWS SNS
- **Open the confirmation email** and click the confirmation link
- Subscription is immediately activated

#### Method 2: Manual Confirmation via AWS Console
- If you prefer not to use the email link, use this alternative:
  1. **Copy the confirmation link** from the email you received
  2. Navigate to **Topics** in the left pane
  3. **Select your created topic**
  4. Click on your **subscription** in the subscriptions list
  5. Click on **Confirm subscription**
  6. **Paste the URL** you copied from the email
  7. Submit to confirm the subscription

**Note:** Both methods achieve the same result. Choose whichever is more convenient for you.

---

## IAM Role for Lambda Function


1. **Search for IAM in AWS Console**
   - Navigate to the AWS Management Console
   - Use the search bar to find "IAM" (Identity and Access Management)

2. **Navigate to Roles**
   - In the left pane, click on **Roles**

3. **Create a New Role**
   - Click on **Create a Role** button

4. **Select Trusted Entity Type**
   - Choose **AWS Service** as the trusted entity type

5. **Select Lambda Use Case**
   - Under "Use Case", select **Lambda**
   - Click **Next**

6. **Add Permissions**
   - Under "Add permissions", search for and select:
     - **AWSLambdaBasicExecutionRole**
   - This permission allows Lambda to write logs to CloudWatch
   - Click **Next**

7. **Name Your Role**
   - Enter a role name of your choice

8. **Create the Role**
   - Review the configuration
   - Click **Create the Role** to finalize setup

9. **Create a inline policy**
    - After Role is created, Add a inline policy in this Role
    - Paste the custom policy here:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:your-region:your-account-id:your-topic-name"
    }
  ]
}
```
    - Just change the SNS ARN in the Resource in JSON format
    - Give a policy name and Create it.


---

## AWS Lambda Setup


1. **Search for Lambda in AWS Console**
   - Navigate to the AWS Management Console
   - Use the search bar to find "Lambda"

2. **Create a Function**
   - Click on **Create a Function** button

3. **Select Authoring Model**
   - Choose **Author from scratch** option

4. **Name Your Function**

5. **Select Runtime**
   - Choose **Python 3.14** as the runtime environment
   - This is the execution environment for your function code

6. **Select Architecture**
   - Choose **x86_64** architecture

7. **Configure Permissions**
   - Under "Permissions" section, select **Use an existing role**

8. **Assign the IAM Role**
   - Search for the IAM role you created earlier
   - Select it from the dropdown list

9. **Create the Function**
   - Review all the settings
   - Click **Create Function** to finalize setup

---

## Creating the Lambda Function Code

1. **Access Your Lambda Function Code Editor**
   - Go to your Lambda function in the console
   - Navigate to the **Code** section
   - You'll see the default code in the editor

2. **Replace the Default Code**
   - Select all the default code in the editor
   - Delete it completely
   - Copy and paste the Lambda function code provided here:


```
import boto3
import os
from datetime import datetime

sns = boto3.client("sns")


def get_remediation(finding_type):
    """
    Return remediation advice based on GuardDuty finding category.
    """

    if finding_type.startswith("Recon"):
        return (
            "Investigate reconnaissance activity. Review security groups, "
            "NACLs, and restrict unnecessary open ports."
        )

    elif finding_type.startswith("UnauthorizedAccess"):
        return (
            "Check IAM credentials and login activity. Rotate keys/passwords "
            "if compromise is suspected."
        )

    elif finding_type.startswith("Trojan") or finding_type.startswith("Backdoor"):
        return (
            "Isolate the EC2 instance immediately. Inspect running processes, "
            "network connections, and scan for malware."
        )

    elif finding_type.startswith("CryptoCurrency"):
        return (
            "Investigate high CPU usage and running processes. Stop the instance "
            "if unauthorized crypto mining is detected."
        )

    elif finding_type.startswith("Impact"):
        return (
            "Investigate possible data impact or abuse. Review logs and "
            "contain affected resources."
        )

    elif finding_type.startswith("Exfiltration"):
        return (
            "Possible data exfiltration detected. Review outbound traffic and "
            "restrict suspicious connections."
        )

    else:
        return (
            "Investigate this finding in the GuardDuty console. "
            "Review IAM activity, network traffic, and resource behavior."
        )


def get_severity_label(severity):
    if severity >= 7:
        return "HIGH"
    elif severity >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def lambda_handler(event, context):
    try:
        detail = event.get("detail", {})

        finding_type = detail.get("type", "Unknown")
        description = detail.get("description", "No description available")
        region = detail.get("region", "Unknown")
        severity = detail.get("severity", 0)
        severity_label = get_severity_label(severity)

        time = detail.get("service", {}).get("eventFirstSeen", "")

        resource = detail.get("resource", {})
        instance_details = resource.get("instanceDetails", {})

        instance_id = instance_details.get("instanceId", "N/A")

        network_interfaces = instance_details.get("networkInterfaces", [])
        public_ip = (
            network_interfaces[0].get("publicIp", "N/A")
            if network_interfaces else "N/A"
        )

        profile = instance_details.get(
            "iamInstanceProfile", {}
        ).get("arn", "N/A")

        action = detail.get("service", {}).get("action", {})
        network_action = action.get("networkConnectionAction", {})

        remote_ip = network_action.get(
            "remoteIpDetails", {}
        ).get("ipAddressV4", "N/A")

        remote_port = network_action.get(
            "remotePortDetails", {}
        ).get("port", "N/A")

        formatted_time = "N/A"
        if time:
            try:
                formatted_time = datetime.strptime(
                    time, "%Y-%m-%dT%H:%M:%S.%fZ"
                ).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                formatted_time = time

        recommendation = get_remediation(finding_type)

        readable_message = f"""
GuardDuty Security Alert

- Severity: {severity_label} (Score: {severity})
- Type: {finding_type}
- Description: {description}

- Instance ID: {instance_id}
- Instance Profile: {profile}
- Public IP: {public_ip}
- Remote IP: {remote_ip}:{remote_port}
- Region: {region}
- Time: {formatted_time} UTC

- Recommended Action:
{recommendation}

📘 GuardDuty Findings Guide:
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html
"""

        sns.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Subject=f"{severity_label} GuardDuty Alert - {finding_type}",
            Message=readable_message,
        )

        return {
            "statusCode": 200,
            "body": f"Alert sent successfully for {finding_type}"
        }

    except Exception as e:
        print("Error:", str(e))
        return {
            "statusCode": 500,
            "body": f"Error processing event: {str(e)}"
        }

```


3. **Deploy the Function**
   - Click the **Deploy** button located at the top-right corner of the code editor
   - Wait for the deployment to complete
   - You should see a **success message** confirming the deployment

---

## Lambda Configuration Setup

1. **Access Lambda Configuration Section**
   - Go to your Lambda function in the AWS console
   - Click on the **Configuration** tab at the top

2. **Navigate to Environment Variables**
   - In the left sidebar under Configuration, click on **Environment Variables**
   - Click the **Edit** button

3. **Add Environment Variable - Key**
   - Click **Add environment variable** button
   - For **Key**, enter: `SNS_TOPIC_ARN`

4. **Add Environment Variable - Value**
   - For **Value**, you need to get your SNS Topic ARN:
     - Open AWS SNS service in a new tab
     - Go to **Topics**
     - Select your SNS topic that you created earlier
     - Copy the **ARN** (Amazon Resource Name) from the topic details
     - Return to Lambda and paste the ARN in the **Value** field

5. **Save the Configuration**
   - Click **Save** button
 
---

## Amazon EventBridge Setup

1. **Search for EventBridge in AWS Console**
   - Navigate to the AWS Management Console
   - Use the search bar to find "EventBridge"

2. **Open Rules**
   - In the left pane, click **Rules**

3. **Create a Rule**
   - Click **Create rule**

4. **Disable Visual Editor (optional)**
   - If a visual editor appears at the top, disable/turn off the visual opt-in to use the JSON editor

5. **Name the Rule**
   - Give the rule a descriptive name

6. **Event Source**
   - For **Event source**, choose **Other**

7. **Event Pattern**
   - Select **Custom event pattern** and paste the following JSON:

```
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"]
}
```

8. **Next**
   - Click **Next** to continue

9. **Configure Target**
   - For **Target 1**, set **Target** to **Lambda function**
   - Select the Lambda function you created earlier from the dropdown

10. **Finish**
   - Click **Next**, review the settings, then **Create rule** to enable the rule

---

## Testing Phase

1. Install AWS CLI on your PC
2. Configure it using a user
3. Create a user in IAM AWS with Admin permissions for testing purposes
4. Configure it using command `aws configure`
5. Check whether it is configured or not using `aws configure list`
6. Give following command one or two to check your system

### Trojan / Malware Activity
```
aws guardduty create-sample-findings --detector-id <Your Detector ID> --finding-types "Trojan:EC2/BlackholeTraffic"
```

🔎 2️⃣ Recon / Port Scan
```
aws guardduty create-sample-findings --detector-id <Your Detector ID> --finding-types "Recon:EC2/Portscan"
```

🔐 3️⃣ Unauthorized Access (Tor Client)
```
aws guardduty create-sample-findings --detector-id <Your Detector ID> --finding-types "UnauthorizedAccess:EC2/TorClient"
```

💰 4️⃣ Cryptocurrency Mining
```
aws guardduty create-sample-findings --detector-id <Your Detector ID> --finding-types "CryptoCurrency:EC2/BitcoinTool.B"
```

🚨 5️⃣ Backdoor / Command & Control
```
aws guardduty create-sample-findings --detector-id <Your Detector ID> --finding-types "Backdoor:EC2/C&CActivity.B"
```

⚡ BONUS — Test Multiple Threats at Once (FAST)

Windows CMD version:
```
aws guardduty create-sample-findings --detector-id <Your Detector ID> --finding-types "Recon:EC2/Portscan" "Trojan:EC2/BlackholeTraffic" "UnauthorizedAccess:EC2/TorClient"
```

And check on your GuardDuty console and Email and SMS whether it is received or not

