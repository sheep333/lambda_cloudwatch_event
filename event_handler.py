import base64
import json
import gzip
import datetime
import boto3
import re
import logging
from os import getenv

from redminelib import Redmine

sns = boto3.client('sns')
cw_logs = boto3.client('logs')
redmine = Redmine(getenv("URL"), key=getenv("KEY"))
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

RE_TEXT = r"""
  ^(?P<type>[^ ]*)\u0020
  (?P<time>[^ ]*)\u0020
  (?P<elb>[^ ]*)\u0020
  (?P<client_ip>[^ ]*):(?P<client_port>[0-9]*)\u0020
  (?P<target_ip>[^ ]*)[:-](?P<target_port>[0-9]*)\u0020
  (?P<request_processing_time>[-.0-9]*)\u0020
  (?P<target_processing_time>[-.0-9]*)\u0020
  (?P<response_processing_time>[-.0-9]*)\u0020
  (?P<elb_status_code>|[-0-9]*)\u0020
  (?P<target_status_code>-|[-0-9]*)\u0020
  (?P<received_bytes>[-0-9]*)\u0020
  (?P<sent_bytes>[-0-9]*)\u0020
  \"(?P<request_method>[^ ]*)\u0020
  (?P<request_url>[^ ]*)\u0020
  (?P<request_http_version>- |[^ ]*)\"\u0020
  \"(?P<user_agent>[^\"]*)\"\u0020
  (?P<ssl_cipher>[A-Z0-9-]+)\u0020
  (?P<ssl_protocol>[A-Za-z0-9.-]*)\u0020
  (?P<target_group_arn>[^ ]*)\u0020
  \"(?P<trace_id>[^\"]*)\"\u0020
  \"(?P<domain_name>[^\"]*)\"\u0020
  \"(?P<chosen_cert_arn>[^\"]*)\"\u0020
  (?P<matched_rule_priority>[-.0-9]*)\u0020
  (?P<request_creation_time>[^ ]*)\u0020
  \"(?P<actions_executed>[^\"]*)\"\u0020
  \"(?P<redirect_url>[^\"]*)\"\u0020
  \"(?P<error_reason>[^\"]*)\"
  (?P<new_field>.*)
  """
RE_FORMAT = re.compile(RE_TEXT, flags=re.VERBOSE)
ACCESS_LOG_GROUP = '/app/nginx/access_log'
APP_LOG_GROUP = '/app/php/error_log'
SNS_ARN = 'arn:aws:sns:ap-northeast-1:111111111111:***********'


def lambda_handler(event, context):
    # CloudWatchのログを整形
    compressed_payload = base64.b64decode(event['awslogs']['data'])
    uncompressed_payload = gzip.decompress(compressed_payload)
    payload = json.loads(uncompressed_payload)

    for log_event in payload['logEvents']:
        # logイベント前の1分間に他の5XXエラーがないかを確認
        response = cw_logs.filter_log_events(
            logGroupName=ACCESS_LOG_GROUP,
            logStreamName=log_event['logStream'],
            startFromHead=True,
            startTime=log_event['timestamp'] - 60,
            endTime=log_event['timestamp'],
            filter_pattern="[ip, id, user, timestamp, request, status_code=5*, size]"
        )
        # 5XXエラーごとにアプリログの取得とRedmine/SNSへの通知を行う
        for error_log in response['events']:
            logger.info(f"Get Error Log: {error_log['eventID']}")
            formatted_error = RE_FORMAT.match(error_log['message']).groupdict()
            app_log = get_application_log(formatted_error)
            issue = create_redmine_ticket(error_log, app_log)
            logger.info(f"Create Redmine Issue:{issue['id']}")
            send_sns_message(formatted_error)


def create_redmine_ticket(error_log, app_log):
    issue = redmine.issue.create(
        project_id=getenv("PROJECT_ID"),
        subject='5XX Error',
        description=f'### error_log    ```{error_log}```    ### app_log    ```{app_log}```',
        assigned_to_id=getenv("ASSIGNEE_ID"),
        tracker_id=getenv("TRACKER_ID")
    )
    return issue


def get_application_log(formatted_error):
    response = cw_logs.filter_log_events(
        logGroupName=APP_LOG_GROUP,
        logStreamName=formatted_error['logStream'],
        startFromHead=True,
        startTime=formatted_error['timestamp'] - 60,
        endTime=formatted_error['timestamp'] + 60
    )
    return response


def send_sns_message(formatted_error):
    # SNSに送るデータの作成
    date = datetime.datetime.fromtimestamp(int(str(formatted_error["timestamp"])[:10])) + datetime.timedelta(hours=9)
    sns_body = {}
    sns_body["default"] = ""
    sns_body["default"] += "LogStream : " + formatted_error["logStreamName"] + "\n"
    sns_body["default"] += "Time : " + date.strftime('%Y-%m-%d %H:%M:%S') + "\n"
    sns_body["default"] += "EventID : " + formatted_error['eventId'] + "\n"
    sns_body["default"] += "Message : " + formatted_error['message'] + "\n"

    topic = SNS_ARN
    subject = "5XX ERROR OCCURED!!"
    sns.publish(
        TopicArn=topic,
        Message=json.dumps(sns_body, ensure_ascii=False),
        Subject=subject,
        MessageStructure='json'
    )
    return
