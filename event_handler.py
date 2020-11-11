import json
import datetime
import boto3
import logging
from os import getenv

from redminelib import Redmine
from slack.errors import SlackApiError
from slack.web.client import WebClient

ACCESS_LOG_GROUP = '/app/nginx/access_log'
APP_LOG_GROUP = '/app/php/error_log'
SNS_ARN = 'arn:aws:sns:ap-northeast-1:111111111111:***********'
SLACK_TOKEN = os.environ.get("SLACK_TOKEN")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")
REDMINE_URL = getenv("REDMINE_URL")
REDMINE_KEY = getenv("REDMINE_KEY")

sns = boto3.client('sns')
cw_logs = boto3.client('logs')
redmine = Redmine(REDMINE_URL, key=REDMINE_KEY)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
slack = WebClient(token=SLACK_TOKEN)


def lambda_handler(event, context):
    logger.info(f"Get Error Log: {event['detail']}")
    error_log = event["detail"]["message"]
    response = get_application_log(event)
    app_log = ''
    for res in response:
        app_log += f"{res['logEvents']['message']}\n\n"
    issue = create_redmine_ticket(error_log, app_log)
    logger.info(f"Create Redmine Issue:{issue['id']}")
    redmine_blocks = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"Redmineのチケットリンク: {REDMINE_URL}/issues/{issue.id}"
        }
    }
    res = post_slack(error_log)


def create_redmine_ticket(error_log, app_log):
    issue = redmine.issue.create(
        project_id=getenv("PROJECT_ID"),
        subject='5XX Error',
        description=f'### error_log    ```{error_log}```    ### app_log    ```{app_log}```',
        assigned_to_id=getenv("ASSIGNEE_ID"),
        tracker_id=getenv("TRACKER_ID")
    )
    return issue


def get_application_log(event):
    log_streams = cw_logs.describe_log_streams(
        logGroupName=ACCESS_LOG_GROUP
    )
    event_time = event['detail']['Date']
    check_logstreams = []
    for log_stream in log_streams:
        if log_stream['firstEventTimestamp'] < event_time \
                and log_stream['lastEventTimestamp'] >　event_time:
            check_logstreams.append(log_stream)
    for logstream in check_logstreams:
        response = cw_logs.filter_log_events(
            logGroupName=APP_LOG_GROUP,
            logStreamName=logstream['logStreamName'],
            startFromHead=True,
            startTime=event_time - 60,
            endTime=event_time + 60
        )
    return response


def post_slack(message, extra_blocks=[]):
    title = "Cloud Watch Event!!"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": message
            }
        }
    ]

    if extra_blocks:
        blocks += extra_blocks

    payload = {
        "blocks": blocks,
        "ts": int(timestamp.timestamp())
    }

    try:
        slack.chat_postMessage(channel=SLACK_CHANNEL, **payload)
    except SlackApiError as e:
        logger.debug(f"payload: {payload}")
        logger.debug("response: ", e.response.data)
        logger.error(f"Failed to post message to slack: {e}")
        raise e
