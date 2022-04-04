from http import client
import json
import datetime
import base64
import hmac
import hashlib
import os
import logging
import re
import requests
import secrets
import time
import jwt
import azure.functions as func
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from .state_manager import StateManager

customer_id = os.environ['WorkspaceID']
shared_key = os.environ['WorkspaceKey']
logAnalyticsUri = os.environ.get('logAnalyticsUri')
log_type = 'ServiceNow'
servicenow_uri = os.environ['ServiceNowUri']
# servicenow_user = os.environ['ServiceNowUser']
# servicenow_password = os.environ['ServiceNowPassword']
offset_limit = 1000
connection_string = os.environ['AzureWebJobsStorage']
private_key = os.environ['ServiceNowPrivateKey']
passphrase = os.environ['ServiceNowPassphrase']
client_id = os.environ['ServiceNowClientID']
client_secret = os.environ['ServiceNowClientSecret']
jwt_subject = os.environ['ServiceNowSubClaim']
jwt_keyid = os.environ['ServiceNowKeyID']
jwt_algorithm = os.getenv('ServiceNowAlgorithm', 'RS256')
authentication_url = os.environ['ServiceNowAuthenticationUrl']

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):
    logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'

pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
match = re.match(pattern,str(logAnalyticsUri))
if(not match):
    raise Exception("Invalid Log Analytics Uri.")


def process_events(table_name, events_obj):
    # ServiceNow から取得したデータを加工して Log Analytics へ送信したい場合は、ここで変換を行う
    # 例: 全ての ServiceNow のテーブルを共通の Log Analytics のテーブルに格納する場合に、
    #     table_name のようなフィールドを追加する
    # for i in range(len(events_obj)):
    #     events_obj[i]["table_name"] = table_name
    element_count = len(events_obj)
    global global_element_count, oldest, latest
    if element_count > 0:
        post_status_code = post_data(table_name, json.dumps(events_obj))
        if post_status_code is not None:
            global_element_count = global_element_count + element_count


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization


# Log Analytics ワークスペースへログを送信
def post_data(table_name, body):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = logAnalyticsUri + resource + '?api-version=2016-04-01'
    # ServiceNow のテーブル毎に Log Analytics の異なるテーブルに格納したい場合は、
    # log_type の値をテーブル毎に変更する必要あり
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type + '_' + table_name, # この実装例では ServiceNow_<テーブル名> という名前の Log Analytics テーブルに格納しています
        'x-ms-date': rfc1123date
    }
    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        return response.status_code
    else:
        logging.warn("Events are not processed into Azure. Response code: {}".format(response.status_code))
        return None

def get_basic_auth_header(user, password):
    return 'Basic ' + str(base64.b64encode((user + ':' + password).encode("utf-8")), "utf-8")


def load_private_key():
    key = load_pem_private_key(
        data = private_key.encode('utf8'),
        password = passphrase.encode('utf8'),
        backend = default_backend()
    )
    return key

def create_claims():
    exp = round(time.time()) + 45
    claims = {
        'sub': jwt_subject,
        'aud': client_id,
        'iss': client_id,
        'jti': secrets.token_hex(64),
        'exp': exp
    }
    assertion = jwt.encode(claims,
        load_private_key(),
        algorithm=jwt_algorithm,
        headers = {
            'kid': jwt_keyid
        })

    return assertion


def get_access_token():
    logging.info("Start requesting an access token.")
    token = None
    try:
        assertion = create_claims()
        # logging.info(assertion)

        params = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion
        }
        r = requests.post(authentication_url, params)
        if r.status_code ==200:
            if "access_token" in r.json():
                # アプリケーション登録時に指定した Access Token Lifespan よりも
                # 全てのデータ取得に時間がかかるようであれば、
                # expires_in の値も取得してトークンが切れていないかの確認と
                # 再取得の実装を検討する必要があります。
                token = r.json()["access_token"]
            else:
                logging.info("Access token not found.")
        else:
            logging.error("Something wrong. Error code: {}".format(r.status_code))
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return token


def get_oauth_header():
    global token_cache
    if token_cache == None:
        token_cache = get_access_token()
        if token_cache == None:
            return None
    # logging.info(token_cache)
    return 'Bearer ' + token_cache


def get_result_request(table_name, params):
    count = 0
    try:
        url = servicenow_uri + table_name
        # basic_auth_header = get_basic_auth_header(servicenow_user, servicenow_password)
        oauth_header = get_oauth_header()
        if oauth_header == None:
            logging.error("Failed to get OAuth token")
            return 0
        r = requests.get(url=url,
                         headers={'Accept': 'application/json',
                                  "Authorization": oauth_header
                                  },
                         params=params)
        if r.status_code == 200:
            if "result" in r.json():
                result = r.json()["result"]
                count = len(result)
                if count > 0:
                    logging.info("Processing {} events".format(count))
                    process_events(table_name, result)
            else:
                logging.info("There are no entries from the output.")
        elif r.status_code == 401:
            logging.error("The authentication credentials are incorrect or missing. Error code: {}".format(r.status_code))
        elif r.status_code == 403:
            logging.error("The user does not have the required permissions. Error code: {}".format(r.status_code))
        else:
            logging.error("Something wrong. Error code: {}".format(r.status_code))
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return count


def generate_query(oldest, latest):
    strOldest = datetime.datetime.fromtimestamp(int(oldest)).strftime("%Y-%m-%d %H:%M:%S")
    strLatest = datetime.datetime.fromtimestamp(int(latest)).strftime("%Y-%m-%d %H:%M:%S")
    return 'sys_created_onBETWEEN{}@{}'.format(strOldest, strLatest)

def process_table(table_name, oldest, latest):
    logging.info("Start processing events to Azure Sentinel. Table: {}, Time period: from {} to {}.".format(table_name, datetime.datetime.fromtimestamp(int(oldest)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                                                      datetime.datetime.fromtimestamp(int(latest)).strftime("%Y-%m-%dT%H:%M:%SZ")))

    # 1 度に全件取得せずに、offset_limit 件毎にわけてデータを取得
    offset = 0
    count = offset_limit
    query = generate_query(oldest, latest)
    logging.info("sysparm_query: {}".format(query))
    while count > 0:
        params = {
            "sysparm_limit": offset_limit,
            "sysparm_offset": offset,
            "sysparm_query": query  # 取得するデータの時間範囲を指定
        }
        count = get_result_request(table_name, params)
        # エラー発生時や全件取得した時には 0 が返るのでループを抜ける
        offset += offset_limit
        # break # 動作検証のために、1 回だけ (offset_limit 件だけ) データを取得する場合はここで break

    logging.info("Processed {} events to Azure Sentinel. Table: {}, Time period: from {} to {}.".format(global_element_count, table_name, datetime.datetime.fromtimestamp(int(oldest)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                                                      datetime.datetime.fromtimestamp(int(latest)).strftime("%Y-%m-%dT%H:%M:%SZ")))

# これはいつからいつまでのデータを取得するか指定するための、開始時刻、終了時刻を返す関数です
def generate_date():
    # 現在時刻
    current_time = datetime.datetime.utcnow().replace(second=0, microsecond=0) - datetime.timedelta(minutes=10)
    # ストレージ アカウントに保存された前回実行時の現在時刻を取得
    state = StateManager(connection_string=connection_string)
    past_time = state.get()
    if past_time is not None:
        logging.info("The last time point is: {}".format(past_time))
    else:
        # 初回実行時はストレージ アカウントに情報が無いので 1 時間前からのデータを取得する
        logging.info("There is no last time point, trying to get events for last hour.")
        past_time = (current_time - datetime.timedelta(minutes=60)).strftime("%s")
    # 現在時刻でストレージ アカウント上の状態を更新
    state.post(current_time.strftime("%s"))
    return (past_time, current_time.strftime("%s"))


def main(mytimer: func.TimerRequest)  -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.info('Starting program')
    global global_element_count
    global_element_count = 0
    oldest, latest = generate_date()
    global token_cache
    token_cache = None

    # 取得する ServiceNow のテーブルが 3 つあるので、それぞれのテーブルに対して処理
    for table_name in ["sysevent", "syslog", "syslog_transaction"]:
        process_table(table_name, oldest, latest)