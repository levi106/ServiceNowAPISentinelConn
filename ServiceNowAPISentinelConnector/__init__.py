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
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError
from .state_manager import StateManager
from typing import Any, Tuple, List


log_type = 'ServiceNow'
offset_limit = 1000
connection_string = os.environ['AzureWebJobsStorage']

########## LogAnalytics 設定 ##########
# Ingestion endpoint of the Data Collection Endpoint object
dce_endpoint = os.environ['DCEndpoint']
# ImmutableId property of the Data Collection Rule
dcr_immutableid = os.environ['DCRImmutableID']
# インジェストを行う際の資格情報は azure.identity.DefaultAzureCredential によって取得されます
# https://learn.microsoft.com/ja-jp/python/api/azure-identity/azure.identity.defaultazurecredential?view=azure-python
# https://learn.microsoft.com/ja-jp/azure/developer/python/sdk/authentication-overview#use-defaultazurecredential-in-an-application
# マネージド ID を使用する場合は特に設定は不要です
# サービス プリンシパルを使用する場合は次のドキュメントに記載の環境変数の設定が必要です
# https://learn.microsoft.com/ja-jp/python/api/azure-identity/azure.identity.environmentcredential?view=azure-python

########## ServiceNow API 設定 ##########
servicenow_uri = os.environ['ServiceNowUri']
# 認証方式 (必須)
# basic ... Basic 認証
# jwt ... OAuth JWT API endpoint
# password ... OAuth API endpoint (Resource owner password credentials)
# refresh_token ... OAuth API endpoint (Refresh Token)
auth_type = os.environ['ServiceNowAuthType']
# 認証ユーザー名
# basic, password で使用
servicenow_user = os.getenv('ServiceNowUser')
# 認証ユーザーパスワード
# basic, password で使用
servicenow_password = os.getenv('ServiceNowPassword')
# 秘密鍵
# jwt で使用
private_key = os.getenv('ServiceNowPrivateKey')
# 秘密鍵のパスフレーズ
# jwt で使用
passphrase = os.getenv('ServiceNowPassphrase')
# JWT に含めるユーザー名
# jwt で使用
jwt_subject = os.getenv('ServiceNowSubClaim')
# キー ID
# jwt で使用
jwt_keyid = os.getenv('ServiceNowKeyID')
# ハッシュアルゴリズム
# jwt で使用
jwt_algorithm = os.getenv('ServiceNowAlgorithm', 'RS256')
# リフレッシュトークン
# refresh_token で使用
refresh_token = os.getenv('ServiceNowRefreshToken')
# Client ID
# jwt, password, refresh_token で使用
client_id = os.getenv('ServiceNowClientID')
# Client Secret
# jwt, password, refresh_token で使用
client_secret = os.getenv('ServiceNowClientSecret')
# 認証 URL
# basic, jwt, password, refresh_token で使用
authentication_url = os.getenv('ServiceNowAuthenticationUrl', '')
# 取得対象のテーブル
table_name = os.environ['ServiceNowTableName']
# ログのサイズが大きい場合に分割するパーティション数
number_of_partitions = int(os.getenv('NumberOfPartitions', '5'))

def process_events(client: LogsIngestionClient, table_name: str, events_obj: List[Any]) -> None:
    # ServiceNow から取得したデータを加工して Log Analytics へ送信したい場合は、ここで変換を行う
    # 例: 全ての ServiceNow のテーブルを共通の Log Analytics のテーブルに格納する場合に、
    #     table_name のようなフィールドを追加する
    # for i in range(len(events_obj)):
    #     events_obj[i]["table_name"] = table_name
    element_count = len(events_obj)
    global global_element_count, oldest, latest
    if element_count > 0:
        result = post_data(client, table_name, events_obj)
        if result:
            global_element_count = global_element_count + element_count


# Log Analytics ワークスペースへログを送信
def post_data(client: LogsIngestionClient, table_name: str, body: List[Any]) -> bool:
    stream_name = "Custom-" + table_name
    try:
        client.upload(rule_id=dcr_immutableid, stream_name=stream_name, logs=body)
        return True
    except HttpResponseError as e:
        logging.error(f"Upload failed: {e}")
        return False


def get_basic_auth_header(user: str, password: str) -> str:
    return 'Basic ' + str(base64.b64encode((user + ':' + password).encode("utf-8")), "utf-8")


def load_private_key() -> Any:
    key = load_pem_private_key(
        data = private_key.encode('utf8'),
        password = passphrase.encode('utf8'),
        backend = default_backend()
    )
    return key


def create_claims() -> str:
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


def get_access_token() -> str:
    logging.info("Start requesting an access token.")
    token = None
    try:
        params = {
            'client_id': client_id,
            'client_secret': client_secret
        }

        if auth_type == 'jwt':
            assertion = create_claims()
            # logging.info(assertion)
            params['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
            params['assertion'] = assertion
        elif auth_type == 'password':
            params['grant_type'] = 'password'
            params['username'] = servicenow_user
            params['password'] = servicenow_password
        elif auth_type == 'refresh_token':
            params['grant_type'] = 'refresh_token'
            params['refresh_token'] = refresh_token

        r = requests.post(authentication_url, params)
        if r.status_code ==200:
            if "access_token" in r.json():
                # アプリケーション登録時に指定した Access Token Lifespan よりも
                # 全てのデータ取得に時間がかかるようであれば、
                # expires_in の値も取得してトークンが切れていないかの確認と
                # 再取得の実装を検討する必要があります。
                token = r.json()["access_token"]
                logging.info("Succeeded to get access token")
            else:
                logging.info("Access token not found.")
        else:
            logging.error("Something wrong. Error code: {}".format(r.status_code))
            logging.error("{}".format(r.content.decode('utf8')))
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
        raise
    return token


def get_oauth_header() -> str:
    global token_cache
    if token_cache == None:
        token_cache = get_access_token()
        if token_cache == None:
            return None
    # logging.info(token_cache)
    return 'Bearer ' + token_cache


def get_result_request(client: LogsIngestionClient, table_name: str, params: Any) -> int:
    count = 0
    try:
        logging.info('Auth Type: {}'.format(auth_type))
        url = servicenow_uri + table_name
        if auth_type == 'basic':
            auth_header = get_basic_auth_header(servicenow_user, servicenow_password)
        else:
            auth_header = get_oauth_header()
        if auth_header == None:
            logging.error("Failed to get auth token")
            return 0
        r = requests.get(url=url,
                         headers={'Accept': 'application/json',
                                  "Authorization": auth_header
                                  },
                         params=params)
        if r.status_code == 200:
            Max_Data_Size = 1024 * 1024; # 1MB
            if "result" in r.json():
                result = r.json()["result"]
                count = len(result)
                if count > 0:
                    s = len(r.text)
                    if s > Max_Data_Size:
                        m = (count + number_of_partitions - 1) // number_of_partitions
                        for i in range(0, number_of_partitions):
                            logging.info("Processing {}/{}  (total {} events, total size: {})".format(i, number_of_partitions, count, s))
                            process_events(client, table_name, result[i * m: (i + 1) *m])
                    else:
                        logging.info("Processing {} events".format(count))
                        process_events(client, table_name, result)
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
        raise
    return count


def generate_query(oldest: str, latest: str) -> str:
    strOldest = datetime.datetime.fromtimestamp(int(oldest)).strftime("%Y-%m-%d %H:%M:%S")
    strLatest = datetime.datetime.fromtimestamp(int(latest)).strftime("%Y-%m-%d %H:%M:%S")
    return 'sys_created_onBETWEEN{}@{}'.format(strOldest, strLatest)


def process_table(client: LogsIngestionClient, table_name: str, oldest: str, latest: str) -> None:
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
        count = get_result_request(client, table_name, params)
        # エラー発生時や全件取得した時には 0 が返るのでループを抜ける
        offset += offset_limit
        # break # 動作検証のために、1 回だけ (offset_limit 件だけ) データを取得する場合はここで break

    logging.info("Processed {} events to Azure Sentinel. Table: {}, Time period: from {} to {}.".format(global_element_count, table_name, datetime.datetime.fromtimestamp(int(oldest)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                                                      datetime.datetime.fromtimestamp(int(latest)).strftime("%Y-%m-%dT%H:%M:%SZ")))

# これはいつからいつまでのデータを取得するか指定するための、開始時刻、終了時刻を返す関数です
def generate_date() -> Tuple[str, str]:
    # 現在時刻
    current_time = datetime.datetime.utcnow().replace(second=0, microsecond=0) - datetime.timedelta(minutes=10)
    # ストレージ アカウントに保存された前回実行時の現在時刻を取得
    state = StateManager(connection_string=connection_string)
    past_time = state.get()
    if past_time is not None:
        logging.info("The last time point is: {}".format(past_time))
        past_time = int((datetime.datetime.fromtimestamp(int(past_time)) + datetime.timedelta(seconds=1)).timestamp())
    else:
        # 初回実行時はストレージ アカウントに情報が無いので 1 時間前からのデータを取得する
        logging.info("There is no last time point, trying to get events for last hour.")
        past_time = int((current_time - datetime.timedelta(minutes=60)).timestamp())
    # 現在時刻でストレージ アカウント上の状態を更新
    state.post(str(int(current_time.timestamp())))
    return (past_time, int(current_time.timestamp()))


def main(mytimer: func.TimerRequest)  -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.info('Starting program')
    global global_element_count
    global_element_count = 0
    oldest, latest = generate_date()
    global token_cache
    token_cache = None
    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=dce_endpoint, credential=credential, logging_enable=True)

    process_table(client, table_name, oldest, latest)