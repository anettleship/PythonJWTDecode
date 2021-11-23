# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
# except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.

import json
import time
import urllib.request
import requests
import base64
import boto3
import flask_login

from jose import jwk, jwt
from jose.utils import base64url_decode
from botocore.exceptions import ClientError
from requests.exceptions import HTTPError
from datetime import timedelta

from flask import Flask, request, redirect

# init login manager from flask_login
login_manager = flask_login.LoginManager()
# init app
app = Flask(__name__)

#
# This needs to be put in aws secrets manager if we were serious
#

app.secret_key = 'kjgvfkjgkhgvkjhkjhvbkljhkljhbkljhvkljvhkljvvj'
# init login manager for app
login_manager.init_app(app)
app.permanent_session_lifetime = timedelta(minutes=1)


region = 'eu-west-1'
userpool_id = 'eu-west-1_AV7FrAxts'
app_client_id = '18nec1fvj7mi5kec2p4m4ls8g'
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
  response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

# this is a flask_login class
class User(flask_login.UserMixin):
    pass

# user_loader callback for flask-login
@login_manager.user_loader
def load_user(cognito_username):
    user = User()
    user.id = cognito_username
    return user

@app.route('/', methods=['GET'])
def login():
    return redirect('https://adrian-flask-silence.auth.eu-west-1.amazoncognito.com/login?client_id=18nec1fvj7mi5kec2p4m4ls8g&response_type=code&scope=aws.cognito.signin.user.admin+email+openid+phone+profile&redirect_uri=https://lgjg6hg706.execute-api.eu-west-2.amazonaws.com/dev/authenticate')

# a simple page that says hello
@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():

    data = request.args
    print(f'hello worldy: {data}')

    try:
        code = data['code']

    except KeyError:
        return {
        'statusCode': 401,
        'body': 'code was not specified'
        }

    # From: https://stackoverflow.com/questions/62171090/how-programtically-exchange-the-authorization-code-to-get-the-access-token-from
    client_secret_aws = json.loads(get_awssecrets("pythonjwtdecode_app_client_secret"))["client_secret"]
    token_url="https://adrian-flask-silence.auth.eu-west-1.amazoncognito.com/oauth2/token"
    message = bytes(f"{app_client_id}:{client_secret_aws}",'utf-8')
    secret_hash = base64.b64encode(message).decode()
    payload = {
        "grant_type": 'authorization_code',
        "client_id": app_client_id,
        "code": code,
        # https://stackoverflow.com/questions/50264679/aws-cognito-unauthorized-client-error-when-hitting-oauth2-token
        # whatever redirect_uri I set here, it has to match *exactly* in the aws console redirect field.
        # "redirect_uri": 'https://localhost'
        "redirect_uri": 'https://lgjg6hg706.execute-api.eu-west-2.amazonaws.com/dev/authenticate'
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {secret_hash}"}
    print(f'Making request {token_url} with payload: {json.dumps(payload)} and headers: {json.dumps(headers)}')

    resp = requests.post(token_url, params=payload, headers=headers)
    resp_string = json.loads(resp.content)

    print(f'Response received: {resp_string}')

    if "error" in json.loads(resp.content):
        return {
        'statusCode': 401,
        'body': resp_string
        }

    token = json.loads(resp.content)['id_token']

    print(f'\n\ntoken received: {token}\n\n')
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return {
        'statusCode': 401,
        'body': 'Public key not found in jwks.json'
        }
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return {
        'statusCode': 401,
        'body': 'Signature verification failed'
        }
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    print(f'claims retrieved: {claims}')
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return {
        'statusCode': 401,
        'body': 'Token is expired'
        }
    else:
        print(f'Token is valid until {claims["exp"]}')
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        print('Token was not issued for this audience')
        return {
        'statusCode': 401,
        'body': 'Token was not issued for this audience'
        }
    else:
        print('App ID matches token')
    # now we can use the claims
    print(claims)

    # flask can now log in the user
    user = User()
    user.id = claims["cognito:username"]
    flask_login.login_user(user)
    return redirect('/dev/protected')


@app.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.id
   
@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'
    
def get_awssecrets(secret_name):

    # Copied straight from aws secrets manager boilerplate code.
    region_name = "eu-west-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

if __name__ == '__main__':
    app.run()