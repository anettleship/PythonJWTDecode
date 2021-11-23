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
from jose import jwk, jwt
from jose.utils import base64url_decode

from requests.exceptions import HTTPError

from flask import Flask
from flask import request

app = Flask(__name__)

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

from flask import request


@app.route('/', methods=['GET', 'POST'])
def hello(event, context):
    
    data = request.args
    print(f'hello worldy: {data}')

    try:

        event = {
            "lambda.event":{
                "resource":"/",
                "path":"/",
                "httpMethod":"GET",
                "queryStringParameters":{
                    "access_token":"eyJraWQiOiJrSk5vZDB2K3hLOEhWbGs3MXNcLzcxSkdCRDdrRkEzT2hrcWI3WGl5a2JMTT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkMjQxNjliYy0zMDEyLTRkN2EtYWVlYS1kNGJkODg4MmYzYWQiLCJldmVudF9pZCI6IjcxMjZiZGE4LWRlY2ItNDU2NS1hMjMzLWFkMzc5NGRkNmRkZiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4gcGhvbmUgb3BlbmlkIHByb2ZpbGUgZW1haWwiLCJhdXRoX3RpbWUiOjE2MzM3MjU5OTYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX0FWN0ZyQXh0cyIsImV4cCI6MTYzMzcyOTU5NiwiaWF0IjoxNjMzNzI1OTk2LCJ2ZXJzaW9uIjoyLCJqdGkiOiJkZjJiMWVjMy03OGM3LTQxOTgtYmViMy03OTRkZmRhYTA4ZDAiLCJjbGllbnRfaWQiOiIxOG5lYzFmdmo3bWk1a2VjMnA0bTRsczhnIiwidXNlcm5hbWUiOiJkMjQxNjliYy0zMDEyLTRkN2EtYWVlYS1kNGJkODg4MmYzYWQifQ.o7n3AB35SfA-3syvQDDKHJu4iKPeIpH_1WU_ovyy5ajcbcA0j4XVrznRP5CH9h5wFvKalHi66bhKnKQZ5NrykKwvGSjAQsoHz3c9Meg-zMaYdHASqyIlffLoxfuiySn33II6rRMR15PsNx8zHEbHJTOWTBy30kP_N_qnwjqSlWg3TJI1PVkOOqQbtTyFV00OAdqZY8wY8v4SaSq-YSL1IPh8oAMzfmtFNP3OaV6cVC-1oPf3a9HM0pdejDBkSxylmp4CVXywG98lz1eIwZWI-AMe2Kzf-ChtdxbAgH0daOx3yrWZN7Nt21h1-W0rF1mwTEryJo1MrP_SGXKNtwnNWw",
                    "expires_in":"3600",
                    "id_token":"eyJraWQiOiJ1bk9EVERWdzdmK1lhVHJZYVF3U1RDSUZFNEZkek9ISHJVc3VUK05yRkVJPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoidFljd3lDYkhXM1FrSV9sVEhaQm9ZUSIsInN1YiI6ImQyNDE2OWJjLTMwMTItNGQ3YS1hZWVhLWQ0YmQ4ODgyZjNhZCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMV9BVjdGckF4dHMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZDI0MTY5YmMtMzAxMi00ZDdhLWFlZWEtZDRiZDg4ODJmM2FkIiwiYXVkIjoiMThuZWMxZnZqN21pNWtlYzJwNG00bHM4ZyIsImV2ZW50X2lkIjoiNzEyNmJkYTgtZGVjYi00NTY1LWEyMzMtYWQzNzk0ZGQ2ZGRmIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2MzM3MjU5OTYsImV4cCI6MTYzMzcyOTU5NiwiaWF0IjoxNjMzNzI1OTk2LCJqdGkiOiJiYmVkMzFmOS04NzZmLTQ1NDMtYTMyYy1kOThiOTI3NWRlMmIiLCJlbWFpbCI6ImEubmV0dGxlc2hpcEBnbWFpbC5jb20ifQ.YuPmfit5DYgL-nwOVjMVxspRqu9q_Lu-TNWRDK3UYdv582q-NMML9VKcCNGF55I6FvtyLB9AVXcWdjhumfpQev3jHQCSP0rC-B__vVBhcqk4Zu3xKVbgGWrqLMrZRjm6Xkh5ygfH5HR7zCaLF1ZXXVZWWFqd7heCwZcE389v-JbF1ooQxEo0NiKg2xdFCTSZDAmWAWIWQp9-l_c0sl65Dini-ucrWzEWm0LV4xaPou8jAX1HuLFJmjsN4u5exCFc7Ba3TcTZOcqzAYx9_-dy0eBGw46zfwCG7jUCF0pJaz2csGA15fkmkUJAC7inGTCkrSQXmKhUzwHqO-oo5lDIoQ",
                    "token_type":"Bearer",
                    "code": data['code']
                },
            }
        }

        context = ''

    except KeyError:
        return {
        'statusCode': 401,
        'body': data
        }

    result = lambda_handler(event, context)


    return result



def lambda_handler(event, context):
    print(f'\n\nevent received: {event}\n\n')

    try:
        code = event["lambda.event"]["queryStringParameters"]["code"]
    except KeyError:
        return {
        'statusCode': 500,
        'body': 'Malformed Event, KeyError'
        }
    except TypeError:
        return {
        'statusCode': 500,
        'body': 'Malformed Event, TypeError'
        }

    #
    #
    #
    # client_secret needs to be an environment variable!
    #
    #

    # From: https://stackoverflow.com/questions/62171090/how-programtically-exchange-the-authorization-code-to-get-the-access-token-from
    client_secret = 'r9vg7mchfj95tij0goqr5c3lu53hukb0smcmvv0eqagt2ce8gbn'
    token_url="https://adrian-flask-silence.auth.eu-west-1.amazoncognito.com/oauth2/token"
    message = bytes(f"{app_client_id}:{client_secret}",'utf-8')
    secret_hash = base64.b64encode(message).decode()
    payload = {
        "grant_type": 'authorization_code',
        "client_id": app_client_id,
        "code": code,
        "redirect_uri": 'https://nmofhrov8g.execute-api.eu-west-2.amazonaws.com/prod/'
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {secret_hash}"}
            
    resp = requests.post(token_url, params=payload, headers=headers)

    if "error" in json.loads(resp.content):
        return {
        'statusCode': 401,
        'body': 'Invalid Code Grant'
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
    return {
        'statusCode': 200,
        'body': json.dumps(claims),
        'info': 'end'
        }

        
# the following is useful to make this script executable in both
# AWS Lambda and any other local environments
#if __name__ == '__main__':
    # for testing locally you can enter the Code Grant here - it can be used once!
 #   event = {
 #       "code": "30b46528-2a09-410b-aefb-d16cbae7ed7c",
 #       }
 #   lambda_handler(event, None)

if __name__ == '__main__':
    event = {}
    context = {}
    app.run(event, context)