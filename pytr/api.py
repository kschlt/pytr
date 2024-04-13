# MIT License

# Copyright (c) 2020 nborrmann

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import base64
import hashlib
import json
import pathlib
import time
import urllib.parse
import uuid
import certifi
import ssl
import requests
import websockets
from ecdsa import NIST256p, SigningKey
from ecdsa.util import sigencode_der
from http.cookiejar import MozillaCookieJar

from pytr.utils import get_logger


home = pathlib.Path.home()
BASE_DIR = home / '.pytr'
CREDENTIALS_FILE = BASE_DIR / 'credentials'
KEY_FILE = BASE_DIR / 'keyfile.pem'
COOKIES_FILE = BASE_DIR / 'cookies.txt'


class TradeRepublicApi:
    _default_headers = {'User-Agent': 'TradeRepublic/Android 30/App Version 1.1.5534'}
    _default_headers_web = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36'
    }
    _host = 'https://api.traderepublic.com'
    _weblogin = False

    _refresh_token = None
    _session_token = None
    _session_token_expires_at = None
    _process_id = None
    _web_session_token_expires_at = 0

    _ws = None
    _lock = asyncio.Lock()
    _subscription_id_counter = 1
    _previous_responses = {}
    subscriptions = {}

    _credentials_file = CREDENTIALS_FILE
    _cookies_file = COOKIES_FILE

    @property
    def session_token(self):
        if not self._refresh_token:
            self.login()
        elif self._refresh_token and time.time() > self._session_token_expires_at:
            self.refresh_access_token()
        return self._session_token

    @session_token.setter
    def session_token(self, val):
        self._session_token_expires_at = time.time() + 290
        self._session_token = val

    def __init__(self, phone_no=None, pin=None, keyfile=None, locale='de', save_cookies=False, credentials_file = None, cookies_file = None):
        self.log = get_logger(__name__)
        self._locale = locale
        self._save_cookies = save_cookies

        self._credentials_file = pathlib.Path(credentials_file) if credentials_file else CREDENTIALS_FILE
        self._cookies_file = pathlib.Path(cookies_file) if cookies_file else COOKIES_FILE

        if not (phone_no and pin):
            try:
                with open(self._credentials_file, 'r') as f:
                    lines = f.readlines()
                self.phone_no = lines[0].strip()
                self.pin = lines[1].strip()
            except FileNotFoundError:
                raise ValueError(f'phone_no and pin must be specified explicitly or via {self._credentials_file}')
        else:
            self.phone_no = phone_no
            self.pin = pin



        self.keyfile = keyfile if keyfile else KEY_FILE
        try:
            with open(self.keyfile, 'rb') as f:
                self.sk = SigningKey.from_pem(f.read(), hashfunc=hashlib.sha512)
        except FileNotFoundError:
            pass

        self._websession = requests.Session()
        self._websession.headers = self._default_headers_web
        if self._save_cookies:
            self._websession.cookies = MozillaCookieJar(self._cookies_file)

    def initiate_device_reset(self):
        self.sk = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha512)

        r = requests.post(
            f'{self._host}/api/v1/auth/account/reset/device',
            json={'phoneNumber': self.phone_no, 'pin': self.pin},
            headers=self._default_headers,
        )

        self._process_id = r.json()['processId']

    def complete_device_reset(self, token):
        if not self._process_id and not self.sk:
            raise ValueError('Initiate Device Reset first.')

        pubkey_bytes = self.sk.get_verifying_key().to_string('uncompressed')
        pubkey_string = base64.b64encode(pubkey_bytes).decode('ascii')

        r = requests.post(
            f'{self._host}/api/v1/auth/account/reset/device/{self._process_id}/key',
            json={'code': token, 'deviceKey': pubkey_string},
            headers=self._default_headers,
        )
        if r.status_code == 200:
            with open(self.keyfile, 'wb') as f:
                f.write(self.sk.to_pem())

    def login(self):
        self.log.info('Logging in')
        r = self._sign_request(
            '/api/v1/auth/login',
            payload={'phoneNumber': self.phone_no, 'pin': self.pin},
        )
        self._refresh_token = r.json()['refreshToken']
        self.session_token = r.json()['sessionToken']

    def refresh_access_token(self):
        self.log.info('Refreshing access token')
        r = self._sign_request('/api/v1/auth/session', method='GET')
        self.session_token = r.json()['sessionToken']
        self.save_websession()

    def _sign_request(self, url_path, payload=None, method='POST'):
        ts = int(time.time() * 1000)
        payload_string = json.dumps(payload) if payload else ''
        signature_payload = f'{ts}.{payload_string}'
        signature = self.sk.sign(
            bytes(signature_payload, 'utf-8'),
            hashfunc=hashlib.sha512,
            sigencode=sigencode_der,
        )
        signature_string = base64.b64encode(signature).decode('ascii')

        headers = self._default_headers.copy()
        headers['X-Zeta-Timestamp'] = str(ts)
        headers['X-Zeta-Signature'] = signature_string
        headers['Content-Type'] = 'application/json'

        if url_path == '/api/v1/auth/login':
            pass
        elif url_path == '/api/v1/auth/session':
            headers['Authorization'] = f'Bearer {self._refresh_token}'
        elif self.session_token:
            headers['Authorization'] = f'Bearer {self.session_token}'

        return requests.request(
            method=method,
            url=f'{self._host}{url_path}',
            data=payload_string,
            headers=headers,
        )

    def inititate_weblogin(self):
        r = self._websession.post(
            f'{self._host}/api/v1/auth/web/login',
            json={'phoneNumber': self.phone_no, 'pin': self.pin},
        )
        j = r.json()
        try:
            self._process_id = j['processId']
        except KeyError:
            err = j.get('errors')
            if err:
                raise ValueError(str(err))
            else:
                raise ValueError('processId not in reponse')
        return int(j['countdownInSeconds']) + 1

    def resend_weblogin(self):
        r = self._websession.post(
            f'{self._host}/api/v1/auth/web/login/{self._process_id}/resend', headers=self._default_headers
        )
        r.raise_for_status()

    def complete_weblogin(self, verify_code):
        if not self._process_id and not self._websession:
            raise ValueError('Initiate web login first.')

        r = self._websession.post(f'{self._host}/api/v1/auth/web/login/{self._process_id}/{verify_code}')
        r.raise_for_status()
        self.save_websession()
        self._weblogin = True

    def save_websession(self):
        # Saves session cookies too (expirydate=0).
        if self._save_cookies:
            self._websession.cookies.save(ignore_discard=True, ignore_expires=True)

    def resume_websession(self):
        '''
        Use saved cookie file to resume web session
        return success
        '''
        if self._save_cookies is False:
            return False

        # Only attempt to load if the cookie file exists.
        if self._cookies_file.exists():
            # Loads session cookies too (expirydate=0).
            self._websession.cookies.load(ignore_discard=True, ignore_expires=True)
            self._weblogin = True
            try:
                self.settings()
            except requests.exceptions.HTTPError:
                return False
                self._weblogin = False
            else:
                return True
        return False

    def _web_request(self, url_path, payload=None, method='GET'):
        if self._web_session_token_expires_at < time.time():
            r = self._websession.get(f'{self._host}/api/v1/auth/web/session')
            r.raise_for_status()
            self._web_session_token_expires_at = time.time() + 290
        return self._websession.request(method=method, url=f'{self._host}{url_path}', data=payload)

    async def _get_ws(self):
        if self._ws and self._ws.open:
            return self._ws

        self.log.info('Connecting to websocket ...')
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        extra_headers = None
        connection_message = {'locale': self._locale}
        connect_id = 21

        if self._weblogin:
            # authenticate with cookies, set different connection message and connect ID
            cookie_str = ''
            for cookie in self._websession.cookies:
                if cookie.domain.endswith('traderepublic.com'):
                    cookie_str += f'{cookie.name}={cookie.value}; '
            extra_headers = {'Cookie': cookie_str.rstrip('; ')}

            connection_message = {
                'locale': self._locale,
                'platformId': 'webtrading',
                'platformVersion': 'chrome - 94.0.4606',
                'clientId': 'app.traderepublic.com',
                'clientVersion': '5582',
            }
            connect_id = 31

        self._ws = await websockets.connect('wss://api.traderepublic.com', ssl=ssl_context, extra_headers=extra_headers)
        await self._ws.send(f'connect {connect_id} {json.dumps(connection_message)}')
        response = await self._ws.recv()

        if not response == 'connected':
            raise ValueError(f'Connection Error: {response}')

        self.log.info('Connected to websocket ...')

        return self._ws


    async def timeline(self, after=None):
        return await self.subscribe({'type': 'timeline', 'after': after})

    async def timeline_detail(self, timeline_id):
        return await self.subscribe({'type': 'timelineDetail', 'id': timeline_id})

    async def timeline_detail_order(self, order_id):
        return await self.subscribe({'type': 'timelineDetail', 'orderId': order_id})

    async def timeline_detail_savings_plan(self, savings_plan_id):
        return await self.subscribe({'type': 'timelineDetail', 'savingsPlanId': savings_plan_id})

    async def order_overview(self):
        return await self.subscribe({'type': 'orders'})

    async def price_for_order(self, isin, exchange, order_type):
        return await self.subscribe(
            {
                'type': 'priceForOrder',
                'parameters': {
                    'exchangeId': exchange,
                    'instrumentId': isin,
                    'type': order_type,
                },
            }
        )

class TradeRepublicError(ValueError):
    def __init__(self, subscription_id, subscription, error_message):
        self.subscription_id = subscription_id
        self.subscription = subscription
        self.error = error_message
