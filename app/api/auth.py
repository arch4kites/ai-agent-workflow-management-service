import base64
import binascii
import gzip
import json
import hashlib
import hmac
import os
from datetime import datetime
from typing import Optional
from fastapi.routing import Match
import httpx
import jwt
from fastapi.exceptions import HTTPException
from fastapi.security.http import HTTPBearer, HTTPBasic
from fastapi.security.oauth2 import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from jwt import PyJWKClient
from starlette.requests import Request
from starlette.status import (
    HTTP_200_OK,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

FOURKITES_APP_ID = os.environ.get("FOURKITES_APP_ID")
SHARED_APP_SECRET = os.environ.get("SHARED_APP_SECRET")
USER_SERVICE_VALIDATE_TOKEN_URL = os.environ.get("USER_SERVICE_VALIDATE_TOKEN_URL")
USER_SERVICE_LOGIN_URL = os.environ.get("USER_SERVICE_LOGIN_URL")


class FourkitesUMSStatelessAuthentication(OAuth2):
    """
    This is the JWT authentication offered by User Service.
    """

    HEADER = "FK-User"

    async def __call__(self, request: Request) -> Optional[dict]:
        token: str = request.headers.get(self.HEADER)

        if not self.get_public_key():
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Config error: JWT_PUBLIC_KEY not defined",
            )

        if not token:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": self.HEADER},
            )

        decompressed_token = self.decompress_token(token)

        if not decompressed_token:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Invalid token")

        if not self.check_token_expiration(decompressed_token):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Token is expired",
            )

        data = self.check_token_signature(decompressed_token)

        if not data:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid token signature",
            )

        return self.get_user(data)

    def decompress_token(self, compressed_token: str):
        """
        This JWT token passed through a compression process which is:
            Base64(Gzip())
        We undo this process here to access the pure JWT.
        """
        try:
            return gzip.decompress(base64.urlsafe_b64decode(compressed_token)).decode()
        except (TypeError, binascii.Error):
            return None

    def check_token_expiration(self, token: str):
        try:
            return jwt.decode(
                token,
                self.get_public_key(),
                algorithms=["RS256"],
                options={"verify_signature": False, "verify_exp": True},
            )
        except jwt.exceptions.ExpiredSignatureError:
            return False

    def check_token_signature(self, token: str):
        try:
            return jwt.decode(
                token,
                self.get_public_key(),
                algorithms=["RS256"],
                options={"verify_signature": True, "verify_exp": False},
            )
        except jwt.exceptions.InvalidSignatureError:
            return False

    def get_user(self, data: dict):
        return data

    @classmethod
    def get_public_key(cls):
        # XXX: Temporarily we are using a public key instead of JWK because we need
        # to implement a change in user-service before using it really.
        public_key = os.environ.get("JWT_PUBLIC_KEY")

        if public_key:
            try:
                return base64.urlsafe_b64decode(public_key)
            except binascii.Error:
                pass


class FourkitesUMSAuthenticationBearer(HTTPBearer):
    """
    This is the JWT authentication offered by User Service.
    """

    USER_ID_HEADER = "X-FourKitesUserId"
    DEVICE_ID_HEADER = "X-FourKitesDeviceId"

    async def validate_token(self, user_id: str, device_id: str, token: str):
        """
        Validates the user_id, device_id and token tuple in the user service,
        returning user information if it goes ok and None if not
        """
        if not USER_SERVICE_VALIDATE_TOKEN_URL:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Config error: USER_SERVICE_VALIDATE_TOKEN_URL not defined",
            )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                USER_SERVICE_VALIDATE_TOKEN_URL,
                headers={
                    self.USER_ID_HEADER: user_id,
                    self.DEVICE_ID_HEADER: device_id,
                    "Authorization": f"Bearer {token}",
                },
            )
            if response.status_code == HTTP_200_OK:
                return response.json()["user"]

    def standardize_fields(self, user):
        """
        Standardize fields to make the two auths equal in terms
        of the user data they return.
        """
        user["companyPermalink"] = user.get("companyId")
        return user

    async def __call__(self, request: Request) -> Optional[dict]:
        authorization: str = request.headers.get("Authorization")
        user_id: str = request.headers.get(self.USER_ID_HEADER)
        device_id: str = request.headers.get(self.DEVICE_ID_HEADER)
        scheme, token = get_authorization_scheme_param(authorization)

        if not (authorization and scheme and token):
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Authorization"},
            )

        if not user_id:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": self.USER_ID_HEADER},
            )

        if not device_id:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": self.DEVICE_ID_HEADER},
            )

        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid credentials - Bearer Auth Token required",
            )

        user = await self.validate_token(user_id, device_id, token)

        if not user:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid credentials - Bearer Auth Token not valid",
            )

        return self.standardize_fields(user)


class KeycloakAuthenticationJWT(OAuth2):
    """
    This is the JWT authentication offered by Keycloak using JWK to
    get public key and validate the token
    """

    HEADER = "X-FourKitesKeycloakToken"

    async def __call__(self, request: Request) -> Optional[dict]:
        token: str = request.headers.get(self.HEADER)

        if not self.get_keycloak_url():
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Config error: KEYCLOAK_URL not defined",
            )

        if not token:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": self.HEADER},
            )

        try:
            self.get_public_key(token)
        except jwt.exceptions.PyJWKClientError:
            # Unable to find a signing key that matches the kid
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid token signature",
            )

        if not self.check_token_expiration(token):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Token is expired",
            )

        data = self.check_token_signature(token)

        if not data:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid token signature",
            )

        return self.get_user(data)

    def check_token_expiration(self, token: str):
        try:
            decoded_jwt = jwt.decode(
                token,
                self.get_public_key(token),
                algorithms=["RS256"],
                options={"verify_signature": False, "verify_exp": True},
            )
            return decoded_jwt
        except jwt.exceptions.ExpiredSignatureError:
            return False

    def check_token_signature(self, token: str):
        try:
            return jwt.decode(
                token,
                self.get_public_key(token),
                algorithms=["RS256"],
                options={"verify_signature": True, "verify_exp": False},
            )
        except jwt.exceptions.InvalidSignatureError:
            return False

    def get_user(self, data: dict):
        return data

    def get_public_key(self, token):
        jwks_client = PyJWKClient(self.get_keycloak_url())
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return signing_key.key

    def get_keycloak_url(self):
        return os.environ.get("KEYCLOAK_URL")
    
class FourKitesUMSAuthenticationBasic(HTTPBasic):
    """
    This is the Basic authentication offered by User Service.
    """
    
    async def __call__(self, request: Request) -> Optional[dict]:
        authorization: str = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)
        url_path = self.get_url_path(request)
        
        if not (authorization and scheme and token):
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Authorization"},
            )

        if scheme.lower() != "basic":
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid credentials - Basic Auth Token required",
            )

        user = await self.validate_token(token, url_path)

        if not user:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid credentials - Basic Auth Token not valid",
            )

        return self.standardize_fields(user)
    
    async def validate_token(self, token: str, url_path: str):
        """
        Validates the token in the user service,
        returning user information if it goes ok and None if not
        """
        if not USER_SERVICE_LOGIN_URL:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Config error: USER_SERVICE_LOGIN_URL not defined",
            )
            
        username, password = base64.b64decode(token).decode().split(":", 2) 
        payload = json.dumps({
            "username": username,
            "password": password,
            "url_path": url_path
        })
        headers = {
            'Content-Type': 'application/json'
        }
        
        signature_info = self.generate_signature()
        signature = signature_info[0]
        timestamp = signature_info[1]
        user_service_login_url = f"{USER_SERVICE_LOGIN_URL}?app_id=contacts-service&timestamp={timestamp}&signature={signature}"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                user_service_login_url,
                headers={
                    'Content-Type': 'application/json'
                },
                data=payload
            )
            if response.status_code == HTTP_200_OK:
                return response.json()["user"]
            
    def get_url_path(self, request: Request):
        return request.url.path
    
    def standardize_fields(self, user):
        """
        Standardize fields to make the two auths equal in terms
        of the user data they return.
        """
        user["companyPermalink"] = user.get("companyId")
        return user
    
    def generate_signature(self):
        app_id = os.environ["FOURKITES_APP_ID"]
        secret = os.environ["SHARED_APP_SECRET"]
        current_time = datetime.today()
        timestamp = datetime.strftime(current_time, "%Y%m%d%H%M%S")
        base_string = f"{app_id}--{timestamp}"
        secret = secret.encode("utf-8")
        base_string = base_string.encode("utf-8")
        hashed = hmac.new(secret, base_string, hashlib.sha1)
        converted_to_base_64 = base64.urlsafe_b64encode(hashed.digest())
        signature = converted_to_base_64.decode("utf-8")
        return signature, timestamp


stateless_auth = FourkitesUMSStatelessAuthentication()
bearer_auth = FourkitesUMSAuthenticationBearer()
keycloak_auth = KeycloakAuthenticationJWT()
basic_auth = FourKitesUMSAuthenticationBasic()


class FourkitesStatelessOrBearerOrKeycloakJWTAuthentication:
    async def __call__(self, request: Request) -> Optional[dict]:
        if request.headers.get(FourkitesUMSStatelessAuthentication.HEADER):
            user = await stateless_auth(request)
        elif request.headers.get(KeycloakAuthenticationJWT.HEADER):
            user = await keycloak_auth(request)
        elif request.headers.get(FourkitesUMSAuthenticationBearer.USER_ID_HEADER) and request.headers.get(
            FourkitesUMSAuthenticationBearer.DEVICE_ID_HEADER
        ):
            user = await bearer_auth(request)
        else:
            user = await basic_auth(request)

        if self.is_authorized(request, user):
            return user

        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=f"User {user['userId']} not authorized to perform this action",
        )

    def is_authorized(self, request, user):
        # Super Admin can do anything in any carrier
        if user.get("superAdmin", False):
            return True

        # All the other roles can only do anything in the
        # carrier they pertain to
        permalink = user.get("companyPermalink")
        

        routes = request.app.router.routes
        for route in routes:
            match, scope = route.matches(request)
            if match == Match.FULL:
                print(scope["path_params"])

        if not permalink:
            return False

        return request.path_params["carrier_permalink"] == permalink