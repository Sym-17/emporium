from functools import wraps

import jwt
from core import config
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


def decode_jwt_token(token):
    """
    Decodes a JWT token and returns the payload.
    """
    try:
        return jwt.decode(
            token,
            config.user_authentication.signing_key,
            algorithms=[config.user_authentication.algorithm],
        )
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError


def refresh_access_token(refresh_token: str) -> str:
    """
    Refreshes an access token using the provided refresh token.
    """
    try:
        refresh = RefreshToken(refresh_token)
        return str(refresh.access_token)
    except TokenError:
        raise TokenError("Invalid refresh token")


def require_token(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            return JsonResponse({"error": "Authentication required!"}, status=401)

        try:
            payload = decode_jwt_token(access_token)
            request.user_id = payload.get("user_id")

        except jwt.ExpiredSignatureError:
            refresh_token = request.COOKIES.get("refresh_token")

            if not refresh_token:
                return JsonResponse({"error": "Log In required!"}, status=401)

            try:
                new_access_token = refresh_access_token(refresh_token)
                response = JsonResponse({"message": "Token refreshed successfully!"})
                response.set_cookie(
                    "access_token",
                    new_access_token,
                    httponly=True,
                    secure=True,
                    samesite="Lax",
                )

                payload = decode_jwt_token(new_access_token)
                request.user_id = payload.get("user_id")
                print("Access token refreshed successfully!")
                # return response

            except TokenError:
                return JsonResponse(
                    {"error": "Invalid refresh token! Please log in again."},
                    status=401,
                )

        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid access token!"}, status=401)

        return view_func(request, *args, **kwargs)

    return wrapper
