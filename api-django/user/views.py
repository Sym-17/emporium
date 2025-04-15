from django.http import HttpResponse
from django.shortcuts import render
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from user.serializers import UserLogInSerializer, UserSignUpSerializer
from user.utils import refresh_access_token, require_token


class HelloWorldView(APIView):

    @require_token
    def get(self, request):
        return Response({"message": "Hello World!"}, status=200)


class UserSignUpView(APIView):
    def post(self, request):
        serializer = UserSignUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Sign Up Successfully"}, status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogInView(APIView):
    def post(self, request):
        serializer = UserLogInSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.validate_user(data=request.data)

                refresh_token = RefreshToken.for_user(user)
                access_token = refresh_access_token(refresh_token)

                response = Response(
                    {
                        "message": "Log In Successfully",
                    },
                    status=status.HTTP_202_ACCEPTED,
                )
                response.set_cookie(
                    "access_token",
                    access_token,
                    httponly=True,
                    secure=True,
                    samesite="Lax",
                )
                response.set_cookie(
                    "refresh_token",
                    str(refresh_token),
                    httponly=True,
                    secure=True,
                    samesite="Lax",
                )
                return response
            except serializers.ValidationError as e:
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                return HttpResponse(status=500)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RefreshAccessToken(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response({"error": "Old refresh token is required!"}, status=400)

        try:
            access_token = refresh_access_token(refresh_token)
            response = JsonResponse({"message": "Access token refreshed successfully!"})
            response.set_cookie(
                "access_token", access_token, httponly=True, secure=True, samesite="Lax"
            )
            return response
        except TokenError as e:
            return Response({"error": "Invalid or expired refresh token"}, status=401)
