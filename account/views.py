from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from account.serializers import (UserRegistrationSerializer,UserLoginSerializer)
from django.contrib.auth import authenticate, login

# Create your views here.

class UserRegistrationView(APIView):

    def post(self, request,format=None):
        serializers = UserRegistrationSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):
            serializers.save()
            return Response(serializers.data,
                            status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
 
class UserLoginView(APIView):
    def post(self, request, format=None):
        serializers = UserLoginSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):
            email = serializers.data.get('email')
            password = serializers.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                # login(request, user) 
                return Response({'msg':"Login Sucess"}, status=status.HTTP_200_OK)
            else:
                return Response({
                    'errors':{
                        "non_fields_errors":["Email or Password Not valid"]
                    }},
                    status=status.HTTP_404_NOT_FOUND)
        return Response(serializers.errors,
            status=status.HTTP_400_BAD_REQUEST)