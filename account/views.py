from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from account.serializers import (UserRegistrationSerializer,
                                 UserLoginSerializer,
                                 UserProfileSerializer,
                                 UserChnagePasswordSerializer,
                                 SendPasswordResetEmailSerializer,
                                 UserPasswordResetSerializer)
from django.contrib.auth import authenticate, login
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Create your views here.


#Get the token for the user Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request,format=None):
        serializers = UserRegistrationSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):
            user=serializers.save()
            token = get_tokens_for_user(user)
            return Response({'data':serializers.data,'token':token},
                            status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)
 
class UserLoginView(APIView):
    renderer_classes = (UserRenderer,)
    def post(self, request, format=None):
        serializers = UserLoginSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):
            email = serializers.data.get('email')
            password = serializers.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                # login(request, user) 
                return Response({'token':token,'msg':"Login Sucess"}, status=status.HTTP_200_OK)
            else:
                return Response({
                    'errors':{
                        "non_fields_errors":["Email or Password Not valid"]
                    }},
                    status=status.HTTP_404_NOT_FOUND)
        return Response(serializers.errors,
            status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        user = request.user
        serializers = UserProfileSerializer(user)
        if serializers:
            return Response(serializers.data,status=status.HTTP_200_OK)
    
    def put(self,request):
        user = request.user
        serializers = UserRegistrationSerializer(user,data=request.data)
        if serializers.is_valid(raise_exception=True):
            serializers.save()
            return Response(serializers.data,status=status.HTTP_200_OK)
        return Response(serializers.errors,status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self,request):
        user = request.user
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self,request):
        user = request.user
        serializers = UserChnagePasswordSerializer(user,data=request.data,
                                                   context = {'user':user} )
        if serializers.is_valid(raise_exception=True):
            # serializers.save()
            return Response({'msg':'Password Change Sucessfully'},status=status.HTTP_200_OK)
        return Response(serializers.errors,status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self,request):
        user = request.user
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            return Response({'msg':'Email Send Sucessfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self,request,uid,token,format=None):
        serializer = UserPasswordResetSerializer(data=request.data,
        context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
    