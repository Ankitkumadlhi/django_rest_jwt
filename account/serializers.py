from rest_framework import serializers
from account.models import User
from django.utils.encoding import force_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    User Registration Serializer
    
    """    
    # Confirm password field in Registration Request
    password2 = serializers.CharField(max_length=255,style={'input_type': 'password'},
                write_only=True)
    
    class Meta:
        model = User
        fields = [
            'email',
            'name',
            'password',
            'password2',
            'tc',
        ]
        extra_kwargs = {
            'password': {'write_only': True}
        }
    #validate the password and password2
    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({'password': 'Passwords must match.'})
        return data

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class UserLoginSerializer(serializers.ModelSerializer):
    """
    User Login Serializer    
    """
    email = serializers.EmailField(max_length=255) 
    # password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = [
            'email',
            'password'
        ]

class UserProfileSerializer(serializers.ModelSerializer):
    """
    User Profile Serializer    
    """
    class Meta:
        model = User
        fields = [
            'email',
            'name',
            'tc',
        ]   

class UserChnagePasswordSerializer(serializers.Serializer):
    password1 = serializers.CharField(max_length=255,style={'input_type': 'password'},
                write_only=True,required=True)
    password2 = serializers.CharField(max_length=255,style={'input_type': 'password'},
                write_only=True,required=True)

    class Meta:
        fields = [
            'password1',
            'password2'
        ]
    def validate(self, data):
        user = self.context.get('user')
        if data['password1'] != data['password2']:
            raise serializers.ValidationError({'password': 'Passwords must match.'})
        user.set_password(data['password1'])
        user.save()
        return data
     

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = [ 
            'email',
        ]
    def validate(self, data):
        email = data.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)

            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            print("Encoded uidb64",uidb64)
            token = PasswordResetTokenGenerator().make_token(user)
            link = f'http://localhost:3000/api/user/password-reset-confirm/{uidb64}/{token}'
            print("Password Reset Link",link)
            
            # send_mail(subject, message, from_email, recipient_list, html_message) 
            Util.send_email({
                'email_subject': 'Reset Your Password',
                'email_body': f"Click on given Link: {link}",
                'to_email': user.email
            })
            return data
        else:
            raise serializers.ValidationError({'email': 'User not a Registered User..'})
        
class UserPasswordResetSerializer(serializers.Serializer):
    password1 = serializers.CharField(max_length=255,style={'input_type': 'password'},
                write_only=True,required=True)
    password2 = serializers.CharField(max_length=255,style={'input_type': 'password'},
                write_only=True,required=True)
    

    class Meta:
        fields = [
            'password1',
            'password2'
        ]
    def validate(self, data):
        try:
            uid= self.context.get('uid')
            token = self.context.get('token')
            if data['password1'] != data['password2']:
                raise serializers.ValidationError({'password': 'Passwords must match.'})
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise serializers.ValidationError({'token': 'Token is not valid or Expried, please request a new one.'})
            user.set_password(data['password1'])
            user.save()
            return data
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise serializers.ValidationError({'token': 'Token is not valid or Expried, please request a new one.'})
        
