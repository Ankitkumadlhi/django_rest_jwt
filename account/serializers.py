from rest_framework import serializers
from account.models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    User Registration Serializer
    
    """    
    # Confirm password field in Registration Request
    password2 = serializers.CharField(style={'input_type': 'password'},
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