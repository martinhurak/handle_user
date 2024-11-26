from rest_framework import serializers
from django.contrib.auth.models import User

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    username = serializers.CharField(max_length=150, required=True)

    class Meta:
        model = User
        fields = ['username', 'email']

    def validate_email(self, value):
        user = self.context['request'].user

        # Overenie prítomnosti neplatných znakov
        if any(char in value for char in "<>\"'"):
            raise serializers.ValidationError("E-mail obsahuje neplatné znaky.")

        # Kontrola, či je nový e-mail odlišný od aktuálneho
        if value == user.email:
            raise serializers.ValidationError("Nový e-mail sa zhoduje s aktuálnym.")

        # Overenie, či už e-mail nie je obsadený
        if User.objects.filter(email=value).exclude(id=user.id).exists():
            raise serializers.ValidationError("Tento e-mail už používa iný používateľ.")
        
        return value

    def validate_username(self, value):
        user = self.context['request'].user

        # Overenie prítomnosti neplatných znakov
        if any(char in value for char in "<>\"'"):
            raise serializers.ValidationError("Používateľské meno obsahuje neplatné znaky.")

        # Overenie, či je meno prázdne alebo obsahuje iba medzery
        if len(value.strip()) == 0:
            raise serializers.ValidationError("Používateľské meno nemôže byť prázdne alebo obsahovať iba medzery.")

        # Kontrola, či meno už nie je obsadené
        if User.objects.filter(username=value).exclude(id=user.id).exists():
            raise serializers.ValidationError("Toto meno už používa iný používateľ.")
        
        return value
    
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])  # Bezpečné hashovanie hesla
        user.save()
        return user