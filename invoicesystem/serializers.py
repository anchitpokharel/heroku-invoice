from base64 import urlsafe_b64encode
from dataclasses import fields
from multiprocessing import AuthenticationError
from os import stat
from unicodedata import decimal
from requests import request
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

from .models import Company, Client, Currency, Language, Invoice, InvoiceDetails
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import (
    smart_str,
    force_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.response import Response


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        # validators=[UniqueValidator(queryset=User.objects.all())],
    )

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    confirmpassword = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            # "username",
            "email",
            "first_name",
            "last_name",
            "company_name",
            "password",
            "confirmpassword",
            # "is_staff",
        )
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
        }

    def validate(self, attrs):
        if attrs["password"] != attrs["confirmpassword"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            # username=validated_data["username"],
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            # is_staff=True,
            company_name=validated_data["company_name"],
        )

        user.set_password(validated_data["password"])
        user.save()

        # save company in company table while registering new user
        # company = Company.objects.create(
        #     user=User.objects.get(email=user.email),
        #     company_name=validated_data["company_name"],
        # )
        # company.save()

        # email verification
        # user_data = User.objects.get(email=user.email)
        # token = RefreshToken.for_user(user_data).access_token

        # current_site = "127.0.0.1:8000"  # get_current_site(request).domain
        # relativeLink = reverse("email-verify")

        # absurl = "http://" + current_site + relativeLink + "?token=" + str(token)
        # email_body = (
        #     "Hi "
        #     + user_data.first_name
        #     + ", Click the below link to verify your email.\n"
        #     + absurl
        # )
        # data = {
        #     "email_body": email_body,
        #     "email_subject": "Verify your email address",
        #     "to_email": user_data.email,
        # }

        # Util.send_email(data)

        return user
        # return Response(
        #     {
        #         "status": "ok",
        #         "message": "Registration Successful",
        #     },
        #     status=status.HTTP_201_CREATED,
        # )


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ["token"]


class RequestPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ["email"]


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ["password", "uidb64", "token"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            uidb64 = attrs.get("uidb64")
            token = attrs.get("token")

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationError("The reset link is invalid", 401)

            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            raise AuthenticationError("The reset link is invalid", 401)
        return super().validate(attrs)


# login serializer
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super(MyTokenObtainPairSerializer, cls).get_token(user)

        # Add custom claims
        # token["username"] = user.username
        return token


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = [
            "id",
            "company_name",
            "address",
            "email",
            "created_date",
            "modified_date",
            "user",
        ]


class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = [
            "id",
            "full_name",
            "email",
            "phone_number",
            "address",
            "currency",
            "language",
        ]


class CurrencySerializer(serializers.ModelSerializer):
    class Meta:
        model = Currency
        fields = [
            "id",
            "currency",
        ]


class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language
        fields = [
            "id",
            "language",
        ]


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = [
            "id",
            "due_date",
            "notes",
            "discount",
            "tax",
            "client",
            "currency",
            "language",
            "total_amount",
        ]
        read_only_fields = ("total_amount",)


class InvoiceDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvoiceDetails
        fields = ["id", "description", "usd", "quantity", "invoice"]

    def create(self, validated_data):
        invoice_details = InvoiceDetails.objects.create(
            description=validated_data["description"],
            usd=validated_data["usd"],
            quantity=validated_data["quantity"],
            invoice=validated_data["invoice"],
        )

        invoice_details.save()

        # save invoice total amount in invoice model
        obj = Invoice.objects.get(pk=int(str(invoice_details.invoice)))
        obj.total_amount += (
            validated_data["usd"] * validated_data["quantity"]
        ) - obj.discount
        obj.save()

        return invoice_details
        # return Response(
        #     {
        #         "status": "ok",
        #         "message": "Invoice Added Successfully",
        #         "data": invoice_details,
        #     },
        #     status=status.HTTP_201_CREATED,
        # )


class EmailTemplateSerializer(serializers.Serializer):
    invoice_id = serializers.IntegerField()
    client_id = serializers.IntegerField()

    class Meta:
        fields = ["invoice_id", "client_id"]
