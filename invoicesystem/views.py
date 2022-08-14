from multiprocessing import context
from operator import is_
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.generics import (
    ListCreateAPIView,
    RetrieveUpdateDestroyAPIView,
    RetrieveDestroyAPIView,
    GenericAPIView,
    CreateAPIView,
    UpdateAPIView,
    ListAPIView,
)
from rest_framework.views import APIView
from .serializers import (
    RegisterSerializer,
    EmailVerificationSerializer,
    InvoiceSerializer,
    ChangeUserPasswordSerializer,
    ChangeUsernameSerializer,
    ChangeUserImageSerializer,
)
from .models import (
    Client,
    Company,
    Currency,
    InvoiceDetails,
    InvoiceSettings,
    Language,
    Invoice,
    InvoiceDiscount,
    Tax,
    UserImage,
)
from django.contrib.auth import get_user_model

User = get_user_model()

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import (
    RegisterSerializer,
    MyTokenObtainPairSerializer,
    CompanySerializer,
    RequestPasswordEmailSerializer,
    SetNewPasswordSerializer,
    ClientSerializer,
    CurrencySerializer,
    LanguageSerializer,
    EmailTemplateSerializer,
    InvoiceSettingsSerializer,
    TaxSerializer,
)
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from django.conf import settings
from rest_framework import status
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

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

# for generating invoice
from io import BytesIO
from django.template.loader import get_template
from xhtml2pdf import pisa
import os

# Create your views here.
class register(ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class VerifyEmail(APIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get("token")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])

            # set user verified status to true
            user.is_verified = True
            user.save()
            return Response(
                {"email": "Successfully Activated"}, status=status.HTTP_201_CREATED
            )
        except jwt.ExpiredSignatureError as identifier:
            return Response(
                {"error": "Activation Expired"}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.exceptions.DecodeError as identifier:
            return Response(
                {"error": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST
            )


class RequestPasswordResetEmail(GenericAPIView):
    serializer_class = RequestPasswordEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data["email"]

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            print("user_id:", user.id)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = (
                "127.0.0.1:3000/auth"  # get_current_site(request=request).domain  #
            )
            relativeLink = reverse(
                "password-reset-confirm", kwargs={"uidb64": uidb64, "token": token}
            )

            absurl = "http://" + current_site + relativeLink
            email_body = (
                "Hi, " + "Click the below link to reset your password.\n" + absurl
            )
            data = {
                "email_body": email_body,
                "email_subject": "Reset your password",
                "to_email": user.email,
            }

            Util.send_email(data)

            return Response(
                {"success": "We have sent you a link to reset your password."},
                status=status.HTTP_200_OK,
            )

        else:
            return Response(
                {"error": "Email doesnot exists."}, status=status.HTTP_400_BAD_REQUEST
            )


class PasswordTokenCheckAPI(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {"error": "Token is not valid, please request a new one"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            return Response(
                {
                    "success": True,
                    "message": "Credentials Valid",
                    "uidb64": uidb64,
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )

        except DjangoUnicodeDecodeError as identifier:
            return Response(
                {"error": "Token is not valid, please request a new one"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"success": True, "message": "Password reset successful"},
            status=status.HTTP_200_OK,
        )


# login
class MyObtainTokenPairView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        try:
            serializer.is_valid()
            return Response(
                {"data": serializer.validated_data, "message": "Login Successful"},
                status=status.HTTP_200_OK,
            )
        except Exception:
            return Response(
                {"data": "NULL", "message": "Invalid Credentials"},
                status=status.HTTP_404_NOT_FOUND,
            )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        if self.request.data.get("all"):
            token: OutstandingToken
            for token in OutstandingToken.objects.filter(user=request.user):
                _, _ = BlacklistedToken.objects.get_or_create(token=token)
            return Response({"status": "OK, goodbye, all refresh tokens blacklisted"})
        refresh_token = self.request.data.get("refresh_token")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"status": "OK, goodbye"})


# company
class company(ListCreateAPIView):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


class companyDetails(RetrieveUpdateDestroyAPIView):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


# currency
class currencyCreateList(ListCreateAPIView):
    queryset = Currency.objects.all()
    serializer_class = CurrencySerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


# language
class languageCreateList(ListCreateAPIView):
    queryset = Language.objects.all()
    serializer_class = LanguageSerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


# client
class clientCreateList(ListCreateAPIView):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


class clientDetails(RetrieveUpdateDestroyAPIView):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


# invoice
class invoiceCreateList(ListCreateAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user = self.request.user
        data = request.data

        # insert invoice data
        invoice_data = Invoice.objects.create(
            client=Client.objects.get(id=data["client"]),
            due_date=data["due_date"],
            notes=data["notes"],
            currency=Currency.objects.get(id=data["currency"]),
            language=Language.objects.get(id=data["language"]),
            created_by=User.objects.get(id=user.id),
        )

        invoice_data.save()

        # invoice items insert
        for i in data["items"]:
            items_data = InvoiceDetails.objects.create(
                invoice=Invoice.objects.get(id=invoice_data.id),
                description=i["description"],
                amount=i["amount"],
                quantity=i["quantity"],
            )
            items_data.save()

        # insert invoice discount
        invoice_discount_data = InvoiceDiscount.objects.create(
            invoice=Invoice.objects.get(id=invoice_data.id),
            type=data["type"],
            value=data["value"],
        )
        invoice_discount_data.save()

        return Response(
            {"success": "Invoice Created."},
            status=status.HTTP_200_OK,
        )


# send email template in invoice
class sendEmailTemplate(GenericAPIView):
    serializer_class = EmailTemplateSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        invoice_id = request.data["invoice_id"]
        client_id = request.data["client_id"]

        client = Client.objects.get(id=client_id)

        html_content = render_to_string(
            "emailtemplate.html", {"var1": "hello", "content": client.full_name}
        )
        text_content = strip_tags(html_content)
        email = EmailMultiAlternatives(
            # subject
            "View Your Invoice",
            # content
            text_content,
            # from email
            settings.EMAIL_HOST_USER,
            # recepeint list
            [client.email],
        )

        email.attach_alternative(html_content, "text/html")
        email.send()

        return Response(
            {"success": "We have sent you an invoice. Check Your email."},
            status=status.HTTP_200_OK,
        )

        # email_body = "Hi, " + "Click the below link to reset your password.\n"
        # data = {
        #     "email_body": email_body,
        #     "email_subject": "Reset your password",
        #     "to_email": client.email,
        # }

        # Util.send_email(data)


def fetch_resources(uri, rel):
    path = os.path.join(uri.replace(settings.STATIC_URL, ""))
    return path


def render_to_pdf(template_src, context_dict={}):
    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type="application/pdf")
    return None


# generate invoice
class GenerateInvoice(GenericAPIView):
    def get(self, request, pk):
        invoice = Invoice.objects.get(pk=pk)
        data = {
            "invoice_id": invoice.id,
            "due_date": invoice.due_date,
            "notes": invoice.notes,
            "discount": invoice.discount,
            "tax": invoice.tax,
            "client_id": invoice.client_id,
            "currency_id": invoice.currency_id,
            "language_id": invoice.language_id,
            "total_amount": invoice.total_amount,
        }
        pdf = render_to_pdf("abc.html", {"data": data})
        return HttpResponse(pdf, content_type="application/pdf")

        # if pdf:
        #     response = HttpResponse(pdf, content_type="application/pdf")
        #     filename = "invoice_%s.pdf" % (data["invoice_id"])
        #     content = "inline; filename='%s'" % (filename)


class invoiceSetttingsUpdate(APIView):
    def post(self, request, format=None):
        serializer = InvoiceSettingsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "success": "Settings Updated",
                    "status": "success",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors)

    def get(self, request, format=None):
        settings_data = InvoiceSettings.objects.all()
        serializer = InvoiceSettingsSerializer(settings_data, many=True)
        return Response(
            {
                "status": "success",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


# tax
class taxCreateList(ListCreateAPIView):
    queryset = Tax.objects.all()
    serializer_class = TaxSerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


class taxDetails(RetrieveDestroyAPIView):
    queryset = Tax.objects.all()
    serializer_class = TaxSerializer
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


class taxByCompany(GenericAPIView):
    def get(self, request, id):
        queryset = Tax.objects.filter(company=id)
        serializer_class = TaxSerializer

        return Response(
            {
                "data": queryset,
            },
            status=status.HTTP_200_OK,
        )


class changeUserPassword(UpdateAPIView):
    serializer_class = ChangeUserPasswordSerializer
    model = User
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            self.object.set_password(serializer.data.get("password"))
            self.object.save()
            response = {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Password updated successfully",
                "data": [],
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class changeUsername(UpdateAPIView):
    serializer_class = ChangeUsernameSerializer
    model = User
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = self.request.user
        user_data = User.objects.get(id=user.id)

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            uname = serializer.data.get("username")
            splitted_name = uname.split()

            if len(splitted_name) < 2:
                user_data.first_name = splitted_name[0]
                last_name = ""
            elif len(splitted_name) < 3:
                user_data.first_name = splitted_name[0]
                last_name = splitted_name[1]
            else:
                user_data.first_name = splitted_name[0]
                last_name = ""
                for i in range(1, len(splitted_name)):
                    last_name += " " + splitted_name[i]

            user_data.last_name = last_name
            user_data.save()
            response = {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Username updated successfully",
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class changeUserImage(ListCreateAPIView):
    queryset = UserImage.objects.all()
    serializer_class = ChangeUserImageSerializer
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]


class getClientByUser(ListAPIView):
    serializer_class = ClientSerializer
    model = Client
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = Client.objects.filter(user=self.request.user)
        serializer = ClientSerializer(queryset, many=True)
        return Response(
            {
                "status": "success",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )
