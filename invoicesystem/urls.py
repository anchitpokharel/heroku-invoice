from django.urls import path
from . import views

from rest_framework_simplejwt.views import TokenRefreshView

from rest_framework_swagger.views import get_swagger_view

from django.conf.urls.static import static
from django.conf import settings

schema_view = get_swagger_view(title="Invoice System API")

urlpatterns = [
    path("register/", views.register.as_view()),
    path("login/", views.MyObtainTokenPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", views.LogoutView.as_view(), name="auth_logout"),
    path("company/", views.company.as_view()),
    path("company/<int:pk>", views.companyDetails.as_view()),
    path("apidocs/", schema_view),
    path("email-verify/", views.VerifyEmail.as_view(), name="email-verify"),
    path(
        "request-reset-email",
        views.RequestPasswordResetEmail.as_view(),
        name="request-reset-email",
    ),
    path(
        "password-reset/<uidb64>/<token>",
        views.PasswordTokenCheckAPI.as_view(),
        name="password-reset-confirm",
    ),
    path(
        "password-reset-complete",
        views.SetNewPassword.as_view(),
        name="password-reset-complete",
    ),
    path("client/", views.clientCreateList.as_view()),
    path("client/<int:pk>", views.clientDetails.as_view()),
    path("currency/", views.currencyCreateList.as_view()),
    path("language/", views.languageCreateList.as_view()),
    path("invoiceListCreate/", views.invoiceCreateList.as_view()),
    path(
        "sendEmailTemplate",
        views.sendEmailTemplate.as_view(),
    ),
    path(
        "generateInvoice/<int:pk>",
        views.GenerateInvoice.as_view(),
    ),
    path(
        "invoiceSetttingsUpdate/",
        views.invoiceSetttingsUpdate.as_view(),
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
