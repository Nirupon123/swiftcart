from django.urls import path
from .views import LoginView, LogoutView, CustomerSignupView, RiderSignupView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/customer/', CustomerSignupView.as_view(), name='customer-signup'),
    path('signup/rider/', RiderSignupView.as_view(), name='rider-signup'),
]