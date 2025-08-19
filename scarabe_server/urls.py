
from django.contrib import admin
from django.urls import path
from scarabe import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/create-account/', views.CreateAccountAPIView.as_view(), name='create-account'),
    path('auth/login/', views.SingInView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', views.TokenRefresh.as_view(), name='token_refresh'),
  
    path('auth/request-reset-code/', views.RequestPasswordResetCodeView.as_view(), name='request-reset-code'),
    path('auth/verify-reset-code/', views.VerifyResetCodeView.as_view(), name='verify-reset-code'),
    path('auth/change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    path('auth/resend-reset-code/', views.ResendResetCodeView.as_view() , name='resend-reset-code'),
    
    path('auth/send-email-confirmation-code/', views.SendEmailConfirmationCodeView.as_view(), name='send_email_confirmation_code'),
    path('auth/confirm-email/', views.ConfirmEmailView.as_view(), name='confirm-email'),
    # third day 
    path('auth/user-list/', views.UserListAPIView.as_view(), name='user-list'),
    path("auth/update-account-status/<int:account_id>/", views.UpdateAccountStatusAPIView.as_view(), name="update-account-status"),
    path('accounts/change-role/<int:account_id>/', views.ChangeAccountRoleAPIView.as_view(), name='change-account-role'),
    path("auth/delete-account/<int:pk>/", views.DeleteAccountAPIView.as_view(), name="delete-account"),
    path("auth/view-user-account/<int:user_id>/", views.UserProfileAPIView.as_view(), name="view-user-account"),
    path("auth/update-my-profile/", views.UpdateMyProfileAPIView.as_view(), name="update-my-profile"),
     path("auth/my-profile/", views.MyProfileAPIView.as_view(), name="update-my-profile"),
    # vehicles management endpoint url
    path("material/vehicles/create-new-vehicle/", views.CreateVehicleAPIView.as_view(), name="create-new-vehicle"),
    #fourth day
    path("materials/all/", views.MaterialListView.as_view(), name="list-all-materials"),

    path("material/vehicles/list-all-vehicles/", views.VehicleListAPIView.as_view(), name="list-all-vehicles"),
    path('material/vehicles/<int:vehicle_id>/', views.VehicleDetailView.as_view(), name='vehicle-detail'),
    path('material/vehicles/update-vehicle/<int:vehicle_id>/', views.UpdateVehicleAPIView.as_view(), name='vehicle-update'),
    # tools management endpoint url
    path("material/tools/create-new-tool/", views.CreateToolAPIView.as_view(), name="create-new-tool"),
    path("material/tools/list-all-tool/", views.ToolListAPIView.as_view(), name="list-all-tool"),
    path('material/tools/<int:tool_id>/', views.ToolDetailView.as_view(), name='vehicle-detail'),
    path('material/tools/update-tool/<int:tool_id>/', views.UpdateToolAPIView.as_view(), name='tool-update'),

    # material management
    path('materials/delete/<int:material_id>/', views.DeleteMaterialAPIView.as_view(), name='delete-material'),
    #fifth day: vehicle-update tool-update
    # Malfunctions management 
    path('material/malfunctions/add-material/', views.CreateMalfunctionAPIView.as_view(), name='malfunctions-add-material'),
    path('material/malfunctions/all-list/', views.MaterialMalfunctionListView.as_view(), name='malfunctions-all-list'),
    path('material/malfunctions-details/<int:malfunction_id>/', views.MalfunctionDetailView.as_view(), name='malfunction-detail'),
    path('material/malfunctions/delete/<int:malfunction_id>/', views.MalfunctionDeleteView.as_view(), name='delete-malfunction'),
    path("material/malfunctions/update/<int:malfunction_id>/", views.MalfunctionUpdateView.as_view(), name="malfunction-update"),

    # Advertisement 
    path('advertisements/advertisements-create/', views.CreateAdvertisementView.as_view(), name='create-advertisement'),
    path('advertisements/advertisements-list-all/', views.AdvertisementListView.as_view(), name='advertisement-all-list'),
    path('advertisements/advertisements-list/', views.InspectorsAdvertisementView.as_view(), name='advertisement-all-list'),
    path('advertisements/advertisement-details/<int:ad_id>/', views.AdvertisementDetailView.as_view(), name='advertisement-detail'),
    path('advertisements/advertisement-update/<int:ad_id>/', views.UpdateAdvertisementView.as_view(), name='update-advertisement'),
    path('advertisements/advertisement-delete/<int:ad_id>/', views.DeleteAdvertisementView.as_view(), name='delete-advertisement'),
     
    # reservations endpoints
    path('reservations/create-reservation/', views.CreateReservationView.as_view(), name='create-reservation'),
    path('reservations/update-reservation/<int:reservation_id>/', views.UpdateReservationView.as_view(), name='update-reservation'),
    path('reservations/reservation-detail/<int:reservation_id>/', views.ReservationDetailView.as_view(), name='reservation-detail'),
    path('reservations/reservation-all-list/', views.ReservationListView.as_view(), name='reservation-all-list'),
    path('reservations/user-reservations/<int:user_id>/', views.UserReservationListView.as_view(), name='user-reservations'),
    path('materials/reservations/<int:material_id>/', views.MaterialReservationListView.as_view(), name='material-reservations'),
    path('reservations/user-my-reservations/', views.MyReservationListView.as_view(), name='user-reservations'),
    path('reservations/reservation-delete/<int:reservation_id>/', views.DeleteReservationView.as_view(), name='delete-reservation'),
    path('reservations/reservation-accept/<int:reservation_id>/', views.AcceptReservationView.as_view(), name='accept-reservation'),
    path('reservations/reservation-decline/<int:reservation_id>/', views.RefuseReservationView.as_view(), name='decline-reservation'),
   
   # endpoints of pre checks
    path('pre-checks/all-list/', views.PreCheckListView.as_view(), name='pre-checks-all-list'),
    path('pre-checks/pre-check-details/<int:precheck_id>/', views.PreCheckDetailView.as_view(), name='pre-check-details'),
    path('pre-checks/pre-check-delete/<int:precheck_id>/', views.PreCheckDeleteView.as_view(), name='delete-pre-check'),

    # endpoints of support
    path('support/tickets/', views.TicketListCreateAPIView.as_view(), name='support-ticket-list-create'),
    path('support/tickets/<int:pk>/', views.TicketDetailAPIView.as_view(), name='support-ticket-detail'),
    path('support/tickets/<int:pk>/replies/', views.TicketRepliesAPIView.as_view(), name='support-ticket-replies'),
    path('support/replies/<int:pk>/', views.ReplyDetailAPIView.as_view(), name='support-reply-detail'),
     path('support/my-tickets/', views.MyTicketsAPIView.as_view(), name='my-tickets'),
    
    #notification endpoint
     path('notifications/my/', views.MyNotificationsView.as_view(), name='my-notifications-list'),
    path('notifications/my/<int:notification_id>/', views.MyNotificationsView.as_view(), name='my-notifications-detail'),
    
    path('recent-activity/', views.RecentActivityAPIView.as_view(), name='recent-reservations'),
    path('dashboard/stats/', views.DashboardStatsAPIView.as_view(), name='dashboard-stats'),

    ]
