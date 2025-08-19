from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.mail import send_mail
from scarabe.auth import authenticate_and_authorize, authenticate_and_authorize_allUser
from scarabe.notifications import create_notification, send_notification_email
from scarabe_server import settings
from .models import Account, AccountTypes, AccountStatus, Advertisement, AdvertisementStatus, BodyCondition, CheckStatus, EngineStatus, FuelType, Malfunction, MalfunctionPhoto, MalfunctionStatus, Material, MaterialReservationStatus, MaterialStatus, MaterialType, Notification, NotificationStatus, PreCheck, PriorityLevel, Reservation, ReservationStatus, ReservationType, SeverityLevel, SupportAttachment, SupportReply, SupportTicket, SupportTicketStatus, TireStatus, Tool, Vehicle
from django.utils.crypto import get_random_string
from .serializers import ConfirmEmailSerializer, CustomTokenRefreshSerializer, ResetCodeSerializer, VerificationCodeSerializer
import re
from django.db.models import Q
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from .serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils.timezone import now , localtime
import base64
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils.dateparse import parse_date
from django.db.models import Prefetch
# Create your views here.

# create accounts endpoint
class CreateAccountAPIView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        username        = request.data.get('full_name')
        email            = request.data.get('email')
        role             = request.data.get('role')
        whatsapp_number  = request.data.get('whatsapp_number')
        password         = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        # --- Validate ---
        if not all([username, email, role, whatsapp_number, password, confirm_password]):
            return Response({"message": "Tous les champs sont obligatoires."}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({"message": "le mot de passe et la confirmation du mot de passe ne correspondent pas"}, status=status.HTTP_400_BAD_REQUEST)

        if not re.match(r'^[\w.+-]+@[\w-]+\.[\w.-]+$', email):
            return Response({"message": "Format d'email invalide."}, status=status.HTTP_400_BAD_REQUEST)

        if not re.match(r'^\+\d{10,15}$', whatsapp_number):
            return Response({"message": "Format WhatsApp invalide. Utilisez +1234567890"}, status=status.HTTP_400_BAD_REQUEST)

        if role not in AccountTypes.values:
            return Response({"message": f"Rôle invalide; choisissez-en un parmi {list(AccountTypes.values)}"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"message": "Un utilisateur avec cet email existe déjà."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # --- Create User with strong hash ---
            user = User(username=username, email=email)
            user.set_password(password)  # uses PBKDF2 by default
            if role == AccountTypes.ADMIN:
                user.is_staff = True        # Can access Django admin panel
                user.is_superuser = True    # Has all permissions
            else:
                user.is_staff = False
                user.is_superuser = False

            user.save()

            # --- Create Account ---
            now = timezone.now()
            account = Account.objects.create(
                user=user,
                whatsapp_number=whatsapp_number,
                role=role,
                status= AccountStatus.ACTIVE,
                # these are auto_now/auto_now_add on the model:
                # created_at, updated_at
                registration_date=now,
                rest_code= get_random_string(length=6, allowed_chars='0123456789'),
                rest_code_expires=now + timedelta(minutes=10),
            )
                        # Build a friendly notification message for the new user
            try:
                # dynamic plaintext content (newlines will be converted to paragraphs)
                notif_title = "Bienvenue sur VeYoo — compte créé"
                notif_content = (
                    f"Bonjour {user.get_full_name() or user.username},\n\n"
                    f"Votre compte VeYoo a été créé par un administrateur.\n\n"
                    f"Identifiant: {user.email}\n\n"
                    "Connectez-vous à l'application pour compléter votre profil et changer votre mot de passe.\n\n"
                    "Si vous n'attendiez pas cet e-mail, veuillez contacter votre administrateur."
                )

                # create notification & send email (send_notification_email will create the Notification if needed)
                send_result = send_notification_email(title=notif_title, content=notif_content, recipient=user)

                if not send_result.get("ok"):
                    return Response({"message": "Failed to send welcome notification for user"}, status=status.HTTP_400_BAD_REQUEST)
            except:
                # don't crash the endpoint if notification fails
               
                 return Response({"message": "Failed to send welcome notification for user"}, status=status.HTTP_400_BAD_REQUEST)

            data = {
                    "id": user.id,
                    "account_id":account.id,
                    "username": user.username,
                    "email": user.email,
                    "role": account.role,
                    "whatsapp": account.whatsapp_number or "Non défini",
                    "status": account.status,
                    "registration_date": localtime(account.registration_date).strftime("%d/%m/%Y") if account.registration_date else "",
                
            }
            return Response({'message': 'nouveau compte créé avec succès','new_user':data}, status=status.HTTP_200_OK)

        except ValidationError as e:
            user.delete()
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            user.delete()
            return Response({"message": f"Unexpected error: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
     
# Login  endpoint
class SingInView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response({'message': 'Email et mot de passe sont requis.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            
        except User.DoesNotExist:
            return Response({'message': 'Aucun compte avec cet email..!'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            return Response({'message': 'Mot de passe incorrect.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({'message': 'Le compte est inactif.'}, status=status.HTTP_403_FORBIDDEN)
        # Now generate tokens using the serializer
        serializer = TokenObtainPairSerializer(data={"email": email, "password": password})
        serializer.is_valid(raise_exception=True)
        tokens = serializer.validated_data
        
        return Response({
            'message': 'Connexion réussie.',
            'tokens': tokens,
           
        }, status=status.HTTP_200_OK)

# Refresh token endpoint
class TokenRefresh(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            # Validate and get tokens
            serializer.is_valid(raise_exception=True)
            tokens = serializer.validated_data

            return Response({
                'message': 'Rafraîchissement réussi.',
                'tokens': tokens
            }, status=status.HTTP_200_OK)

        except TokenError as e:
            return Response({
                'message': 'Le jeton (Token) est invalide ou expiré.' ,
                'details': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)

        except InvalidToken as e:
            return Response({
                'message': 'Token invalide.',
                'details': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)
        
# reset code 
class RequestPasswordResetCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
       
        email            = request.data.get('email')
        if not re.match(r'^[\w.+-]+@[\w-]+\.[\w.-]+$', email):
            return Response({"error": "Format d'email invalide."}, status=status.HTTP_400_BAD_REQUEST)
      
        
        try:
             User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Aucun compte trouvé pour l'adresse e-mail fournie."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ResetCodeSerializer(data=request.data , context={"title": "Code de réinitialisation de mot de passe"})
        if serializer.is_valid():
            result = serializer.save()
            return Response(
                {"message": f"Le code a été envoyé par email : {result['email']}"},
                status=status.HTTP_200_OK
            )
        return Response({"message": f"problèmes sur le serveur"}, status=status.HTTP_400_BAD_REQUEST)


class VerifyResetCodeView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')

        if not email or not code:
            return Response({"message": "L'email et le code sont requis."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            account = user.account
        except User.DoesNotExist:
            return Response({"message": "Cet e-mail n'est associé à aucun compte."}, status=status.HTTP_404_NOT_FOUND)

        # Check code and expiration
        if account.rest_code == code and account.rest_code_expires > now():
            return Response(
                {"message": "Réinitialisez le mot de passe. Assurez-vous qu'il soit fort."},
                status=status.HTTP_200_OK
            )
        elif account.rest_code_expires <= now():
             # Refresh the code 
            new_code = get_random_string(length=6, allowed_chars='0123456789')
            account.rest_code = new_code
            account.rest_code_expires = now() + timedelta(minutes=10)
            account.save()
            return Response(
                {"message": "Le code de réinitialisation a expiré."},
                status=status.HTTP_400_BAD_REQUEST
            )    
        else:

            return Response(
                {"message": "Le code de réinitialisation est invalide"},
                status=status.HTTP_400_BAD_REQUEST
            )  

class ChangePasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")
        email = request.data.get("email")
        if not password or not confirm_password:
            return Response({"message": "Le mot de passe et la confirmation du mot de passe sont requis."},
                            status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({"message": "Les mots de passe ne correspondent pas."}, status=status.HTTP_400_BAD_REQUEST)


        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "Utilisateur non trouvé."}, status=status.HTTP_404_NOT_FOUND)

        # Set the new password
        user.set_password(password)
        user.save()

        return Response({"message": "Mot de passe changé avec succès."}, status=status.HTTP_200_OK) 

# resend confirmation code 

class ResendResetCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        print(email)
        # Step 1: Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({"message": "Format d'email invalide."}, status=status.HTTP_400_BAD_REQUEST)

        # Step 2: Check if the user with the email exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "L'utilisateur avec cet email n'existe pas."}, status=status.HTTP_404_NOT_FOUND)

        account = user.account
        code = get_random_string(length=6, allowed_chars='0123456789')
        account.rest_code = code
        account.rest_code_expires = now() + timedelta(minutes=10)
        account.save()

        # Step 4: Send reset code via email
       
        serializer = VerificationCodeSerializer(data=request.data , context={"title": "Votre nouveau code de vérification"} )
        if serializer.is_valid():
            result = serializer.save()
            return Response(
                {"message": f"Code de réinitialisation envoyé avec succès."},
                status=status.HTTP_200_OK
            )
        return Response({"message": f"problèmes sur le serveur"}, status=status.HTTP_400_BAD_REQUEST)

       

# code for confirmation of email
class SendEmailConfirmationCodeView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        user = request.user

        try:
            user = User.objects.get(id=user.id)
            account = user.account 
        except User.DoesNotExist:
            return Response({"message": "Utilisateur non trouvé."}, status=status.HTTP_404_NOT_FOUND)

        # Generate confirmation code
        code = get_random_string(length=6, allowed_chars='0123456789')
        account.rest_code = code
        account.rest_code_expires = now() + timedelta(minutes=10)
        account.save(update_fields=["rest_code", "rest_code_expires"])

        # Send code via email
        serializer = ConfirmEmailSerializer(data=request.data , context={"title": 'Code de confirmation par e-mail'} )
        if serializer.is_valid():
            result = serializer.save()
            return Response(
                {"message": f"Le code de confirmation a été envoyé à votre e-mail."},
                status=status.HTTP_200_OK
            )
        return Response({"message": f"problèmes sur le serveur"}, status=status.HTTP_400_BAD_REQUEST)

        

# confirm mail endpoint
class ConfirmEmailView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def post(self, request):
        code = request.data.get("code")
        user = request.user
        if not code:
            return Response({"message": "Un code de réinitialisation est requis."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user.id)
            account = user.account
        except Account.DoesNotExist:
            return Response({"message": "Compte non trouvé."}, status=status.HTTP_404_NOT_FOUND)

        if account.rest_code != code:
            return Response({"message": "Code invalide."}, status=status.HTTP_400_BAD_REQUEST)

        if not account.rest_code_expires or timezone.now() > account.rest_code_expires:
            return Response({"message": "Le code a expiré."}, status=status.HTTP_400_BAD_REQUEST)

        account.email_verified = True
        account.save()

        return Response({"message": "Email confirmé avec succès."}, status=status.HTTP_200_OK)  


# Users list endpoint
class UserListAPIView(APIView):
    permission_classes = [IsAdminUser]

    def get_counts(self):
        total_users = Account.objects.count()
        active_users = Account.objects.filter(status=AccountStatus.ACTIVE).count()
        managers = Account.objects.filter(role=AccountTypes.MANAGER).count()
        inspectors = Account.objects.filter(role=AccountTypes.INSPECTOR).count()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "managers": managers,
            "inspectors": inspectors,
        }

    def get(self, request):
        accounts = Account.objects.select_related('user').all()
        data = []
        if accounts:
            
            for account in accounts:
                user = account.user
                data.append({
                    "id": user.id,
                    "account_id":account.id,
                    "name": user.username,
                    "email": user.email,
                    "role": account.role,
                    "whatsapp": account.whatsapp_number or "Non défini",
                    "status": account.status,
                    "registration_date": localtime(account.registration_date).strftime("%d/%m/%Y") if account.registration_date else "",
                })

            response = {
                "counts": self.get_counts(),
                "users": data
            }

            return Response(response , status=status.HTTP_200_OK ) 
        else:
              return Response({"message": "Il y a des problèmes, essayez de recharger la page."} , status=status.HTTP_400_BAD_REQUEST ) 


class UpdateAccountStatusAPIView(APIView):
    permission_classes = [IsAdminUser , IsAuthenticated]

    def put(self, request, account_id):
        # Get requester account
        try:
            requester = Account.objects.get(user=request.user)
        except Account.DoesNotExist:
            return Response({"message": "Compte utilisateur authentifié non trouvé."}, status=status.HTTP_404_NOT_FOUND)

        # Check permission
        if requester.role != AccountTypes.ADMIN:
            return Response({"message": "Permission refusée. Seul un administrateur peut effectuer cette action."}, status=status.HTTP_403_FORBIDDEN)

        # Find target account
        try:
            user = User.objects.get(id=account_id)
            target_account = user.account
        except User.DoesNotExist:
            return Response({"message": "Compte non trouvé."}, status=status.HTTP_404_NOT_FOUND)

       
        try:
            with transaction.atomic():
                 # Toggle status
                if target_account.status == AccountStatus.ACTIVE:
                    target_account.status = AccountStatus.INACTIVE
                    action = "désactivé"
                else:
                    target_account.status = AccountStatus.ACTIVE
                    action = "activé"

                try:
                    target_account.save(update_fields=["status", "updated_at"])
                except Exception:
                    target_account.save()

                actor_name = requester.user.username
                title = f"Votre compte a été {action}"
                content = (
                    f"Bonjour {user.username},\n\n"
                    f"Votre compte a été {action} par {actor_name} le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                    "Si vous pensez qu'il s'agit d'une erreur, veuillez contacter un administrateur."
                )

                # create_notification will raise on error; it's wrapped inside the transaction so both
                # the account update and the notification creation are atomic.
                notification = create_notification(
                    title=title,
                    content=content,
                    recipient= user,
                    notification_date=timezone.localdate(),
                    notification_time=timezone.localtime().time()
                    # notification_status omitted => uses default (UNREAD)
                )
        except :
                  
                    return Response(
                        {"message": "Échec lors de la modification du statut du compte."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )  
        try:
            # send_notification_email accepts a Notification instance OR title/content/recipient.
            # Here we pass the Notification instance we just created.
            send_result = send_notification_email(notification=notification)
            if not send_result.get("ok"):
                return Response({"message": "Failed to send account status notification for user"}, status=status.HTTP_400_BAD_REQUEST)
        except :
            return Response({"message": "Failed to send account status notification for user"}, status=status.HTTP_400_BAD_REQUEST)


        return Response({
            "message": f"Compte {action} avec succès.",
            "account_id": user.id,
            "new_status": target_account.status
        }, status=status.HTTP_200_OK)
    
# change the role of user
class ChangeAccountRoleAPIView(APIView):
    permission_classes = [IsAdminUser, IsAuthenticated]

    def put(self, request, account_id):
        # 1) auth and permission
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response

        # 2) Validate payload
        new_role = request.data.get("role")
        if not new_role:
            return Response({"message": "Le champ 'role' est requis."}, status=status.HTTP_400_BAD_REQUEST)

        if new_role not in AccountTypes.values:
            return Response({"message": f"Rôle invalide; choisissez-en un parmi {list(AccountTypes.values)}"},
                            status=status.HTTP_400_BAD_REQUEST)

        # 3) Find target user & account
        try:
            target_user = User.objects.get(id=account_id)
            target_account = target_user.account
        except User.DoesNotExist:
            return Response({"message": "Compte non trouvé."}, status=status.HTTP_404_NOT_FOUND)
        except Account.DoesNotExist:
            return Response({"message": "Compte associé introuvable."}, status=status.HTTP_404_NOT_FOUND)

        old_role = target_account.role

        if old_role == new_role:
            return Response({"message": "Le rôle est déjà défini sur la valeur demandée.",
                             "account_id": target_user.id,
                             "role": old_role},
                            status=status.HTTP_200_OK)

        # 4) Perform role update inside a transaction and create notification record
        try:
            with transaction.atomic():
                # Update user flags for admin role (if you want admin users to have staff/superuser)
                if new_role == AccountTypes.ADMIN:
                    target_user.is_staff = True
                    target_user.is_superuser = True
                else:
                    # if demoting from admin, remove admin privileges
                    target_user.is_staff = False
                    target_user.is_superuser = False
                target_user.save(update_fields=["is_staff", "is_superuser"])

                # Update account role
                target_account.role = new_role
                # update timestamp updated_at if present on model
                try:
                    target_account.save(update_fields=["role", "updated_at"])
                except Exception:
                    # fallback if updated_at is auto_now and can't be updated_fields
                    target_account.save()

                # Build notification content (French)
                actor_name = user.username
                human_old = old_role
                human_new = new_role
                # Optionally map to friendly labels if you have them
                title = "Modification de votre rôle"
                content = (
                    f"Bonjour {target_user.username},\n\n"
                    f"Votre rôle sur VeYoo a été modifié.\n\n"
                    f"Ancien rôle : {human_old}\n"
                    f"Nouveau rôle : {human_new}\n\n"
                    f"Action réalisée par : {actor_name} le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                    "Si vous pensez qu'il s'agit d'une erreur, veuillez contacter un administrateur."
                )

                notification = create_notification(
                    title=title,
                    content=content,
                    recipient=target_user,
                    notification_date=timezone.localdate(),
                    notification_time=timezone.localtime().time()
                )
                # transaction ends here: account update + notification creation are committed together
        except:
            return Response({"message": "Échec lors de la modification du rôle du compte."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 5) Send email (do this *after* transaction commit). Don't fail response if email send fails.
        try:
            send_result = send_notification_email(notification=notification)
        except Exception as exc_send:
           pass

        # 6) Return success
        return Response({
            "message": f"Rôle du compte modifié avec succès ({old_role} → {new_role}).",
            "account_id": target_user.id,
            "old_role": old_role,
            "new_role": new_role
        }, status=status.HTTP_200_OK)


# Delete account endpoint

class DeleteAccountAPIView(APIView):
    permission_classes = [IsAdminUser ,IsAuthenticated]

    def delete(self, request, pk):
        # Check if account exists
        try:
            account = User.objects.get(pk=pk)
            name = account.username
        except User.DoesNotExist:
            return Response({"message": f"Le compte n'existe pas."}, status=status.HTTP_404_NOT_FOUND)
        

        admin_name = request.user.username
        notif_title = "Suppression de votre compte VeYoo"
        notif_content = (
            f"Bonjour {name},\n\n"
            f"Votre compte sur la plateforme VeYoo a été supprimé par l'administrateur {admin_name} le "
            f"{timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
            "Si vous pensez qu'il s'agit d'une erreur, veuillez contacter votre administrateur."
        )

        try:
            # create_notification will create a Notification record (and will raise on error)
            notification = create_notification(
                title=notif_title,
                content=notif_content,
                recipient=account,
                notification_date=timezone.localdate(),
                notification_time=timezone.localtime().time()
            )
        except :
            return Response({"message": "Échec lors de la création de la notification."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # send the email (send_notification_email will attempt to send and return {"ok": True/False, ...})
        try:
            send_result = send_notification_email(notification=notification)
            if not send_result.get("ok"):
                return Response({"message": "Échec lors de l'envoi de l'email de notification."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as exc_send:
            return Response({"message": "Échec lors de l'envoi de l'email de notification."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # Delete user and account
        try:
            account.delete()
            return Response({"message": f"Le compte avec le nom {name} a été supprimé."}, status=status.HTTP_200_OK)
        except:
            return Response({"message": f"Échec de la suppression du compte"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    


# get profile picture en base64        
def ProfilePicture(account):
        profile_pic_base64 = None
        if account.profile_picture and hasattr(account.profile_picture, 'read'):
            try:
                image_data = account.profile_picture.read()
                profile_pic_base64 = base64.b64encode(image_data).decode('utf-8')
            except Exception:
                profile_pic_base64 = None
        return  profile_pic_base64 
      
class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            account = Account.objects.get(user=user)
        except Account.DoesNotExist:
            return Response({"message": "Associated account not found."}, status=status.HTTP_404_NOT_FOUND)
        

        # Manual user data response
        data = {
            "message": "Profil utilisateur récupéré avec succès.",
            "user": {
                "id": user.pk,
                "fullname": user.username,
                "email": user.email,
                "whatsapp_number": account.whatsapp_number,
                "role": account.role,
                "status": account.status,
                "registration_date": account.registration_date.strftime('%d/%m/%Y') if account.registration_date else None,
                "last_login": user.last_login.strftime('%d/%m/%Y à %H:%M:%S') if user.last_login else None,
                "profile_photo_base64": ProfilePicture(account)
            }
        }

        return Response(data, status=status.HTTP_200_OK)
# my profile
class MyProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        try:
            user = User.objects.get(id=user.id)
        except User.DoesNotExist:
            
            return Response({"message": "Utilisateur introuvable."}, status=status.HTTP_404_NOT_FOUND)

        try:
            account = Account.objects.get(user=user)
        except Account.DoesNotExist:
            return Response({"message": "Compte associé introuvable."}, status=status.HTTP_404_NOT_FOUND)
        

        # Manual user data response
        data = {
            "message": "Profil utilisateur récupéré avec succès.",
            "user": {
                "id": user.pk,
                "fullname": user.username,
                "email": user.email,
                "email_verified":account.email_verified,
                "whatsapp_number": account.whatsapp_number,
                "role": account.role,
                "status": account.status,
                "registration_date": account.registration_date.strftime('%d/%m/%Y') if account.registration_date else None,
                "last_login": user.last_login.strftime('%d/%m/%Y à %H:%M:%S') if user.last_login else None,
                "profile_photo_base64": ProfilePicture(account),
                "created_at":account.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at":account.updated_at.strftime("%Y-%m-%d %H:%M")
            }
        }

        return Response(data, status=status.HTTP_200_OK)
# update my profile endpoint
class UpdateMyProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  

    def put(self, request):
        
        # Get token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return Response({"message": "En-tête d'autorisation manquant ou invalide."},
                            status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(" ")[1]
        try:
            validated_token = JWTAuthentication().get_validated_token(token)
            user_id = validated_token.get("user_id")
        except (InvalidToken, TokenError):
            return Response({"message": "Token invalide."}, status=status.HTTP_401_UNAUTHORIZED)


        try:
            
            user = User.objects.get(id=user_id)
            account = user.account
        except Account.DoesNotExist:
            return Response({"message": "Compte introuvable."}, status=status.HTTP_404_NOT_FOUND)

        # Update fullname from User model
        fullname = request.data.get("fullname")
        if fullname:
            user.username = fullname
            user.save()
        #update email 
        email =  request.data.get("email")
        if email:
            user.email = email
            user.save()
        # Update Account fields
        whatsapp_number = request.data.get("whatsapp_number")
        if whatsapp_number is not None:
            account.whatsapp_number = whatsapp_number

        if 'profile_picture' in request.FILES:
            account.profile_picture = request.FILES['profile_picture']
        
        account.save()

        return Response({
            "message": "Profil mis à jour avec succès.",
            "profile": {
                "fullname": user.username,
                "email": user.email,
                "whatsapp_number": account.whatsapp_number,
                "role": account.role,
                "status": account.status,
            }
        }, status=status.HTTP_200_OK)  
# get photo of material
def get_base64_image(material):
        photo_base64 = None
        if material.photo and hasattr(material.photo, 'read'):
            try:
                image_data = material.photo.read()
                photo_base64 = base64.b64encode(image_data).decode('utf-8')
            except Exception:
                photo_base64 = None
        return  photo_base64 


class MaterialListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # 1) grab all materials
        all_mats = Material.objects.select_related('vehicle', 'tool').all()
        if not all_mats.exists():
            return Response(
                {"message": "Il n'y a pas encore de matériaux."},
                status=status.HTTP_200_OK
            )

        # 2) separate vehicles vs tools
        vehicles = []
        tools    = []

        for mat in all_mats:
            # vehicle?
            if hasattr(mat, 'vehicle'):
                v = mat.vehicle
                vehicles.append({
                    "id":                mat.id,
                    "name":              mat.name,
                    "type":              mat.get_type_display(),
                    "status":            mat.get_status_display(),
                    "reservationStatus": mat.get_reservationStatus_display(),
                    "license_plate":     v.license_plate,
                    "brand":             v.brand,
                    "model":             v.model,
                    "year_of_manufacture": v.year_of_manufacture,
                    "color":             v.color,
                    "current_mileage":   v.current_mileage,
                    "fuel_level":        v.fuel_level,
                    "oil_level":         v.oil_level,
                    "tire_status":       v.get_tire_status_display(),
                    "body_condition":    v.get_body_condition_display(),
                    "engine_status":     v.get_engine_status_display(),
                    "fuel_type":         v.get_fuel_type_display(),
                    "location":          v.location,
                })

            # tool?
            if hasattr(mat, 'tool'):
                t = mat.tool
                tools.append({
                    "id":                mat.id,
                    "name":              mat.name,
                    "type":              mat.get_type_display(),
                    "status":            mat.get_status_display(),
                    "reservationStatus": mat.get_reservationStatus_display(),
                    "serial_number":     t.serial_number,
                    "manufacturer":      t.manufacturer,
                    "purchase_date":     t.purchase_date,
                    "warranty_expiry":   t.warranty_expiry,
                })

        # 3) build response or empty–state messages
        if not vehicles and not tools:
            return Response(
                {"message": "Il n'y a pas encore de matériaux."},
                status=status.HTTP_200_OK
            )

        payload = {
            "vehicles": vehicles if vehicles else "Il n'y a pas de véhicules.",
            "tools":    tools    if tools    else "Il n'y a pas d'outils.",
        }
        return Response(payload, status=status.HTTP_200_OK)
# vehicles management endpoint

# create new vehicle
class CreateVehicleAPIView(APIView):
    permission_classes= [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        # 1) auth and permission
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response

        data = request.data
        # 3) required fields
        required = ["name","license_plate","model","brand"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return Response({"message": f"Champs manquants : {', '.join(missing)}"},
                            status=status.HTTP_400_BAD_REQUEST)
        # Status
        ms = data.get("status", MaterialStatus.GOOD)
        if ms not in MaterialStatus.values:
            return Response(
                {"message": f"Statut de matériel invalide '{ms}'. Doit être l'un des{list(MaterialStatus.values)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # tire_status
        ts = data.get("tire_status", TireStatus.NEW)
        if ts not in TireStatus.values:
            return Response(
                {"message": f"Statut de pneu invalide '{ts}'. Doit être l'un de {list(TireStatus.values)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # body_condition
        bc = data.get("body_condition", BodyCondition.GOOD)
        if bc not in BodyCondition.values:
            return Response(
                {"message": f"Condition corporelle invalide '{bc}'. Doit être l'un de {list(BodyCondition.values)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # engine_status
        es = data.get("engine_status", EngineStatus.GOOD)
        if es not in EngineStatus.values:
            return Response(
                {"message": f"Statut du moteur invalide '{es}'. Doit être l'un des {list(EngineStatus.values)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # fuel_type
        ft = data.get("fuelType", FuelType.DIESEL)
        if ft not in FuelType.values:
            return Response(
                {"message": f"Type de carburant invalide '{ft}'. Doit être l'un des {list(FuelType.values)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # photo of vehicle 
        photo_file = data.get("photo")
        
        # location of vehicle
        lc = data.get("location")
        if not lc :
            lc = None
        # vehicle color
        col = data.get("color") 
        if not col :
            col = None 
        # 5) create Material
        mat = Material.objects.create(
            name=data["name"],
            type=MaterialType.VEHICLE,
            status=ms,
            is_active=True,
            photo=photo_file if photo_file else None,
            last_maintenance_date=parse_date(data.get("last_maintenance_date")) if data.get("last_maintenance_date") else None,
            inspection_due_date=parse_date(data.get("inspection_due_date")) if data.get("inspection_due_date") else None,
        )

        # 6) create Vehicle
        vehicle_obj = Vehicle.objects.create(
            material=mat,
            license_plate=data["license_plate"],
            model=data["model"],
            brand=data["brand"],
            year_of_manufacture=int(data.get("year_of_manufacture", 0)),
            color= col,
            current_mileage=int(data.get("current_mileage",0)),
            fuel_level=int(data.get("fuel_level",0)),
            oil_level=int(data.get("oil_level",0)),
            tire_status=ts,
            body_condition=bc,
            engine_status=es,
            fuel_type=ft,
            location=lc,
        )

        return Response({
            "message": "Véhicule créé avec succès.",
            "material_id": mat.id,
            "vehicle_id": vehicle_obj.id,
            "license_plate": vehicle_obj.license_plate
        }, status=status.HTTP_200_OK) 


class VehicleListAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        vehicles = Vehicle.objects.select_related('material').all()
        
         # Count summary
        total = vehicles.count()
        good = vehicles.filter(material__status=MaterialStatus.GOOD).count()
        under_maintenance = vehicles.filter(material__status=MaterialStatus.UNDER_MAINTENANCE).count()
        pending_maintenance = vehicles.filter(material__status=MaterialStatus.PENDING_MAINTENANCE).count()

        if not vehicles.exists():
            return Response({ "counts": {
                "total": total,
                "good": good,
                "under_maintenance": under_maintenance,
                "pending_maintenance": pending_maintenance,
            },
            "message": "Il n'y a pas de véhicule"}, status=status.HTTP_404_NOT_FOUND)

        vehicle_list = []
        for vehicle in vehicles:
            material = vehicle.material

            

            vehicle_list.append({
                "id": vehicle.id,
                "material_id":material.id,
                "name": material.name,
                "category": material.category,
                "description": material.description,
                "status": material.status,
                "type": material.type,
                "reservation_status": material.reservationStatus,
                "last_maintenance_date": str(material.last_maintenance_date) if material.last_maintenance_date else None,
                "inspection_due_date": str(material.inspection_due_date) if material.inspection_due_date else None,
                "photo_base64": get_base64_image(material),
                "created_at": material.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at": material.updated_at.strftime("%Y-%m-%d %H:%M"),

                "license_plate": vehicle.license_plate,
                "brand": vehicle.brand,
                "model": vehicle.model,
                "year_of_manufacture": vehicle.year_of_manufacture,
                "color": vehicle.color,
                "current_mileage": vehicle.current_mileage,
                "fuel_level": vehicle.fuel_level,
                "oil_level": vehicle.oil_level,
                "tire_status": vehicle.tire_status,
                "body_condition": vehicle.body_condition,
                "engine_status": vehicle.engine_status,
                "fuel_type": vehicle.fuel_type,
                "location": vehicle.location,
            })

       

        return Response({
         
            "counts": {
                "total": total,
                "good": good,
                "under_maintenance": under_maintenance,
                "pending_maintenance": pending_maintenance,
            },
               "vehicles": vehicle_list
        },
         status=status.HTTP_200_OK)

class VehicleDetailView(APIView):
    permission_classes = [IsAuthenticated]
   
    def get(self, request, vehicle_id):
        try:
            vehicle = Vehicle.objects.get(id=vehicle_id)
            material= vehicle.material
            data = {
                "id": vehicle.id,
                "material_id":material.id,
                "name": material.name,
                "category": material.category,
                "description": material.description,
                "status": material.status,
                "type": material.type,
                "reservation_status": material.reservationStatus,
                "last_maintenance_date": str(material.last_maintenance_date) if material.last_maintenance_date else None,
                "inspection_due_date": str(material.inspection_due_date) if material.inspection_due_date else None,
                "photo_base64": get_base64_image(material),
                "material_id": vehicle.material.id,
                "license_plate": vehicle.license_plate,
                "brand": vehicle.brand,
                "model": vehicle.model,
                "year_of_manufacture": vehicle.year_of_manufacture,
                "color": vehicle.color,
                "current_mileage": vehicle.current_mileage,
                "fuel_level": vehicle.fuel_level,
                "oil_level": vehicle.oil_level,
                "tire_status": vehicle.tire_status,
                "body_condition": vehicle.body_condition,
                "engine_status": vehicle.engine_status,
                "fuel_type": vehicle.fuel_type,
                "location": vehicle.location,
            }
            return Response(data, status=status.HTTP_200_OK)
        except Vehicle.DoesNotExist:
            return Response(
                {"error": "Le véhicule avec cet identifiant n'existe pas."},
                status=status.HTTP_404_NOT_FOUND
            )
# update vehicles data
class UpdateVehicleAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def put(self, request, vehicle_id):
        # 1) auth and permission
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response
       
        # 2) fetch the vehicle & its material
        try:
            veh = Vehicle.objects.get(id=vehicle_id)
            mat = veh.material
        except Vehicle.DoesNotExist:
            return Response({"message": "Véhicule non trouvé."},
                            status=status.HTTP_404_NOT_FOUND)

        data = request.data

        # 3) helper to validate any choice‐field
        def validate_choice(key, enum_cls):
            val = data.get(key)
            if val is not None and val not in enum_cls.values:
                return f"Clé invalide {key} : '{val}'. Doit être l'un de {enum_cls.values}"
            return None

        # validate all choices
        for key, enum in [
            ("status", MaterialStatus),
            ("reservationStatus", MaterialReservationStatus),
            ("tire_status", TireStatus),
            ("body_condition", BodyCondition),
            ("engine_status", EngineStatus),
            ("fuelType", FuelType),
        ]:
            err = validate_choice(key, enum)
            if err:
                return Response({"message": err}, status=status.HTTP_400_BAD_REQUEST)

        # 4) update Material fields if provided
        if "name" in data:
            mat.name = data["name"].strip()
        if "status" in data:
            mat.status = data["status"]
        if "reservationStatus" in data:
            mat.reservationStatus = data["reservationStatus"]
        if "description" in data:
            mat.description = data["description"] or None
        if "category" in data:
            mat.category = data["category"] or ""
        if "photo" in data:
            mat.photo = data["photo"] or None
        for date_field in ("last_maintenance_date", "inspection_due_date"):
            if date_field in data:
                val = data[date_field]
                mat.__setattr__(date_field, parse_date(val) if val else None)

        mat.save()

        # 5) update Vehicle fields if provided
        if "license_plate" in data:
            veh.license_plate = data["license_plate"].strip()
        if "model" in data:
            veh.model = data["model"].strip()
        if "brand" in data:
            veh.brand = data["brand"].strip()
        if "year_of_manufacture" in data:
            veh.year_of_manufacture = int(data["year_of_manufacture"])
        if "color" in data:
            veh.color = data["color"]
        if "current_mileage" in data:
            veh.current_mileage = int(data["current_mileage"])
        if "fuel_level" in data:
            veh.fuel_level = int(data["fuel_level"])
        if "oil_level" in data:
            veh.oil_level = int(data["oil_level"])
        if "tire_status" in data:
            veh.tire_status = data["tire_status"]
        if "body_condition" in data:
            veh.body_condition = data["body_condition"]
        if "engine_status" in data:
            veh.engine_status = data["engine_status"]
        if "fuelType" in data:
            veh.fuel_type = data["fuelType"]
        if "location" in data:
            veh.location = data["location"] or ""

        veh.save()

        return Response({
            "message": "Véhicule mis à jour avec succès",
            "vehicle_id": veh.id
        }, status=status.HTTP_200_OK)
    
# tools management endpoint url
# Create Tool
class CreateToolAPIView(APIView):
    permission_classes= [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    def post(self, request):
         # 1) auth and permission
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response
        data = request.data

        # 1. Validate required fields
        required_fields = ["name", "category", "manufacturer"]
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return Response(
                {"error": f"Champs requis manquants: {', '.join(missing_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 2. Validate status
        status_value = data.get("status")
        if status_value not in MaterialStatus.values:
            return Response(
                {"error": f"Statut invalide: {status_value}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3. Create Material
        mat = Material.objects.create(
            name=data["name"],
            type=MaterialType.TOOL,
            status=status_value,
            description=data.get("description") or None,
            category=data.get("category") or None,
            is_active=True,
            photo=data.get("photo") or None,
            last_maintenance_date=parse_date(data.get("last_maintenance_date")) if data.get("last_maintenance_date") else None,
            inspection_due_date=parse_date(data.get("inspection_due_date")) if data.get("inspection_due_date") else None,
        )

        # 4. Create Tool
        Tool.objects.create(
            material=mat,
            serial_number=data.get("serial_number") or None,
            manufacturer=data.get("manufacturer"),
            purchase_date=parse_date(data.get("purchase_date")) if data.get("purchase_date") else None,
            warranty_expiry=parse_date(data.get("warranty_expiry")) if data.get("warranty_expiry") else None,
        )

        return Response({"message": "Outil ajouté avec succès"}, status=status.HTTP_200_OK) 

# list of all tools 
class ToolListAPIView(APIView):
    permission_classes = [IsAuthenticated]
  
    def get(self, request):
        tools = Tool.objects.select_related('material').all()
        
        total = tools.count()
        good = 0
        under_maintenance = 0
        pending_maintenance = 0

        if not tools.exists():
            return Response({ 
                "summary": {
                "total_tools": total,
                "good": good,
                "under_maintenance": under_maintenance,
                "pending_maintenance": pending_maintenance,
            },
            "message": "Il n'y a pas d'outil"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        
        tool_list = []
        for tool in tools:

            material = tool.material

            # Count status
            if material.status == "good":
                good += 1
            elif material.status == "under_maintenance":
                under_maintenance += 1
            elif material.status == "pending_maintenance":
                pending_maintenance += 1

            tool_list.append({
                "id": tool.id,
                "material_id":material.id,
                "name": material.name,
                "category": material.category,
                "manufacturer": tool.manufacturer,
                "serial_number": tool.serial_number,
                "status": material.status,
                "reservation_status": material.reservationStatus,
                "description": material.description,
                "purchase_date": str(tool.purchase_date) if tool.purchase_date else None,
                "warranty_expiry": str(tool.warranty_expiry) if tool.warranty_expiry else None,
                "last_maintenance_date": str(material.last_maintenance_date) if material.last_maintenance_date else None,
                "inspection_due_date": str(material.inspection_due_date) if material.inspection_due_date else None,
                   
                "photo_base64": get_base64_image(material),
            })

        return Response({
            "summary": {
                "total_tools": total,
                "good": good,
                "under_maintenance": under_maintenance,
                "pending_maintenance": pending_maintenance,
            },
            "tools": tool_list
        }, status=status.HTTP_200_OK) 

class ToolDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, tool_id):
        try:
            tool = Tool.objects.get(id=tool_id)
            material= tool.material
            data = {
               "id": tool.id,
                "material_id":material.id,
                "name": material.name,
                "category": material.category,
                "manufacturer": tool.manufacturer,
                "serial_number": tool.serial_number,
                "status": material.status,
                "description": material.description,
                "purchase_date": str(tool.purchase_date) if tool.purchase_date else None,
                "warranty_expiry": str(tool.warranty_expiry) if tool.warranty_expiry else None,
                "last_maintenance_date": str(material.last_maintenance_date) if material.last_maintenance_date else None,
                "inspection_due_date": str(material.inspection_due_date) if material.inspection_due_date else None,
                   
                "photo_base64": get_base64_image(material),
            }
            return Response(data, status=status.HTTP_200_OK)
        except Material.DoesNotExist:
            return Response(
                {"error": "L'outil avec cet ID n'existe pas."},
                status=status.HTTP_404_NOT_FOUND
            )
        
# update tool detail
class UpdateToolAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, tool_id):
        # auth & permission
        user, error = authenticate_and_authorize(request)
        if error:
            return error

        # fetch material + tool
        try:
            tool = Tool.objects.get(id=tool_id)
        except Material.DoesNotExist:
            return Response(
                {"message": f"Outil avec l'identifiant={tool_id} non trouvé ou ce n'est pas un outil."},
                status=status.HTTP_404_NOT_FOUND)
        try:
            mat = tool.material
        except Tool.DoesNotExist:
            return Response({"message":"Matériel non trouvé."},
                            status=status.HTTP_404_NOT_FOUND)

        data = request.data

        # required
        for fld in ("name","category","manufacturer","status"):
            if not data.get(fld):
                return Response({"message":f"Champ requis manquant : {fld}"},
                                status=status.HTTP_400_BAD_REQUEST)

        # validate MaterialStatus
        ms = data.get("status")
        if ms not in MaterialStatus.values:
            return Response({"message":f"Statut invalide '{ms}'."},
                            status=status.HTTP_400_BAD_REQUEST)

        # validate reservationStatus if provided
        rs = data.get("reservationStatus", mat.reservationStatus)
        if rs not in MaterialReservationStatus.values:
            return Response({"message":f"État de réservation invalide'{rs}'."},
                            status=status.HTTP_400_BAD_REQUEST)

        # update Material
        mat.name                = data["name"]
        mat.category            = data["category"] or ""
        mat.description         = data.get("description") or None
        mat.status              = ms
        mat.reservationStatus   = rs
        # dates
        if data.get("last_maintenance_date"):
            mat.last_maintenance_date = parse_date(data["last_maintenance_date"])
        if data.get("inspection_due_date"):
            mat.inspection_due_date   = parse_date(data["inspection_due_date"])
        # photo
        if "photo" in request.FILES:
            mat.photo.delete()
            mat.photo = request.FILES["photo"]
        mat.save()

        # update Tool
        tool.manufacturer   = data["manufacturer"]
        tool.serial_number  = data.get("serial_number") or None
        if data.get("purchase_date"):
            tool.purchase_date   = parse_date(data["purchase_date"])
        if data.get("warranty_expiry"):
            tool.warranty_expiry = parse_date(data["warranty_expiry"])
        tool.save()

        return Response({"message":f"Outil '{mat.name}' mis à jour avec succès."},
                        status=status.HTTP_200_OK)

# Material management
# delete a Material
class DeleteMaterialAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, material_id):
        # 1) auth and permission
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response
        
        
        try:
            material = Material.objects.get(id=material_id)
        except Material.DoesNotExist:
            return Response(
                {"message": "Matériel non trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )

        type_display = material.type
        name = material.name
        material.delete()

        return Response(
            {"message": f"{type_display} {name} supprimé avec succès."},
            status=status.HTTP_200_OK
        )  

# Malfunctions management 
class CreateMalfunctionAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        # 1) authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response

        # 2) required fields
        data = request.data
        required = ["material_id", "description", "severity", "status"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return Response(
                {"message": f"Champs manquants : {', '.join(missing)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3) look up material
        try:
            mat = Material.objects.get(id=data["material_id"])
        except Material.DoesNotExist:
            return Response(
                {"message": f"Le matériel avec l'identifiant={data['material_id']} n'a pas été trouvé."},
                status=status.HTTP_404_NOT_FOUND
    )

        # 4) prevent duplicate open malfunction
        if Malfunction.objects.filter(material=mat).exists():
            return Response(
                {"message": "Un dysfonctionnement existe déjà pour ce matériau."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 5) validate severity & status
        sev = data["severity"]
        if sev not in SeverityLevel.values:
            return Response(
                {"message": f"Gravité invalide'{sev}'."},
                status=status.HTTP_400_BAD_REQUEST
            )
        st = data["status"]
        if st not in MalfunctionStatus.values:
            return Response(
                {"message": f"Statut invalide '{st}'."},
                status=status.HTTP_400_BAD_REQUEST
            )
        # 6) optional fields
        notes  = data.get("notes") or None
               
        with transaction.atomic():
                try:
                    # 6a) delete existing reservations for this material (if any)
                    reservations_qs = Reservation.objects.filter(material=mat).all()
                    reservations_count = reservations_qs.count()
                    if reservations_count > 0:
                        # count prechecks for info (optional)
                        prechecks = PreCheck.objects.filter(reservation__material=mat).all()
                        if prechecks:
                            prechecks.delete()
                        reservations_qs.delete()
                except:
                          return Response( {"message": f"problèmes lors de la suppression des réservations existantes."}, status=status.HTTP_400_BAD_REQUEST)  
        # 7) create
        m = Malfunction.objects.create(
            material       = mat,
            description    = data["description"],
            severity       = sev,
            status         = st,
            reported_by    = user,
            declared_date  = timezone.now().date(),
            declared_time  = timezone.now().time(),
            notes          = notes,
        )
        # 8) Handle uploaded photos (can be multiple)
        try:
            uploaded_files = request.FILES.getlist("photos")
            for image_file in uploaded_files:
                if image_file:
                    MalfunctionPhoto.objects.create(
                        malfunction=m,
                        photo=image_file
                    )
        except:
            # Delete the malfunction record if photo saving fails (optional cleanup)
            m.delete()
            return Response(
                {"message": f"Échec de l'upload des photo(s)"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        try:
             # 9) Update material & reservation statuses
           
            if st == MalfunctionStatus.IN_PROGRESS:
                mat.status = MaterialStatus.UNDER_MAINTENANCE
            else : 
                mat.status = MaterialStatus.PENDING_MAINTENANCE

            mat.reservationStatus = MaterialReservationStatus.NOT_AVAILABLE  # means not available
            mat.save(update_fields=["status", "reservationStatus"])
        except :
                # Delete the malfunction record if photo saving fails (optional cleanup)
                m.delete()
                return Response(
                {"message": f"Échec de l'upload de la défaillance"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        notified = 0
        reporter_role = ""
        try:
            reporter_account = user.account
            if reporter_account and getattr(reporter_account, "role", None):
                reporter_role = str(reporter_account.role)
            else:
                # fallback: mark 'utilisateur'
                reporter_role = "manager"
        except Exception:
            reporter_role = "manager"

        recipients_qs = None
        try:
            # try Account-based roles
            recipients_qs = Account.objects.all()
        except Exception:
            recipients_qs = None

       
        recipients = recipients_qs.distinct().exclude(user__email__isnull=True).exclude(user__email__exact="")    

        for recipient in recipients:
            try:
                admin_tag = (
                    f"{user.get_full_name() or user.username} ({reporter_role})"
                )

                title_fr = f"Nouveau dysfonctionnement signalé: {mat.name}"
                content_fr = (
                    f"Bonjour {recipient.user.username},\n\n"
                    f"Un nouveau dysfonctionnement a été signalé sur le matériel \"{mat.name}\".\n\n"
                    f"Détails :\n"
                    f"- Matériel: {mat.name}\n"
                    f"- Gravité: {sev}\n"
                    f"- Statut du dysfonctionnement: {st}\n"
                    f"- Signalé par: {user.username} ({reporter_role})\n"
                    f"- Date/Heure: {timezone.localtime().strftime('%d %B %Y à %H:%M')}\n\n"
                    f"Description:\n{m.description}\n\n"
                    "Veuillez consulter la liste des pannes pour plus de détails."
                )

                # create notification record
                notif = create_notification(
                    title=title_fr,
                    content=content_fr,
                    recipient=recipient.user,
                    notification_date=timezone.localdate(),
                    notification_time=timezone.localtime().time()
                )

                # attempt to send email (best-effort)
                send_result = send_notification_email(notification=notif)
                if send_result.get("ok"):
                    notified += 1
            except :
                 Response(
                        {"message": "Error leur l'evcoie de notifications "},
                        status=status.HTTP_200_OK
                    )      


        return Response(
            {"message": "Défaillance signalée avec succès.", "id": m.id},
            status=status.HTTP_200_OK
        )    
 

# Material Malfunction List
class MaterialMalfunctionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        materials = Material.objects.prefetch_related(
            Prefetch(
                'malfunction_set',
                queryset=Malfunction.objects.all(),
                to_attr='malfunctions'
            )
        ).filter(malfunction__isnull=False).distinct()
         # Summary counts
        summary = {
            "total_malfunctions": 0,
            "Reported": 0,
            "In Progress": 0,
            "Resolved": 0
        }

        if not materials.exists():
            return Response(
                {"summary": summary, 
                 "message": "Aucune anomalie trouvée pour aucun matériau."},
                status=status.HTTP_404_NOT_FOUND
            )

       

        material_data = []
        for material in materials:
            malfunctions_list = []
            for m in material.malfunctions:
                # Update summary counts
                summary["total_malfunctions"] += 1
                if m.status in summary:
                    summary[m.status] += 1
                
                photos = MalfunctionPhoto.objects.filter(malfunction=m)
                if photos:
                      base64_photos = [get_base64_image(photo) for photo in photos]
                else :
                    base64_photos = None

                malfunctions_list.append({
                    "id": m.id,
                    "description": m.description,
                    "severity": m.severity,
                    "status": m.status,
                    "reported_by": m.reported_by.username,
                    "notes": m.notes,
                    "created_at": m.created_at.strftime("%Y-%m-%d %H:%M"),
                     "photos": base64_photos
                })

            material_data.append({
                "id": material.id,
                "photo":get_base64_image(material),
                "name": material.name,
                "type": material.type,
                "last_maintenance_date": material.last_maintenance_date,
                "inspection_due_date":material.inspection_due_date,
                "status": material.status,
                "malfunctions": malfunctions_list
            })

        return Response({
            "summary": summary,
            "materials": material_data
        }, status=status.HTTP_200_OK)


class MalfunctionDetailView(APIView):
    permission_classes = [IsAuthenticated]
   
    def get(self, request, malfunction_id):
        try:
            malfunction = Malfunction.objects.get(id=malfunction_id)
        except Malfunction.DoesNotExist:
            return Response(
                {"message": f"Aucune anomalie trouvée avec l'ID {malfunction_id}"},
                status=status.HTTP_404_NOT_FOUND
            )

        photos = MalfunctionPhoto.objects.filter(malfunction=malfunction)
        if photos:
           base64_photos = [get_base64_image(photo) for photo in photos]
        else :
            base64_photos = None  

        data = {
            "id": malfunction.id,
            "material": {
                "id": malfunction.material.id,
                "name": malfunction.material.name,
                "type": malfunction.material.type,
                "status": malfunction.material.status,
            },
            "description": malfunction.description,
            "severity": malfunction.severity,
            "status": malfunction.status,
            "reported_by": malfunction.reported_by.username,
            "notes": malfunction.notes,
            "created_at": malfunction.created_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at": malfunction.updated_at.strftime("%Y-%m-%d %H:%M"),
            "photos": base64_photos 
        }

        return Response(data, status=status.HTTP_200_OK) 


# Delete a Malfunction
class MalfunctionDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, malfunction_id):
         # 1) auth and permission
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response
        
        try:
            malfunction = Malfunction.objects.get(id=malfunction_id)
        except Malfunction.DoesNotExist:
            return Response(
                {"error": f"Aucune anomalie trouvée avec l'ID {malfunction_id}"},
                status=status.HTTP_404_NOT_FOUND
            )
        mat = malfunction.material
        try :
            mat.status = MaterialStatus.GOOD
            mat.reservationStatus = MaterialReservationStatus.AVAILABLE  # means not available
            mat.save(update_fields=["status", "reservationStatus"])
        except :
                return Response(
                {"message": f"Échec de la mise à jour du statut"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        photos = MalfunctionPhoto.objects.filter(malfunction = malfunction).all()
        if photos:
           [ph.photo.delete() for ph in photos]
        malfunction.delete()
        return Response(
            {"message": f"La défaillance avec l'ID {malfunction_id} a été supprimée avec succès."},
            status=status.HTTP_200_OK
        )  

# update malfunction

class MalfunctionUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, malfunction_id):
        # 1) authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response

        try:
            malfunction = Malfunction.objects.get(id=malfunction_id)
        except Malfunction.DoesNotExist:
            return Response({"message": "Défaillance non trouvée."}, status=status.HTTP_404_NOT_FOUND)
        # 2) required fields
        data = request.data
          # 5) validate severity & status
        sev = data["severity"]
        if sev not in SeverityLevel.values:
            return Response(
                {"message": f"Gravité invalide'{sev}'."},
                status=status.HTTP_400_BAD_REQUEST
            )
        st = data["status"]
        if st not in MalfunctionStatus.values:
            return Response(
                {"message": f"Statut invalide'{st}'."},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Update fields
        des = data["description"]
        if des :
           malfunction.description =  des
        if sev:   
           malfunction.severity = sev
        if st:
          malfunction.status = st

        malfunction.reported_by = user  # assuming the current user is the reporter
        nts = request.data.get("notes")
        if nts:
             malfunction.notes = nts

        # Update material if changed
        material_id = request.data.get("materialId")
        try:
            material = Material.objects.get(id=material_id)
            malfunction.material = material
        except Material.DoesNotExist:
            return Response({"message": "Identifiant de matériel invalide."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            material.reservationStatus = MaterialReservationStatus.NOT_AVAILABLE
            if st == MalfunctionStatus.IN_PROGRESS:
                material.status = MaterialStatus.UNDER_MAINTENANCE
            elif st == MalfunctionStatus.REPORTED : 
                material.status = MaterialStatus.PENDING_MAINTENANCE
            else: 
                material.status = MaterialStatus.GOOD
                material.reservationStatus = MaterialReservationStatus.AVAILABLE
            material.save(update_fields=["status", "reservationStatus"])        
        except:
                malfunction.delete()
                return Response(
                {"message": f"Échec de mise à joure de la défaillance"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        malfunction.save()

        # Add new uploaded photos and delete the old once
        new_photos = request.FILES.getlist("photos")
        if not new_photos:
            photos = MalfunctionPhoto.objects.filter(malfunction = malfunction).all()
            if photos:
                [ph.photo.delete() for ph in photos]
        if new_photos:
            for image_file in new_photos:
                if image_file :
                    MalfunctionPhoto.objects.create(malfunction=malfunction, photo=image_file)

        return Response({"message": "Le dysfonctionnement a été mis à jour avec succès."}, status=200)  


# Advertisement management

class CreateAdvertisementView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # 1) authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response
        
        data = request.data
         
        # Validate required fields
        required_fields = ['title', 'content', 'startDate', 'endDate']
        missing = [field for field in required_fields if not data.get(field)]
        if missing:
            return Response({"message": f"Champs manquants : {', '.join(missing)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate content length
        if len(data.get('content', '')) < 20:
            return Response({"message": "Le contenu doit contenir au moins 20 caractères."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate startDate < endDate
        if data['startDate'] > data['endDate']:
            return Response({"message": "La date de fin doit être après la date de début."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate priority value
        priority_value = data.get('priority', PriorityLevel.MEDIUM)
        if priority_value not in PriorityLevel.values:
            return Response({"message": f"Priorité invalide : {priority_value}"}, status=400)
        
        # Create the advertisement
        advertisement = Advertisement(
            title=data['title'],
            content=data['content'],
            priority=priority_value,
            start_date=data['startDate'],
            end_date=data['endDate'],
            created_by=user,
        )

        # Handle file uploads (optional)
        if 'coverFile' in request.FILES:
            advertisement.cover = request.FILES['coverFile']
        if 'pdfFile' in request.FILES:
            advertisement.pdf = request.FILES['pdfFile']

        advertisement.save()

        return Response({
            "message": "Annonce créée avec succès",
            "id": advertisement.id
        }, status=status.HTTP_200_OK)  

# list of advertisement
class AdvertisementListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ads = Advertisement.objects.all()

        if ads:
            today = timezone.localdate()
            with transaction.atomic():
                overdue_ads = ads.filter(end_date__lt=today).exclude(status=AdvertisementStatus.EXPIRED)
                if overdue_ads.exists():
                    # Bulk update status + updated_at
                    overdue_ads.update(status=AdvertisementStatus.EXPIRED, updated_at=timezone.now())


        total = ads.count()
        active = Advertisement.objects.filter(status = AdvertisementStatus.ACTIVE).count()
        expired = Advertisement.objects.filter(status = AdvertisementStatus.EXPIRED).count()
        
        if not ads.exists():
            return Response({   "total":total , 
                                 "active" : active , 
                                 "expired":expired
                             , "message": "Aucune annonce trouvée."}, status=status.HTTP_200_OK)

        result = []

        for ad in ads:
            ad_data = {
                "id": ad.id,
                "title": ad.title,
                "content": ad.content,
                "priority": ad.priority,
                "status":ad.status,
                "start_date": ad.start_date,
                "end_date": ad.end_date,
                "created_by": ad.created_by.username,
                "updated_by": ad.updated_by.username if ad.updated_by else None 
            }

            # Encode cover image if exists
            if ad.cover:
                with ad.cover.open('rb') as f:
                    encoded_img = base64.b64encode(f.read()).decode('utf-8')
                ad_data["cover_base64"] = encoded_img
            else:
                ad_data["cover_base64"] = None

            # Encode PDF file if exists
            if ad.pdf:
                try:
                    with ad.pdf.open('rb') as f:
                        encoded_pdf = base64.b64encode(f.read()).decode('utf-8')
                    ad_data["pdf_base64"] = encoded_pdf
                except Exception as e:
                    ad_data["pdf_base64"] = None
            else:
                ad_data["pdf_base64"] = None

            result.append(ad_data)

        return Response({"total":total, "active" : active ,   "expired":expired ,"advertisement": result}, 
                        status=status.HTTP_200_OK) 
# inspector advertisement list :
class InspectorsAdvertisementView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ads = Advertisement.objects.all()
        
        
        if not ads.exists():
            return Response({ "message": "Aucune annonce trouvée."}, status=status.HTTP_200_OK)
        
        today = timezone.localdate()
        with transaction.atomic():
                overdue_ads = ads.filter(end_date__lt=today).exclude(status=AdvertisementStatus.EXPIRED)
                if overdue_ads.exists():
                    # Bulk update status + updated_at
                    overdue_ads.update(status=AdvertisementStatus.EXPIRED, updated_at=timezone.now())

        ads = ads.exclude(status=AdvertisementStatus.EXPIRED)    
        result = []

        for ad in ads:
            ad_data = {
                "id": ad.id,
                "title": ad.title,
                "content": ad.content,
                "priority": ad.priority,
                "start_date": ad.start_date,
                "end_date": ad.end_date,
                "created_by": ad.created_by.username,
                "updated_by": ad.updated_by.username if ad.updated_by else None 
            }

            # Encode cover image if exists
            if ad.cover:
                with ad.cover.open('rb') as f:
                    encoded_img = base64.b64encode(f.read()).decode('utf-8')
                ad_data["cover_base64"] = encoded_img
            else:
                ad_data["cover_base64"] = None

            # Encode PDF file if exists
            if ad.pdf:
                try:
                    with ad.pdf.open('rb') as f:
                        encoded_pdf = base64.b64encode(f.read()).decode('utf-8')
                    ad_data["pdf_base64"] = encoded_pdf
                except Exception as e:
                    ad_data["pdf_base64"] = None
            else:
                ad_data["pdf_base64"] = None

            result.append(ad_data)

        return Response({"advertisement": result}, 
                        status=status.HTTP_200_OK) 
# details of an advertisement

class AdvertisementDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, ad_id):
        try:
            ad = Advertisement.objects.get(id=ad_id)
        except Advertisement.DoesNotExist:
            return Response({"message": "Annonce introuvable."}, status=status.HTTP_404_NOT_FOUND)

        # Prepare data
        ad_data = {
            "id": ad.id,
            "title": ad.title,
            "content": ad.content,
            "priority": ad.priority,
            "start_date": ad.start_date,
            "end_date": ad.end_date,
            "created_by": ad.created_by.username,
            "updated_by":ad.updated_by.username
        }

        # Encode image if exists
        if ad.cover:
            try:
                with ad.cover.open('rb') as f:
                    encoded_img = base64.b64encode(f.read()).decode('utf-8')
                ad_data["cover_base64"] = encoded_img
            except Exception:
                ad_data["cover_base64"] = None
        else:
            ad_data["cover_base64"] = None

        # Encode PDF if exists
        if ad.pdf:
            try:
                with ad.pdf.open('rb') as f:
                    encoded_pdf = base64.b64encode(f.read()).decode('utf-8')
                ad_data["pdf_base64"] = encoded_pdf
            except Exception:
                ad_data["pdf_base64"] = None
        else:
            ad_data["pdf_base64"] = None

        return Response(ad_data, status=status.HTTP_200_OK) 

# update advertisement

class UpdateAdvertisementView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, ad_id):
         # 1) authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
                return error_response
        
        try:
            ad = Advertisement.objects.get(id=ad_id)
        except Advertisement.DoesNotExist:
            return Response({"message": "Annonce introuvable."}, status=status.HTTP_404_NOT_FOUND)

        data = request.data

        # Validate priority
        priority = data.get('priority')
        if priority not in PriorityLevel.values:
            return Response({"message": "Priorité invalide."}, status=status.HTTP_400_BAD_REQUEST)

        # Update fields
        tl = data.get('title')
        if tl:
             ad.title = tl

        adCont = data.get('content')
        if tl:
             ad.content = adCont
        
        if priority:
             ad.priority = priority

        startDate = data.get('startDate')
        if startDate:
             ad.start_date = startDate

        endDate = data.get('endDate')
        if endDate:
             ad.end_date = endDate

         # Update cover image if provided
        if 'cover' not in request.FILES:
            ad.cover.delete()

        if 'coverFile' in request.FILES:    
            ad.cover = request.FILES['coverFile']

        # Update PDF file if provided
        if 'pdf' not in request.FILES:
            ad.pdf.delete()
            
        if 'pdfFile' in request.FILES:     
            ad.pdf = request.FILES['pdfFile']
        
        ad.updated_by =user
        ad.updated_at = timezone.now()
        ad.status = AdvertisementStatus.ACTIVE

        ad.save()

        return Response({"message": "Annonce mise à jour avec succès."}, status=status.HTTP_200_OK) 

# delete advertisement
class DeleteAdvertisementView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, ad_id):
        # 1) Authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
            return error_response

        # 2) Fetch advertisement
        try:
            ad = Advertisement.objects.get(id=ad_id)
        except Advertisement.DoesNotExist:
            return Response({"message": "Annonce introuvable."}, status=status.HTTP_404_NOT_FOUND)

        # 3) Delete
        ad.pdf.delete()
        ad.cover.delete()
        ad.delete()
        return Response({"message": "Annonce supprimée avec succès."}, status=status.HTTP_200_OK) 

# reservations management 
# Create ReservationView
class CreateReservationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # 1) authenticate & get your Account
        user, error_response = authenticate_and_authorize(request)
        if error_response:
            return error_response

        data = request.data

        # 2) required fields
        required = ["userId", "assetId", "startDate", "endDate", "purpose", "reservationType"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return Response(
                {"message": f"Champs manquants : {', '.join(missing)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3) look up the material (asset)
        try:
            mat = Material.objects.get(id=data["assetId"])
        except Material.DoesNotExist:
            return Response(
                {"message": f"L'actif (matériel) avec l'id={data['assetId']} n'a pas été trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 4) look up the account OF THE USER FOR WHOM WE RESERVE
        try:
            assigned = User.objects.get(id=data["userId"])
            
        except User.DoesNotExist:
            return Response(
                {"message": f"Utilisateur avec l'identifiant={data['userId']} non trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 5) basic date validation
        start = data["startDate"]
        end   = data["endDate"]
        if end < start:
            return Response(
                {"message": "La date de fin doit être égale ou postérieure à la date de début."},
                status=status.HTTP_400_BAD_REQUEST
            )
        # validate reservationType
        rtype = data["reservationType"]
     
        valid_types = [choice[0] for choice in Reservation._meta.get_field("reservation_type").choices]
        if rtype not in valid_types:
            return Response(
                {"message": f"Type de réservation invalide '{rtype}'. Doit être l'un des suivants: {', '.join(valid_types)}."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # 6) prevent overlapping reservations
        overlap_qs = Reservation.objects.filter(
            material=mat,
            start_date__lte=end,
            end_date__gte=start,
        )
        if overlap_qs.exists():
            return Response(
                {"message": "Cet matériel est déjà réservé pendant la période demandée."},
                status=status.HTTP_400_BAD_REQUEST
            )

        #  create the reservation
        r = Reservation.objects.create(
            start_date       = start,
            start_time       = timezone.now().time(),   # or parse your own
            end_date         = end,
            end_time         = timezone.now().time(),
            created_by       = user,
            assigned_to      = assigned,
            material         = mat,
            status           = ReservationStatus.PENDING,
            purpose          = data["purpose"] or None,
            notes            = data.get("notes") or None,
            reservation_type = rtype
        )
        try:
             #  Update material & reservation statuses
            mat.reservationStatus = MaterialReservationStatus.RESERVED  # means not available
            mat.save(update_fields=["status", "reservationStatus"])
        except :
                # Delete the malfunction record if photo saving fails (optional cleanup)
                r.delete()
                return Response(
                {"message": f"Échec de la création "},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        actor_name = user.username
        title = f"Nouvelle réservation pour {mat.name}"
        content = (
            f"Bonjour {assigned.get_full_name() or assigned.username},\n\n"
            f"Une nouvelle réservation a été créée pour le matériel suivant par {actor_name}.\n\n"
            f"Détails de la réservation :\n"
            f"- Matériel : {mat.name}\n"
            f"- Période : {start} au {end}\n"
            f"- Heure de début : {data.get('start_time', r.start_time)}\n"
            f"- Heure de fin : {data.get('end_time', r.end_time)}\n"
            f"- Type de réservation : {rtype}\n"
            f"- Objet : {data.get('purpose', '—')}\n"
            f"- Notes : {data.get('notes', '—')}\n\n"
            f"Réservation créée le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
            "Si vous n'avez pas demandé cette réservation, veuillez contacter un administrateur."
        )
        try:
            notification = create_notification(
                title=title,
                content=content,
                recipient=assigned,
                notification_date=timezone.localdate(),
                notification_time=timezone.localtime().time()
            )
        except:
            try : r.delete() 
            except: pass
            return Response(
                {"message": "Échec lors de la création de la notification."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        try:
            send_result = send_notification_email(notification=notification)
            if not send_result.get("ok"):
                # if you want best-effort notify and still succeed, change behavior here to log and continue.
                return Response({"message": "Échec lors de l'envoi de la notification par e-mail pour l'utilisateur assigné."},
                                status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"message": "La réservation créée mes Échec lors de l'envoi de la notification par e-mail pour l'utilisateur assigné.",  "id": r.id},
                            status=status.HTTP_200_OK)
        return Response(
            {"message": "La réservation créée.", "id": r.id},
            status=status.HTTP_200_OK
        )       

# Update reservation detail

class UpdateReservationView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, reservation_id):
        # Authenticate & get your Account
        user, error_response = authenticate_and_authorize(request)
        if error_response:
            return error_response

        # 1) Look up the reservation
        try:
            res = Reservation.objects.get(id=reservation_id)
        except Reservation.DoesNotExist:
            return Response(
                {"message": "Réservation non trouvée."},
                status=status.HTTP_404_NOT_FOUND
            )

        data = request.data

        # Store original values before any modification
        orig_material = res.material
        orig_start = res.start_date
        orig_end = res.end_date

        mat = None  # placeholder for new material

        # 2) Validate and update the assigned-to user
        if "userId" in data:
            if data["userId"] : 
                try:
                    acct = User.objects.get(id=data["userId"])
                    res.assigned_to = acct
                except User.DoesNotExist:
                    return Response(
                        {"message": f"Utilisateur avec l'identifiant={data['userId']} non trouvé."},
                        status=status.HTTP_404_NOT_FOUND
                    )

        # 3) Validate and update the material (asset)
        if "assetId" in data:
            try:
                mat = Material.objects.get(id=data["assetId"])
                res.material = mat
            except Material.DoesNotExist:
                return Response(
                    {"message": f"L'actif (matériel) avec l'id={data['assetId']} n'a pas été trouvé."},
                    status=status.HTTP_404_NOT_FOUND
                )

        # 4) Update dates/purpose/notes/type
        if "startDate" in data:
            start = data["startDate"]
            print(start)
            res.start_date = start
            res.start_time = timezone.now().time()
        else:
            start = res.start_date  

        if "endDate" in data:
            if data["endDate"] < data.get("startDate", res.start_date):
                return Response(
                    {"message": "La date de fin doit être égale ou postérieure à la date de début. ..."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            end = data["endDate"]
            res.end_date = end
            res.end_time = timezone.now().time()
        else:
            end = res.end_date

        if "purpose" in data:
            res.purpose = data["purpose"]

        if "notes" in data:
            res.notes = data["notes"] or ""

        if "reservationType" in data:
            new_type = data["reservationType"]
            valid_types = [choice[0] for choice in ReservationType.choices]
            if new_type not in valid_types:
                return Response(
                    {"message": f"Type de réservation invalide '{new_type}'. Doit être l'un des suivants: {', '.join(valid_types)}."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            res.reservation_type = new_type

        # 5) Prevent overlapping reservations only if asset or duration changed
        material_to_check = mat if "assetId" in data else orig_material

        asset_changed = False
        if "assetId" in data:
            try:
                new_mat_id = int(data.get("assetId"))
            except (TypeError, ValueError):
                new_mat_id = None
            orig_mat_id = getattr(orig_material, "id", None)
            asset_changed = (new_mat_id != orig_mat_id)

        start_changed = "startDate" in data and start != orig_start
        end_changed = "endDate" in data and end != orig_end

        if asset_changed or start_changed or end_changed:
            if material_to_check is None:
                return Response(
                    {"message": "Aucun matériau spécifié pour la vérification de chevauchement."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            overlap_qs = Reservation.objects.filter(
                material=material_to_check,
                start_date__lte=end,
                end_date__gte=start,
            ).exclude(id=res.id)

            if overlap_qs.exists():
                return Response(
                    {"message": "Ce matériel est déjà réservé pendant la période demandée."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        assigned_recipient = res.assigned_to
        try:
            with transaction.atomic():
                # set reservation to pending after modification
                res.status = ReservationStatus.PENDING
                res.save()

                # If there is no assigned recipient, skip notification creation
                notification = None
                if assigned_recipient:
                    # Prepare actor name
                    actor_name = user.username

                    # material info (prefer updated material `res.material`)
                    current_mat = res.material
                    mat_name = getattr(current_mat, "name", "—")
                    # Build notification title and french content
                    title = f"Mise à jour de la réservation pour {mat_name}"
                    content = (
                        f"Bonjour { assigned_recipient.username},\n\n"
                        f"La réservation pour {mat_name} a été modifiée par {actor_name} le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                        f"Détails mis à jour :\n"
                        f"- Matériel : {mat_name}\n"
                        f"- Période : {start} au {end}\n"
                        f"- Objet : {res.purpose or '—'}\n"
                        f"- Notes : {res.notes or '—'}\n"
                        f"- Type de réservation : {res.reservation_type or '—'}\n\n"
                        f"Si vous n'êtes pas responsable de cette modification, veuillez contacter votre administrateur."
                    )

                    # Create notification record (inside the transaction)
                    notification = create_notification(
                        title=title,
                        content=content,
                        recipient=assigned_recipient,
                        notification_date=timezone.localdate(),
                        notification_time=timezone.localtime().time()
                    )
                # commit transaction here
        except:
            # rollback automatically occurred if exception raised
            # Return a 500 to indicate failure creating notification or saving
            return Response(
                {"message": "Échec lors de la sauvegarde de la réservation ou de la création de la notification."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        try:
            if assigned_recipient and notification:
                send_result = send_notification_email(notification=notification)
                if not send_result.get("ok"):
                    # match prior pattern: return 400 if sending fails
                    return Response({"message": "Réservation mise à jour avec succès mes failed to send reservation update notification to the assigned user."}, status=status.HTTP_200_OK)
        except:
                 return Response({"message": "Réservation mise à jour avec succès mes failed to send reservation update notification to the assigned user."}, status=status.HTTP_200_OK)

        return Response(
            {"message": "Réservation mise à jour avec succès."},
            status=status.HTTP_200_OK
        )


# view detail of a reservation

class ReservationDetailView(APIView):
    permission_classes = [IsAuthenticated]
    #
    def get(self, request, reservation_id):
        # 1) fetch reservation or 404
        try:
            res = Reservation.objects.get(id=reservation_id)
        except Reservation.DoesNotExist:
            return Response(
                {"error": "Réservation non trouvée."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 2) assemble payload
        payload = {
            "id":               res.id,
            "start_date":       res.start_date,
            "start_time":       res.start_time.strftime("%H:%M"),
            "end_date":         res.end_date,
            "end_time":         res.end_time.strftime("%H:%M"),
            "purpose":          getattr(res, "purpose", ""),
            "notes":            getattr(res, "notes", ""),
            "reservation_type": getattr(res, "reservation_type", ""),
            "status":           res.status,
            "created_at":       res.created_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at":       res.updated_at.strftime("%Y-%m-%d %H:%M"),
            "created_by": {
                "id":       res.created_by.id,
                "username": res.created_by.username ,
            },
            "assigned_to": {
                "id":       res.assigned_to.id,
                "username": res.assigned_to.username ,
            },
            "material": {
                "id":    res.material.id,
                "name":  res.material.name,
                "type":  res.material.type,
            }
        }

        return Response(payload, status=status.HTTP_200_OK)  

# list of all reservations
class ReservationListView(APIView):
    permission_classes = [IsAuthenticated]
    #
    def get(self, request):
        qs = Reservation.objects.select_related(
            'created_by', 'assigned_to', 'material'
        ).all()
        
        today = timezone.localdate()
        with transaction.atomic():
                overdue_qs = qs.filter(end_date__lt=today).exclude(status=ReservationStatus.COMPLETED)
                if overdue_qs.exists():
                    # Bulk update status + updated_at
                    overdue_qs.update(status=ReservationStatus.COMPLETED, updated_at=timezone.now())

         # Count reservations by status
        total_count = qs.count()
        pending_count = qs.filter(status=ReservationStatus.PENDING).count()
        accepted_count = qs.filter(status=ReservationStatus.ACCEPTED).count()
        declined_count = qs.filter(status=ReservationStatus.DECLINED).count()
        completed_count = qs.filter(status=ReservationStatus.COMPLETED).count()
        if not qs.exists():
            return Response(
                {   "total": total_count,
                    "pending": pending_count,
                    "accepted": accepted_count,
                    "declined": declined_count, 
                    "completed": completed_count,
                    "message": "Il n'y a pas de réservations."},
                status=status.HTTP_404_NOT_FOUND
            )
       

        reservations = []
        for res in qs:
            reservations.append({
                "id":               res.id,
                "start_date":       res.start_date,
                "start_time":       res.start_time.strftime("%H:%M"),
                "end_date":         res.end_date,
                "end_time":         res.end_time.strftime("%H:%M"),
                "purpose":          getattr(res, "purpose", ""),
                "notes":            getattr(res, "notes", ""),
                "reservation_type": getattr(res, "reservation_type", ""),
                "status":           res.status,
                "created_at":       res.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at":       res.updated_at.strftime("%Y-%m-%d %H:%M"),
                "created_by": {
                    "id":       res.created_by.id,
                    "username": getattr(res.created_by, "username", None),
                },
                "assigned_to": {
                    "id":       res.assigned_to.id,
                    "username": getattr(res.assigned_to, "username", None),
                },
                "material": {
                    "id":    res.material.id,
                    "name":  res.material.name,
                    "type":  res.material.type,
                }
            })

        return Response({   "total": total_count,
                            "pending": pending_count,
                            "accepted": accepted_count,
                            "declined": declined_count,
                            "completed": completed_count, 
                            "reservations": reservations}, status=status.HTTP_200_OK)

# get the reservation of an user 
class UserReservationListView(APIView):
    permission_classes = [IsAuthenticated]
    #
    def get(self, request, user_id):
        # 1) check that the Account exists
        try:
            acct = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"message": f"Utilisateur avec id={user_id} non trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )

        valid_types = [
            ReservationType.NORMAL,
            ReservationType.SAISONNIER
        ]

        # 3) filter
        qs = Reservation.objects.select_related("material").filter(
            created_by=acct,
            reservation_type__in=valid_types
        )

        # 4) empty check
        if not qs.exists():
            return Response(
                {"message": "Aucune réservation normale ou saisonnière trouvée pour cet utilisateur."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 5) build payload
        output = []
        for res in qs:
            output.append({
                "id":               res.id,
                "start_date":       res.start_date,
                "start_time":       res.start_time.strftime("%H:%M"),
                "end_date":         res.end_date,
                "end_time":         res.end_time.strftime("%H:%M"),
                "purpose":          getattr(res, "purpose", ""),
                "notes":            getattr(res, "notes", ""),
                "reservation_type": res.reservation_type,
                "status":           res.status,
                "created_at":       res.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at":       res.updated_at.strftime("%Y-%m-%d %H:%M"),
                "material": {
                    "id":   res.material.id,
                    "name": res.material.name,
                    "type": res.material.type,
                }
            })

        return Response({"reservations": output}, status=status.HTTP_200_OK) 


# get the reservation for an selected material 
class MaterialReservationListView(APIView):
    permission_classes = [IsAuthenticated]
  

    def get(self, request, material_id):
        # 1) ensure material exists
        try:
            material = Material.objects.get(id=material_id)
        except Material.DoesNotExist:
            return Response(
                {"message": "Matériel non trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 2) get reservations for that material
        qs = Reservation.objects.select_related('created_by', 'assigned_to', 'material')\
                                .filter(material=material)

        # 3) Count reservations by status (filtered)
        total_count = qs.count()
        pending_count = qs.filter(status=ReservationStatus.PENDING).count()
        accepted_count = qs.filter(status=ReservationStatus.ACCEPTED).count()
        declined_count = qs.filter(status=ReservationStatus.DECLINED).count()

        # 4) if none, return a 404 (matches your pattern)
        if not qs.exists():
            return Response(
                {
                    "material": {
                        "id": material.id,
                        "name": material.name,
                        "type": material.type,
                    },
                    "total": total_count,
                    "pending": pending_count,
                    "accepted": accepted_count,
                    "declined": declined_count,
                    "message": "Il n'y a pas de réservations pour ce matériel."
                },
                status=status.HTTP_404_NOT_FOUND
            )

        # 5) serialize reservations (same fields as your global list)
        reservations = []
        for res in qs:
            reservations.append({
                "id":               res.id,
                "start_date":       res.start_date,
                "start_time":       res.start_time.strftime("%H:%M"),
                "end_date":         res.end_date,
                "end_time":         res.end_time.strftime("%H:%M"),
                "purpose":          getattr(res, "purpose", ""),
                "notes":            getattr(res, "notes", ""),
                "reservation_type": getattr(res, "reservation_type", ""),
                "status":           res.status,
                "created_at":       res.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at":       res.updated_at.strftime("%Y-%m-%d %H:%M"),
                "created_by": {
                    "id":       res.created_by.id,
                    "username": getattr(res.created_by, "username", None),
                },
                "assigned_to": {
                    "id":       res.assigned_to.id if res.assigned_to else None,
                    "username": getattr(res.assigned_to, "username", None) if res.assigned_to else None,
                },
                "material": {
                    "id":    res.material.id,
                    "name":  res.material.name,
                    "type":  res.material.type,
                }
            })

        return Response(
            {
                "material": {
                    "id": material.id,
                    "name": material.name,
                    "type": material.type,
                },
                "total": total_count,
                "pending": pending_count,
                "accepted": accepted_count,
                "declined": declined_count,
                "reservations": reservations
            },
            status=status.HTTP_200_OK
        )
# get the reservation of an user 
class MyReservationListView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        # 1) check that the Account exists
        try:
            acct = User.objects.get(id=user.id)
           
        except User.DoesNotExist:
            return Response(
                {"message": f"User  not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        valid_types = [
            ReservationType.NORMAL,
            ReservationType.SAISONNIER
        ]
        
        # 3) filter
        qs = Reservation.objects.select_related("material").filter(
            assigned_to=acct,
            reservation_type__in=valid_types
        )

        # 4) empty check
        if not qs.exists():
            return Response(
                {"message": "Aucune réservation normale ou saisonnière trouvée pour vous."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        today = timezone.localdate()
        with transaction.atomic():
                overdue_qs = qs.filter(end_date__lt=today).exclude(status=ReservationStatus.COMPLETED)
                if overdue_qs.exists():
                    # Bulk update status + updated_at
                    overdue_qs.update(status=ReservationStatus.COMPLETED, updated_at=timezone.now())
        
        qs = qs.exclude(status=ReservationStatus.COMPLETED)            
        # 5) build payload
        output = []
        for res in qs:
            output.append({
                "id":               res.id,
                "start_date":       res.start_date,
                "start_time":       res.start_time.strftime("%H:%M"),
                "end_date":         res.end_date,
                "end_time":         res.end_time.strftime("%H:%M"),
                "purpose":          getattr(res, "purpose", ""),
                "notes":            getattr(res, "notes", ""),
                "reservation_type": res.reservation_type,
                "status":           res.status,
                "created_at":       res.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at":       res.updated_at.strftime("%Y-%m-%d %H:%M"),
                "material": {
                    "id":   res.material.id,
                    "name": res.material.name,
                    "type": res.material.type,
                }
            })

        return Response({"reservations": output}, status=status.HTTP_200_OK) 
# delete reservation
class DeleteReservationView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, reservation_id):
       # 1) Authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
            return error_response
        
        try:
            reservation = Reservation.objects.get(id=reservation_id)
        except Reservation.DoesNotExist:
            return Response(
                {"message": f"Réservation avec id={reservation_id} non trouvée."},
                status=status.HTTP_404_NOT_FOUND
            )
        mat =  reservation.material
        assigned_to = reservation.assigned_to
        try:
                with transaction.atomic():
                    deleted_prechecks_count = 0

                    # 3) If the material is a vehicle, delete ONLY the prechecks for this reservation
                    if mat.type == MaterialType.VEHICLE:
                        # explicit filter by reservation_id to ensure we only remove prechecks for this reservation
                        prechecks_qs = PreCheck.objects.filter(reservation_id=reservation_id)
                        if prechecks_qs.exists():
                            deleted_info = prechecks_qs.delete()
                            deleted_prechecks_count = deleted_info[0]

                    # 4) update material status to AVAILABLE
                    mat.reservationStatus = MaterialReservationStatus.AVAILABLE
                    mat.save()

                    # 5) delete the reservation
                    reservation.delete()

        except :
                return Response(
                    {
                        "message": "Une erreur s'est produite lors de la suppression de la réservation ou des pré-vérifications associées.",  
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
         # 6) return success (include info about deleted prechecks for clarity)
        msg = "Réservation supprimée avec succès."
        if deleted_prechecks_count:
            msg += f" Suppression de {deleted_prechecks_count} pré-vérification(s) associée(s)."

        if assigned_to:
            try:
                title = f"Votre réservation pour {mat.name} a été supprimée"
                content = (
                    f"Bonjour {assigned_to.username},\n\n"
                    f"La réservation pour le matériel « {mat.name} » a été supprimée par "
                    f"{(user.username)} le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                    "Si vous pensez qu'il s'agit d'une erreur, contactez un administrateur."
                )
                notif = create_notification(
                    title=title,
                    content=content,
                    recipient=assigned_to,
                    notification_date=timezone.localdate(),
                    notification_time=timezone.localtime().time()
                )
                send_result = send_notification_email(notification=notif)
                if not send_result.get("ok"):
                    successMsg = msg + f"mes échec envoi email notification"
                    return Response({"message": successMsg}, status=status.HTTP_200_OK)         
            except:
                   return Response({"message": successMsg}, status=status.HTTP_200_OK)

       

        return Response({"message": msg}, status=status.HTTP_200_OK)

# Accept reservation endpoint

class AcceptReservationView(APIView):
    permission_classes = [IsAuthenticated]  # we’ll do custom auth below

    def put(self, request, reservation_id):
        # 1) authenticate
        user, error_response = authenticate_and_authorize_allUser(request)
        if error_response:
            return error_response

        # 2) lookup reservation
        try:
            reservation = Reservation.objects.get(id=reservation_id)
        except Reservation.DoesNotExist:
            return Response(
                {"message": f"Identifiant de réservation = {reservation_id} non trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )
        is_VEHICLE = False
        if reservation.material.type == MaterialType.VEHICLE:
            is_VEHICLE = True  
        if is_VEHICLE :
                # 3) validate payload: all eight checks must be present
            bool_fields = [
                "car_body_ok",
                "tires_ok",
                "lighting_ok",
                "next_service_within_1k",
                "adblue_ok",
                "no_warning_lights",
                "clean_vehicle",
                "docs_present"
            ]
            missing = [f for f in bool_fields if f not in request.data]
            if missing:
                return Response(
                    {"message": f"Champs de vérification préalables manquants : {', '.join(missing)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            preCheck =  PreCheck.objects.filter(reservation = reservation).first()
            precheck_values = {
                "checked_by": user,
                "car_body_ok": bool(request.data["car_body_ok"]),
                "tires_ok": bool(request.data["tires_ok"]),
                "lighting_ok": bool(request.data["lighting_ok"]),
                "next_service_within_1k": bool(request.data["next_service_within_1k"]),
                "adblue_ok": bool(request.data["adblue_ok"]),
                "no_warning_lights": bool(request.data["no_warning_lights"]),
                "clean_vehicle": bool(request.data["clean_vehicle"]),
                "docs_present": bool(request.data["docs_present"]),
                "report": request.data.get("report", "").strip() or None,
                "status": CheckStatus.COMPLETED,
            }
            if preCheck :
                 # update existing precheck
                for key, val in precheck_values.items():
                    setattr(preCheck, key, val)
                # Save only the fields that changed (optional)
                update_fields = list(precheck_values.keys())
                preCheck.save(update_fields=update_fields)
            else :     
                # 4) create PreCheck
                PreCheck.objects.create(
                    reservation          = reservation,
                    checked_by           = user,
                    # check_date / check_time auto_now_add
                    car_body_ok          = bool(request.data["car_body_ok"]),
                    tires_ok             = bool(request.data["tires_ok"]),
                    lighting_ok          = bool(request.data["lighting_ok"]),
                    next_service_within_1k = bool(request.data["next_service_within_1k"]),
                    adblue_ok            = bool(request.data["adblue_ok"]),
                    no_warning_lights    = bool(request.data["no_warning_lights"]),
                    clean_vehicle        = bool(request.data["clean_vehicle"]),
                    docs_present         = bool(request.data["docs_present"]),
                    report               = request.data.get("report", "").strip() or None,
                    status               = CheckStatus.COMPLETED,
                )

        # 5) update reservation status
        reservation.status = ReservationStatus.ACCEPTED
        reservation.updated_at = timezone.now()
        reservation.save(update_fields=["status", "updated_at"])
        creator = reservation.created_by
        try:
            if creator:
                mat = reservation.material
                mat_type_raw = str(mat.type or "").lower()
                mat_type_fr = "Véhicule" if "veh" in mat_type_raw or mat_type_raw in ("véhicule", "vehicule", "vehicle") else "Outil"

                title = f"La réservation pour  le matériel « {mat.name} » a été acceptée"
                content = (
                    f"Bonjour {creator.username},\n\n"
                    f"La réservation {reservation.id} pour le matériel « {mat.name} » ({mat_type_fr}) a été acceptée par "
                    f"{(user.username)} le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                    f"Période : {reservation.start_date} au {reservation.end_date}\n\n"
                )
                notif = create_notification(
                    title=title,
                    content=content,
                    recipient=creator,
                    notification_date=timezone.localdate(),
                    notification_time=timezone.localtime().time()
                )
                send_result = send_notification_email(notification=notif)
                if not send_result.get("ok"):
                     Response(
            {
                "message": "Réservation acceptée et pré-vérification enregistrée.mes il y'échec envoi email notification"
            },
            status=status.HTTP_200_OK
        ) 
        except Exception as exc:
            Response(
            {
                "message": "Réservation acceptée et pré-vérification enregistrée , mes il y'erreur lors de la notification du créateur"
            },
            status=status.HTTP_200_OK
        ) 
        return Response(
            {
                "message": "Réservation acceptée et pré-vérification enregistrée."
            },
            status=status.HTTP_200_OK
        ) 

# Refuse reservations
class RefuseReservationView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, reservation_id):
        # 1) authenticate & authorize
        user, error_response = authenticate_and_authorize_allUser(request)
        if error_response:
            return error_response

        # 2) lookup reservation
        try:
            reservation = Reservation.objects.get(id=reservation_id)
        except Reservation.DoesNotExist:
            return Response(
                {"message": f"Identifiant de réservation = {reservation_id} non trouvé."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 3) only pending reservations can be refused
        if reservation.status != ReservationStatus.PENDING:
            return Response(
                {"message": f"Impossible de refuser une réservation avec le statut='{reservation.status}'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 4) mark as declined
        reservation.status = ReservationStatus.DECLINED
        reservation.updated_at = timezone.now()
        
        
        mat =  reservation.material
        try:
            mat.reservationStatus = MaterialReservationStatus.AVAILABLE 
            mat.save()
        except:
            return Response(
                {"message": f"Problèmes de changement de statut."},
                status=status.HTTP_404_NOT_FOUND)
        
        reservation.save(update_fields=["status", "updated_at"])
        creator = reservation.created_by
        try:
            if creator:
                mat_type_raw = str(mat.type or "").lower()
                mat_type_fr = "Véhicule" if "veh" in mat_type_raw or mat_type_raw in ("véhicule", "vehicule", "vehicle") else "Outil"

                title = f"La réservation pour le matériel « {mat.name} » a été refusée"
                content = (
                    f"Bonjour {creator.username},\n\n"
                    f"La réservation #{reservation.id} pour le matériel « {mat.name} » ({mat_type_fr}) a été refusée par "
                    f"{(user.username)} le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                    "Si vous pensez qu'il s'agit d'une erreur, veuillez contacter un administrateur."
                )
                notif = create_notification(
                    title=title,
                    content=content,
                    recipient=creator,
                    notification_date=timezone.localdate(),
                    notification_time=timezone.localtime().time()
                )
                send_result = send_notification_email(notification=notif)
                if not send_result.get("ok"):
                   pass
        except Exception as exc:
                    pass

        return Response(
            {"message": f"La réservation pour le matériel « {mat.name} » a été refusée."},
            status=status.HTTP_200_OK
        )
    
# list of pre checks

class PreCheckListView(APIView):
    permission_classes = [IsAuthenticated]  
    #
    def get(self, request):

        # 2) fetch all prechecks
        qs = PreCheck.objects.select_related(
            'reservation', 'checked_by'
        ).all()
        # total count
        total = qs.count()

       
        summary = {
            status_choice.value: qs.filter(status=status_choice.value).count()
            for status_choice in CheckStatus
        }

        # 3) empty check
        if not qs.exists():
            return Response(
                {  "total":        total,
                   "summary":      summary, 
                   "message": "Il n'y a pas de pré-vérifications."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 4) build payload
        output = []
        for p in qs:
            output.append({
                "id":             p.id,
                "reservation": {
                    "id":   p.reservation.id,
                    "start_date":  p.reservation.start_date,
                    "end_date":    p.reservation.end_date,
                    "status":      p.reservation.status,
                    "notes": p.reservation.notes or "",
                    "type" : p.reservation.reservation_type,
                    "material": {
                        "id": p.reservation.material.id,
                        "name": p.reservation.material.name,
                        "type": p.reservation.material.type  # e.g., 'vehicle' or 'tool'
                    }
                },
                
                "checked_by": {
                    "id":       p.checked_by.id,
                    "username": getattr(p.checked_by, "username", None),
                    "role":     p.checked_by.account.role,
                },
                "check_date":     p.check_date,
                "check_time":     p.check_time,
                "report": p.report,  # Ensure report is an array, even if empty
                "status": p.status,
                "car_body_ok":            p.car_body_ok,
                "tires_ok":               p.tires_ok,
                "lighting_ok":            p.lighting_ok,
                "next_service_within_1k": p.next_service_within_1k,
                "adblue_ok":              p.adblue_ok,
                "no_warning_lights":      p.no_warning_lights,
                "clean_vehicle":          p.clean_vehicle,
                "docs_present":           p.docs_present,
                "created_at": p.created_at.strftime("%Y-%m-%d %H:%M"),
                "updated_at": p.updated_at.strftime("%Y-%m-%d %H:%M"),
            })

        return Response({"total":        total,
                        "summary":      summary,   
                        "pre-checks": output}, status=status.HTTP_200_OK)  


# pre check details based on id

class PreCheckDetailView(APIView):
    permission_classes = [IsAuthenticated]  
    
    def get(self, request, precheck_id):

        # 2) fetch the precheck
        try:
            p = PreCheck.objects.select_related('reservation', 'checked_by').get(id=precheck_id)
        except PreCheck.DoesNotExist:
            return Response(
                {"message": f"Vérification préliminaire avec id={precheck_id} non trouvée."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 3) build payload
        payload = {
            "id": p.id,
            "reservation": {
                "id":         p.reservation.id,
                "start_date": p.reservation.start_date,
                "end_date":   p.reservation.end_date,
                "status":     p.reservation.status,
            },
            "checked_by": {
                "id":       p.checked_by.id,
                "username": getattr(p.checked_by, "username", None),
                "role":     p.checked_by.account.role,
            },
            "check_date":     p.check_date,
            "check_time":     p.check_time,
            "report":         p.report,
            "status":         p.status,
            # each checklist boolean
            "car_body_ok":            p.car_body_ok,
            "tires_ok":               p.tires_ok,
            "lighting_ok":            p.lighting_ok,
            "next_service_within_1k": p.next_service_within_1k,
            "adblue_ok":              p.adblue_ok,
            "no_warning_lights":      p.no_warning_lights,
            "clean_vehicle":          p.clean_vehicle,
            "docs_present":           p.docs_present,
            "created_at":     p.created_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at":     p.updated_at.strftime("%Y-%m-%d %H:%M"),
        }

        return Response(payload, status=status.HTTP_200_OK)          

# pre-check delete endpoint

class PreCheckDeleteView(APIView):
    permission_classes = [IsAuthenticated]  # auth inside

    def delete(self, request, precheck_id):
        # 1) authenticate
        user, error_response = authenticate_and_authorize(request)
        if error_response:
            return error_response

        # 2) fetch the precheck
        try:
            p = PreCheck.objects.get(id=precheck_id)
        except PreCheck.DoesNotExist:
            return Response(
                {"message": f"Vérification préliminaire avec id={precheck_id} non trouvée."},
                status=status.HTTP_404_NOT_FOUND
            )

        # 3) delete it
        p.delete()

        return Response(
            {"message": f"Pre‑check with id={precheck_id} deleted successfully."},
            status=status.HTTP_200_OK
        ) 
    
# support management 
# Helper serializers (manual dict builders)
def _user_brief(user):
    if not user:
        return None
    return {
        "id": user.id,
        "username": getattr(user, "username", None),
        "email": getattr(user, "email", None),
    }
import mimetypes
def _attachment_to_dict(att, request=None):
    if not att:
        return None

    b64_data = None
    try:
        # Ensure file is opened in binary mode and read it
        att.file.open(mode='rb')
        raw = att.file.read()
        att.file.close()

        if raw is not None:
            b64 = base64.b64encode(raw).decode('utf-8')

            # try to guess mime type from filename; fallback to generic octet-stream
            mime, _ = mimetypes.guess_type(getattr(att.file, "name", "") or "")
            mime = mime or "application/octet-stream"

            # return as a data URI which is convenient for clients
            b64_data = f"data:{mime};base64,{b64}"
    except Exception:
        # swallow errors and return None for base64 if we couldn't read/encode
        b64_data = None

    return {
        "id": att.id,
        "file_name": getattr(att.file, "name", None),
        "base64": b64_data,
        "uploaded_at": att.uploaded_at.isoformat() if att.uploaded_at else None,
    }

def _reply_to_dict(reply, request=None):
    return {
        "id": reply.id,
        "ticket_id": reply.ticket_id,
        "author": _user_brief(reply.author),
        "author_id": reply.author_id,
        "message": reply.message,
        "attachments": [_attachment_to_dict(a, request) for a in reply.attachments.all()],
        "created_at": reply.created_at.strftime("%Y-%m-%d %H:%M") if reply.created_at else None,
        "updated_at": reply.updated_at.strftime("%Y-%m-%d %H:%M") if reply.updated_at else None,
    }

def _ticket_to_dict(ticket, request=None, include_replies=True):
    data = {
        "id": ticket.id,
        "title": ticket.title,
        "description": ticket.description,
        "type": ticket.type,
        "priority": ticket.priority,
        "status": ticket.status,
        "created_by": _user_brief(ticket.created_by),
        "created_by_id": ticket.created_by_id,
        "assigned_to": _user_brief(ticket.assigned_to) if ticket.assigned_to else None,
        "assigned_to_id": ticket.assigned_to_id if ticket.assigned_to else None,
        "attachments": [_attachment_to_dict(a, request) for a in ticket.attachments.all()],
        "created_at": ticket.created_at.strftime("%Y-%m-%d %H:%M") if ticket.created_at else None,
        "updated_at": ticket.updated_at.strftime("%Y-%m-%d %H:%M") if ticket.updated_at else None,
    }
    if include_replies:
        data["replies"] = [_reply_to_dict(r, request) for r in ticket.replies.order_by("created_at").all()]
    return data

class TicketListCreateAPIView(APIView):
    """
    GET: list tickets
      - admin/manager: all
      - inspector: only own tickets
    POST: create ticket (multipart/form-data supported for attachments)
    """
    permission_classes = [IsAuthenticated] 
    def get(self, request, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        # determine role via user's account.role if present (we don't change auth.py)
        account = getattr(user, "account", None)
        role = getattr(account, "role", None) if account else None

        if role in ("admin", "manager"):
            qs = SupportTicket.objects.all().order_by("-created_at")
        else:
            qs = SupportTicket.objects.filter(created_by=user).order_by("-created_at")
         # counts by status (use the values you defined in SupportTicketStatus)
        open_count = qs.filter(status=SupportTicketStatus.OPEN).count()
        resolved_count = qs.filter(status=SupportTicketStatus.RESOLVED).count()
        total_count = qs.count()
        tickets = [_ticket_to_dict(t, request, include_replies=False) for t in qs]
        return Response({"tickets": tickets, "count": total_count,  "counts": {
            "open": open_count,
            "resolved": resolved_count
        }}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        title = request.data.get("title", "").strip()
        description = request.data.get("description", "").strip()
        type_ = request.data.get("type", "").strip() or "issue"
        priority = request.data.get("priority", "").strip() or "medium"
        # status should default to 'open' in model

        if not title:
            return Response({"message": "Title is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not description:
            return Response({"message": "Description is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        notifications = []
        created_ticket = None
        with transaction.atomic():
            ticket = SupportTicket.objects.create(
                title=title,
                description=description,
                type=type_,
                priority=priority,
                created_by=user
            )
            files = request.FILES.getlist("attachments")
            for f in files:
                SupportAttachment.objects.create(ticket=ticket, file=f)
            
            created_ticket = ticket
            admins = User.objects.filter(account__role__in=("admin", "manager")).all()
            for admin in admins:
                notif_title = f"Nouveau ticket : {ticket.title}"
                notif_content = (
                    f"Bonjour { admin.username},\n\n"
                    f"Un nouveau ticket a été créé par {(user.username)}.\n\n"
                    f"ID: {ticket.id}\n"
                    f"Titre: {ticket.title}\n"
                    f"Priorité: {ticket.priority}\n"
                    "Consultez l'interface d'administration pour plus de détails."
                )
                # create_notification returns the Notification instance
                try:
                    notif = create_notification(
                        title=notif_title,
                        content=notif_content,
                        recipient=admin,
                        notification_date=timezone.localdate(),
                        notification_time=timezone.localtime().time()
                    )
                    notifications.append(notif)
                except Exception as exc:
                    pass
                for notif in notifications:
                    try:
                        send_result = send_notification_email(notification=notif)
                    except:
                       pass
        return Response({
            "message": "Billet créé avec succès.",
            "ticket": _ticket_to_dict(ticket, request)
        }, status=status.HTTP_201_CREATED)


# Ticket detail & update
# -------------------------
class TicketDetailAPIView(APIView):
    """
    GET /api/support/tickets/<pk>/    -> retrieve (ticket + replies + attachments)
    PUT/PATCH /api/support/tickets/<pk>/ -> update (owner restrictions for inspectors)
    """
    def get(self, request, pk, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        ticket = get_object_or_404(SupportTicket, pk=pk)
        account = getattr(user, "account", None)
        role = getattr(account, "role", None) if account else None

        # visibility: inspectors only access their own ticket
        if role not in ("admin", "manager") and ticket.created_by_id != user.id:
            return Response({"message": "Permission refusée."}, status=status.HTTP_403_FORBIDDEN)

        return Response({"ticket": _ticket_to_dict(ticket, request)}, status=status.HTTP_200_OK)

    def put(self, request, pk, *args, **kwargs):
        return self._update(request, pk, partial=False)

    def patch(self, request, pk, *args, **kwargs):
        return self._update(request, pk, partial=True)

    def _update(self, request, pk, partial=True):
        # authenticate (all users allowed here, checks later)
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        ticket = get_object_or_404(SupportTicket, pk=pk)
        account = getattr(user, "account", None)
        role = getattr(account, "role", None) if account else None

        # owner check for inspectors
        if role not in ("admin", "manager") and ticket.created_by_id != user.id:
            return Response({"message": "Permission refusée."}, status=status.HTTP_403_FORBIDDEN)

        # restrict fields inspectors can change
        if role not in ("admin", "manager"):
            allowed = {"title", "description", "priority"}
            incoming = {k: v for k, v in request.data.items() if k in allowed}
        else:
            # admin/manager may update any safe field (status, assigned_to must be set carefully)
            incoming = dict(request.data.items())

        # apply allowed fields
        changed = False
        for key, val in incoming.items():
            if key == "assigned_to":
                # only admin/manager can change assigned_to; accept user id
                if role in ("admin", "manager"):
                    try:
                        from django.contrib.auth import get_user_model
                        User = get_user_model()
                        assigned_user = User.objects.get(id=int(val))
                        ticket.assigned_to = assigned_user
                        changed = True
                    except Exception:
                        return Response({"message": "Identifiant d'utilisateur assigné invalide."}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    continue
            elif key == "status":
                # only admin/manager allowed to change status
                if role in ("admin", "manager"):
                    ticket.status = val
                    changed = True
                else:
                    continue
            else:
                if hasattr(ticket, key):
                    setattr(ticket, key, val)
                    changed = True
        oldFilesID = request.data.getlist("oldFiles")
        if len(oldFilesID) == 0:
              SupportAttachment.objects.filter(ticket=ticket).all().delete()
        # handle attachments if any (append)
        files = request.FILES.getlist("attachments")
        if files:
            for f in files:
                SupportAttachment.objects.create(ticket=ticket, file=f)
            changed = True
       
        

        isDeletetheOledFiles = request.data.getlist("isDeletetheOledFiles")
        if isDeletetheOledFiles:
                for ID in isDeletetheOledFiles:
                   SupportAttachment.objects.filter(id=ID).delete()
        if changed:
            ticket.save()

        notifications = []
        if changed:
            try:
                with transaction.atomic():
                    admins = User.objects.filter(account__role__in=("admin", "manager")).all()
                    actor_name = ( user.username)
                    for admin in admins:
                        notif_title = f"Ticket : {ticket.title} a été mis à jour"
                        # Compose a compact summary of changes (you can extend this)
                        notif_content = (
                            f"Bonjour {admin.username},\n\n"
                            f"Le ticket #{ticket.id} (« {ticket.title} ») a été mis à jour par {actor_name} "
                            f"le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                            f"Priorité: {ticket.priority}\n"
                            f"Statut: {ticket.status}\n"
                            "Consultez le ticket pour plus de détails."
                        )
                        try:
                            notif = create_notification(
                                title=notif_title,
                                content=notif_content,
                                recipient=admin,
                                notification_date=timezone.localdate(),
                                notification_time=timezone.localtime().time()
                            )
                            notifications.append(notif)
                        except:
                            pass
            except Exception as exc:
               pass

        # send emails (best-effort)
        for notif in notifications:
            try:
                send_result = send_notification_email(notification=notif)
            except Exception as exc:
                pass

        return Response({"message": "Le ticket a été mis à jour avec succès.", "ticket": _ticket_to_dict(ticket, request)}, status=status.HTTP_200_OK)
    
    def delete(self, request, pk, *args, **kwargs):
        # manager/admin only
        user, err_resp = authenticate_and_authorize(request, allowed_roles=("admin", "manager"))
        if err_resp:
            return err_resp
        tikket = get_object_or_404(SupportTicket, pk=pk)
        tikket.delete()
        return Response({"message": "Le ticket de support a été supprimé."}, status=status.HTTP_200_OK)

# Ticket replies (list + manager add)
# -------------------------
class TicketRepliesAPIView(APIView):
    """
    GET  /api/support/tickets/<pk>/replies/  -> list replies (inspector only for own ticket)
    POST /api/support/tickets/<pk>/replies/  -> add reply (manager/admin only)  <-- uses authenticate_and_authorize
    """

    def get(self, request, pk, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        ticket = get_object_or_404(SupportTicket, pk=pk)
        account = getattr(user, "account", None)
        role = getattr(account, "role", None) if account else None

        if role not in ("admin", "manager") and ticket.created_by_id != user.id:
            return Response({"message": "Permission refusée."}, status=status.HTTP_403_FORBIDDEN)

        replies = [ _reply_to_dict(r, request) for r in ticket.replies.order_by("created_at").all() ]
        return Response({"ticket": _ticket_to_dict(ticket, request, include_replies=False), "replies": replies}, status=status.HTTP_200_OK)

    def post(self, request, pk, *args, **kwargs):
        # Only manager/admin can add replies (per your spec)
        user, err_resp = authenticate_and_authorize(request, allowed_roles=("admin", "manager"))
        if err_resp:
            return err_resp

        ticket = get_object_or_404(SupportTicket, pk=pk)
        message = (request.data.get("message") or "").strip()
        if not message:
            return Response({"message": "Un message de réponse est requis."}, status=status.HTTP_400_BAD_REQUEST)

        notif = None
        reply = None
        try:
            with transaction.atomic():
                reply = SupportReply.objects.create(ticket=ticket, author=user, message=message)
                files = request.FILES.getlist("attachments")
                for f in files:
                    SupportAttachment.objects.create(reply=reply, file=f)
                ticket.status = SupportTicketStatus.RESOLVED
                ticket.save()
                # Create a Notification record for the ticket creator
                ticket_creator = ticket.created_by
                if ticket_creator:
                    actor_name = (user.username)
                    notif_title = f"Nouvelle réponse au ticket (« {ticket.title} ») "
                    notif_content = (
                        f"Bonjour {ticket_creator.username},\n\n"
                        f"Le ticket #{ticket.id} (« {ticket.title} ») a reçu une réponse de {actor_name} "
                        f"le {timezone.localtime().strftime('%d %B %Y à %H:%M')}.\n\n"
                        f"Message :\n{message}\n\n"
                        "Consultez le ticket pour plus de détails."
                    )
                    try:
                        notif = create_notification(
                            title=notif_title,
                            content=notif_content,
                            recipient=ticket_creator,
                            notification_date=timezone.localdate(),
                            notification_time=timezone.localtime().time()
                        )
                    except :
                       pass

        except :
            pass

        # Best-effort: send email after transaction
        if notif:
            try:
                send_result = send_notification_email(notification=notif)
            except Exception as exc:
                pass

        
        return Response({"message": "Réponse ajoutée.", "reply": _reply_to_dict(reply, request)}, status=status.HTTP_201_CREATED)


# -------------------------
# Reply detail / delete
# -------------------------
class ReplyDetailAPIView(APIView):
    """
    GET /api/support/replies/<pk>/   -> get a reply (manager/admin OR ticket owner)
    DELETE /api/support/replies/<pk>/ -> delete reply (manager/admin only)
    """
    def get(self, request, pk, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        reply = get_object_or_404(SupportReply, pk=pk)
        ticket = reply.ticket
        account = getattr(user, "account", None)
        role = getattr(account, "role", None) if account else None

        if role in ("admin", "manager") or ticket.created_by_id == user.id:
            return Response({"reply": _reply_to_dict(reply, request)}, status=status.HTTP_200_OK)

        return Response({"message": "Permission refusée."}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, pk, *args, **kwargs):
        # manager/admin only
        user, err_resp = authenticate_and_authorize(request, allowed_roles=("admin", "manager"))
        if err_resp:
            return err_resp

        reply = get_object_or_404(SupportReply, pk=pk)
        reply.delete()
        return Response({"message": "Réponse supprimée."}, status=status.HTTP_204_NO_CONTENT)


class MyTicketsAPIView(APIView):
    """
    GET /api/support/my-tickets/
    Returns only the tickets created by the currently authenticated user.
    Uses authenticate_and_authorize_allUser() (no role check) so token auth is reused.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        qs = SupportTicket.objects.filter(created_by=user).order_by('-created_at')

        if not qs.exists():
            # Return a clear message when the inspector has no tickets
            return Response(
                {"message": "Vous n'avez encore envoyé aucune demande", "tickets": [], "count": 0},
                status=status.HTTP_404_NOT_FOUND
            )

        tickets = [_ticket_to_dict(t, request, include_replies=False) for t in qs]
        return Response({"tickets": tickets, "count": len(tickets)}, status=status.HTTP_200_OK)

# notifications 
# 
def _notification_to_dict(n: Notification):
    """Serialize a notification for the frontend."""
    # Compose createdAt in ISO format (frontend expects date strings)
    created_at = n.created_at.isoformat() if n.created_at else None
    # format notification_date/time if you need them separately
    notification_date = n.notification_date.isoformat() if n.notification_date else None
    notification_time = n.notification_time.isoformat() if n.notification_time else None

    return {
        "id": n.id,
        "title": n.title,
        "message": n.content,
        "notification_date": notification_date,
        "notification_time": notification_time,
        "createdAt": created_at,
        "recipient_id": n.recipient.id,
        "recipient": n.recipient.username,
        "notification_status": n.notification_status,
        "isRead": n.notification_status == NotificationStatus.READ,
    }

class MyNotificationsView(APIView):
    """
    GET  /notifications/my/                 -> list notifications for the authenticated user (with counts)
    PUT  /notifications/my/<int:notification_id>/ -> update a notification (default: mark as read)
    """

    def get(self, request, notification_id=None, *args, **kwargs):
        # Authenticate using your project helper
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        qs = Notification.objects.filter(recipient=user).order_by('-notification_date', '-notification_time', '-created_at')

        total = qs.count()
        read_count = qs.filter(notification_status=NotificationStatus.READ).count()
        unread_count = qs.filter(notification_status=NotificationStatus.UNREAD).count()
        if not qs :
            return Response({
            "message": "Il n'y a actuellement aucune notification.",
            "count": total,
            "counts": {
                "read": read_count,
                "unread": unread_count
                 }
               }, status=status.HTTP_400_BAD_REQUEST)
        notifications = [_notification_to_dict(n) for n in qs]

        return Response({
            "notifications": notifications,
            "count": total,
            "counts": {
                "read": read_count,
                "unread": unread_count
            }
        }, status=status.HTTP_200_OK)

    def put(self, request, notification_id=None, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        if not notification_id:
            return Response({"message": "notification_id is required in URL."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            notification = Notification.objects.get(pk=notification_id)
        except Notification.DoesNotExist:
            return Response({"message": "Notification non trouvée."}, status=status.HTTP_404_NOT_FOUND)

        if notification.recipient_id != user.id:
            return Response({"message": "Vous n'êtes pas autorisé à modifier cette notification."}, status=status.HTTP_403_FORBIDDEN)

        new_status = request.data.get("notification_status")
        # default behaviour: mark as READ
        if not new_status:
            new_status = NotificationStatus.READ

        # validate
        if new_status not in NotificationStatus.values:
            return Response({"message": f"Statut invalide. Choisissez parmi {list(NotificationStatus.values)}"}, status=status.HTTP_400_BAD_REQUEST)

        # If no change, short-circuit
        if notification.notification_status == new_status:
            return Response({
                "message": "Le statut est déjà celui demandé.",
                "notification": _notification_to_dict(notification)
            }, status=status.HTTP_200_OK)

        try:
            with transaction.atomic():
                notification.notification_status = new_status
                notification.save(update_fields=['notification_status', 'updated_at'] if hasattr(notification, 'updated_at') else ['notification_status'])
        except Exception:
            return Response({"message": "Échec lors de la mise à jour du statut de la notification."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # recompute counts for the user
        qs = Notification.objects.filter(recipient=user)
        total = qs.count()
        read_count = qs.filter(notification_status=NotificationStatus.READ).count()
        unread_count = qs.filter(notification_status=NotificationStatus.UNREAD).count()

        return Response({
            "message": "Statut de la notification mis à jour.",
            "notification": _notification_to_dict(notification),
            "counts": {"total": total, "read": read_count, "unread": unread_count}
        }, status=status.HTTP_200_OK)    


    def delete(self, request, notification_id=None, *args, **kwargs):
        """
        Delete a single notification by ID, or delete all notifications for the authenticated user
        when ?all=true is present and no notification_id is provided.
        """
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        delete_all_flag = str(request.query_params.get('all', '')).lower() == 'true' or bool(request.data.get('all'))

        # If deleting all and no specific id provided
        if delete_all_flag and not notification_id:
            try:
                with transaction.atomic():
                    qs = Notification.objects.filter(recipient=user)
                    deleted_count = qs.count()
                    qs.delete()
            except Exception:
                return Response({"message": "Échec lors de la suppression des notifications."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({
                "message": f"{deleted_count} notification(s) supprimée(s).",
                "counts": {"total": 0, "read": 0, "unread": 0}
            }, status=status.HTTP_200_OK)

        # Otherwise delete a single notification by id
        if not notification_id:
            return Response({"message": "notification_id is requis dans l'URL, ou utilisez ?all=true pour supprimer toutes les notifications."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            notification = Notification.objects.get(pk=notification_id)
        except Notification.DoesNotExist:
            return Response({"message": "Notification non trouvée."}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the requester owns the notification (can't delete others')
        if notification.recipient_id != user.id:
            return Response({"message": "Vous n'êtes pas autorisé à supprimer cette notification."}, status=status.HTTP_403_FORBIDDEN)

        try:
            with transaction.atomic():
                notification.delete()
        except Exception:
            return Response({"message": "Échec lors de la suppression de la notification."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # recompute counts
        qs = Notification.objects.filter(recipient=user)
        total = qs.count()
        read_count = qs.filter(notification_status=NotificationStatus.READ).count()
        unread_count = qs.filter(notification_status=NotificationStatus.UNREAD).count()

        return Response({
            "message": "Notification supprimée avec succès.",
            "counts": {"total": total, "read": read_count, "unread": unread_count}
        }, status=status.HTTP_200_OK)  

# Reicent actevity
# views.py
from django.db.models import Prefetch


class RecentActivityAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            limit = int(request.query_params.get("limit", 6))
        except (TypeError, ValueError):
            limit = 6

        # helper to build activity items for each model instance
        def map_reservation(r):
            material = getattr(r, "material", None)
            material_name = getattr(material, "name", "—")
            return {
                "type": "reservation",
                "id": f"res-{r.id}",
                "entity_id": r.id,
                "title": f"{getattr(r.created_by, 'username', '—')} - {material_name}",
                "subtitle": r.purpose or "",
                "createdAt": r.created_at,
                "status": r.status or ""
            }

        def map_malfunction(m):
            return {
                "type": "malfunction",
                "id": f"mal-{m.id}",
                "entity_id": m.id,
                "title": f"{getattr(m.reported_by, 'username', '—')} - {getattr(m.material, 'name', '—')}",
                "subtitle": (m.description or "")[:120],
                "createdAt": m.created_at,
                "status": m.status or ""
            }

        def map_ticket(t):
            return {
                "type": "ticket",
                "id": f"tkt-{t.id}",
                "entity_id": t.id,
                "title": f"{getattr(t.created_by, 'username', '—')} - {t.title}",
                "subtitle": (t.description or "")[:120],
                "createdAt": t.created_at,
                "status": t.status or ""
            }

        # initial per-model fetch size
        per_model_fetch = max(limit, 6)

        # fetch recent items from each source (select_related to reduce queries)
        recent_res = list(Reservation.objects.select_related("created_by", "material").order_by("-created_at")[:per_model_fetch])
        recent_mal = list(Malfunction.objects.select_related("reported_by", "material").order_by("-created_at")[:per_model_fetch])
        recent_tkt = list(SupportTicket.objects.select_related("created_by").order_by("-created_at")[:per_model_fetch])

        # map to unified shape
        activities = []
        activities.extend(map_reservation(r) for r in recent_res)
        activities.extend(map_malfunction(m) for m in recent_mal)
        activities.extend(map_ticket(t) for t in recent_tkt)

        # sort unified list by createdAt desc and pick top `limit`
        activities_sorted = sorted(
            activities,
            key=lambda a: a["createdAt"] if a["createdAt"] is not None else timezone.now(),
            reverse=True
        )[:limit]

        # if we didn't reach `limit` but there might be more items in sources,
        # try once to fetch a larger window (fall-back to second pass).
        if len(activities_sorted) < limit:
            # increase fetch window
            per_model_fetch_2 = per_model_fetch * 2
            recent_res2 = list(Reservation.objects.select_related("created_by", "material").order_by("-created_at")[:per_model_fetch_2])
            recent_mal2 = list(Malfunction.objects.select_related("reported_by", "material").order_by("-created_at")[:per_model_fetch_2])
            recent_tkt2 = list(SupportTicket.objects.select_related("created_by").order_by("-created_at")[:per_model_fetch_2])

            activities2 = []
            activities2.extend(map_reservation(r) for r in recent_res2)
            activities2.extend(map_malfunction(m) for m in recent_mal2)
            activities2.extend(map_ticket(t) for t in recent_tkt2)

            activities_sorted = sorted(
                activities2,
                key=lambda a: a["createdAt"] if a["createdAt"] is not None else timezone.now(),
                reverse=True
            )[:limit]

        # convert datetimes to isoformat for JSON
        for a in activities_sorted:
            dt = a.get("createdAt")
            if hasattr(dt, "isoformat"):
                # use timezone-aware localtime isoformat for client
                a["createdAt"] = timezone.localtime(dt).isoformat()
            else:
                # fallback to string
                a["createdAt"] = str(dt)

        return Response({"activity": activities_sorted, "count": len(activities_sorted)}, status=status.HTTP_200_OK)
# statics
class DashboardStatsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user, err_resp = authenticate_and_authorize_allUser(request)
        if err_resp:
            return err_resp

        try:
            # --- Users ---
            total_users = User.objects.count()
            active_users = Account.objects.filter(status=AccountStatus.ACTIVE).count()

            # --- Assets (Materials) overall ---
            total_assets = Material.objects.count()

            available_assets = Material.objects.filter(
                reservationStatus=MaterialReservationStatus.AVAILABLE
            ).count()

            reserved_assets = Material.objects.filter(
                reservationStatus=MaterialReservationStatus.RESERVED
            ).count()

            out_of_service_assets = Material.objects.filter(
                Q(reservationStatus=MaterialReservationStatus.NOT_AVAILABLE) |
                Q(status__in=[MaterialStatus.UNDER_MAINTENANCE, MaterialStatus.PENDING_MAINTENANCE])
            ).distinct().count()

            # --- Reservations ---
            total_reservations = Reservation.objects.count()
            pending_reservations = Reservation.objects.filter(status=ReservationStatus.PENDING).count()
            accepted_reservations = Reservation.objects.filter(status=ReservationStatus.ACCEPTED).count()
            declined_reservations = Reservation.objects.filter(status=ReservationStatus.DECLINED).count()
            completed_reservations = Reservation.objects.filter(status=ReservationStatus.COMPLETED).count()

            # --- Assets by type (vehicles / tools) ---
            vehicles_qs = Material.objects.filter(type=MaterialType.VEHICLE)
            vehicles_total = vehicles_qs.count()
            vehicles_available = vehicles_qs.filter(reservationStatus=MaterialReservationStatus.AVAILABLE).count()
            vehicles_reserved = vehicles_qs.filter(reservationStatus=MaterialReservationStatus.RESERVED).count()
            vehicles_out = vehicles_qs.filter(
                Q(reservationStatus=MaterialReservationStatus.NOT_AVAILABLE) |
                Q(status__in=[MaterialStatus.UNDER_MAINTENANCE, MaterialStatus.PENDING_MAINTENANCE])
            ).distinct().count()

            tools_qs = Material.objects.filter(type=MaterialType.TOOL)
            tools_total = tools_qs.count()
            tools_available = tools_qs.filter(reservationStatus=MaterialReservationStatus.AVAILABLE).count()
            tools_reserved = tools_qs.filter(reservationStatus=MaterialReservationStatus.RESERVED).count()
            tools_out = tools_qs.filter(
                Q(reservationStatus=MaterialReservationStatus.NOT_AVAILABLE) |
                Q(status__in=[MaterialStatus.UNDER_MAINTENANCE, MaterialStatus.PENDING_MAINTENANCE])
            ).distinct().count()

            assets_by_type = {
                "vehicles": {
                    "total": vehicles_total,
                    "available": vehicles_available,
                    "reserved": vehicles_reserved,
                    "out_of_service": vehicles_out,
                },
                "tools": {
                    "total": tools_total,
                    "available": tools_available,
                    "reserved": tools_reserved,
                    "out_of_service": tools_out,
                }
            }

            payload = {
                "users": {"total": total_users, "active": active_users},
                "assets": {
                    "total": total_assets,
                    "available": available_assets,
                    "reserved": reserved_assets,
                    "out_of_service": out_of_service_assets,
                },
                "reservations": {
                    "total": total_reservations,
                    "pending": pending_reservations,
                    "accepted": accepted_reservations,
                    "declined": declined_reservations,
                    "completed": completed_reservations,
                },
                "assets_by_type": assets_by_type,
            }

            return Response(payload, status=status.HTTP_200_OK)

        except Exception as exc:
            return Response(
                {"message": "Erreur lors de la récupération des statistiques.", "detail": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )