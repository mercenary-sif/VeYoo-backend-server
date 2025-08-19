from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth import get_user_model

User = get_user_model()

def authenticate_and_authorize(request, allowed_roles=("admin", "manager")):
    # 1) auth
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, Response({"message": "En-tête d'autorisation manquant ou invalide."},
                              status=status.HTTP_401_UNAUTHORIZED)
    
    token = auth_header.split()[1]
    try:
        validated = JWTAuthentication().get_validated_token(token)
        user_id = validated.get("user_id")
        user = User.objects.get(id=user_id)
    except (InvalidToken, TokenError, User.DoesNotExist):
        return None, Response({"message": "Token invalide ou utilisateur introuvable."},
                              status=status.HTTP_401_UNAUTHORIZED)

    # 2) permission
    account = getattr(user, "account", None)
    if not account or account.role not in allowed_roles:
        return None, Response({"message": "Permission refusée."},
                              status=status.HTTP_403_FORBIDDEN)

    return user, None

def authenticate_and_authorize_allUser(request):
    # 1) auth
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, Response({"message": "En-tête d'autorisation manquant ou invalide."},
                              status=status.HTTP_401_UNAUTHORIZED)
    
    token = auth_header.split()[1]
    try:
        validated = JWTAuthentication().get_validated_token(token)
        user_id = validated.get("user_id")
        user = User.objects.get(id=user_id)
    except (InvalidToken, TokenError, User.DoesNotExist):
        return None, Response({"message": "Token invalide ou utilisateur introuvable."},
                              status=status.HTTP_401_UNAUTHORIZED)

    return user, None
