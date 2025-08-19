from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer , TokenRefreshSerializer

from scarabe_server import settings
from .models import Account, AccountTypes
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from datetime import timedelta


import os
import logging
from datetime import timedelta
from email.mime.image import MIMEImage

from django.conf import settings
from django.template import Template, Context
from django.utils.html import strip_tags
from django.utils.timezone import now, localtime
from django.core.mail import EmailMultiAlternatives

from rest_framework import serializers
from django.utils.crypto import get_random_string

# logger
logger = logging.getLogger(__name__)


class AccountSerializer(serializers.ModelSerializer):
    username        = serializers.CharField(source='user.username', read_only=True)
    email            = serializers.EmailField(source='user.email',    read_only=True)
    whatsapp_number  = serializers.CharField()
    role             = serializers.ChoiceField(choices=AccountTypes.choices)
    status           = serializers.CharField(read_only=True)
    created_at       = serializers.DateTimeField(format="%Y-%m-%dT%H:%M:%SZ", read_only=True)
    updated_at       = serializers.DateTimeField(format="%Y-%m-%dT%H:%M:%SZ", read_only=True)
    last_connected   = serializers.DateTimeField(format="%Y-%m-%dT%H:%M:%SZ", allow_null=True)
    registration_date= serializers.DateTimeField(format="%Y-%m-%dT%H:%M:%SZ", read_only=True)
    rest_code        = serializers.CharField(read_only=True)
    rest_code_expires= serializers.DateTimeField(format="%Y-%m-%dT%H:%M:%SZ", read_only=True)

    class Meta:
        model  = Account
        fields = [
        'id', 'username', 'email',
        'whatsapp_number', 'role', 'status',
        'created_at', 'updated_at', 'last_connected',
        'registration_date', 'rest_code', 'rest_code_expires',
    ]


class TokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'  # tell SimpleJWT to authenticate by email

    @classmethod
    def get_token(cls, user):
        # Get the default token with standard claims (user_id, exp, etc.)
        token = super().get_token(user)

        # Add custom claims here
        token['role'] = user.account.role  # assuming role is in a related Account model
        return token
    
class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        try:
            refresh = RefreshToken(attrs['refresh'])
            data = {}
            access_token = refresh.access_token

            # Get user from user_id claim inside the refresh token
            user_id = refresh['user_id']
            user = User.objects.get(id=user_id)

            # Add custom claims
            access_token['role'] = user.account.role
            # Return both tokens
            data['access'] = str(access_token)
            data['refresh'] = str(refresh)

            return data

        except TokenError as e:
            raise InvalidToken(e.args[0])

######
# email sent
def _make_html_paragraphs(text):
    """Convert plaintext with newlines into safe HTML paragraphs."""
    lines = [ln.strip() for ln in (text or '').splitlines()]
    paragraphs = [
        f'<p style="margin:0 0 12px 0; color:#374151; line-height:1.5;">{ln}</p>'
        for ln in lines if ln
    ]
    return ''.join(paragraphs) or '<p style="margin:0 0 12px 0; color:#374151;">(Aucune information)</p>'


# HTML email template (same structure you provided)
_HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{{ site_name }} - {{ short_title }}</title>
</head>
<body style="font-family: Inter, Arial, Helvetica, sans-serif; background: #f6f8fb; margin:0; padding:20px;">
  <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
    <tr>
      <td align="center">
        <table width="700" cellpadding="0" cellspacing="0" role="presentation" style="background:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 8px 30px rgba(11,37,69,0.06);">
          <!-- header -->
          <tr>
            <td style="padding:18px 22px; border-bottom:1px solid #eef2f6;">
              <table width="100%" role="presentation" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="vertical-align:middle;">
                    <div style="display:flex; align-items:center; gap:12px;">
                      {% if logo_use_cid %}
                        <img src="cid:{{ logo_cid }}" alt="{{ site_name }}" style="height:44px; object-fit:contain; display:block;" />
                      {% elif logo_url %}
                        <img src="{{ logo_url }}" alt="{{ site_name }}" style="height:44px; object-fit:contain; display:block;" />
                      {% else %}
                        <div style="width:44px;height:44px;border-radius:8px;background:#0ea5a5;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;">VY</div>
                      {% endif %}
                      <div>
                        <div style="font-size:18px; font-weight:700; color:#0b2545;">{{ site_name }}</div>
                        <div style="font-size:12px; color:#6b7280;">Notification système</div>
                      </div>
                    </div>
                  </td>
                  <td style="text-align:right; vertical-align:middle; font-size:12px; color:#6b7280;">
                    <div>{{ generation_date }}</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- body -->
          <tr>
            <td style="padding:22px 28px;">
              <h2 style="margin:0 0 12px 0; font-size:16px; color:#0b2545;">{{ title }}</h2>
              {{ content_html|safe }}
              {% if action_url %}
                <div style="margin-top:18px;">
                  <a href="{{ action_url }}" style="display:inline-block; text-decoration:none; padding:10px 14px; border-radius:8px; background:#0b2545; color:#fff; font-weight:600;">{{ action_text }}</a>
                </div>
              {% endif %}

              <div style="margin-top:18px; color:#6b7280; font-size:13px;">
                <strong>Destinataire:</strong> {{ recipient_name }}<br/>
              </div>
            </td>
          </tr>

          <!-- footer -->
          <tr>
            <td style="padding:16px 22px; border-top:1px solid #eef2f6; font-size:12px; color:#6b7280;">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>{{ site_name }} — Gestion de parc</div>
                <div style="text-align:right;">
                  <div>Envoyé le {{ generation_date }}</div>
                  {% if site_url %}
                    <div><a href="{{ site_url }}" style="color:#0b2545; text-decoration:none;">{{ site_url }}</a></div>
                  {% endif %}
                </div>
              </div>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""


def _send_styled_email(to_email, subject, title, content_plain, recipient_name=None, action_url=None, action_text="Voir", from_email=None):
    """
    Send a styled HTML email (with plain-text fallback). Returns dict { ok, error }.
    This does NOT create Notification objects — it's a direct email send.
    """
    from_email = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None) or "no-reply@example.com"
    site_name = getattr(settings, "SITE_NAME", "VeYoo")
    site_url = getattr(settings, "SITE_URL", "")
    logo_url = getattr(settings, "EMAIL_LOGO_URL", None)
    attach_inline_logo = getattr(settings, "EMAIL_LOGO_PATH", None)

    # build content html
    content_html = _make_html_paragraphs(content_plain)

    ctx = {
        "site_name": site_name,
        "site_url": site_url,
        "logo_url": logo_url,
        "title": title,
        "short_title": title,
        "content_html": content_html,
        "recipient_name": recipient_name or "",
        "generation_date": localtime(now()).strftime("%d %B %Y %H:%M"),
        "action_url": action_url or "",
        "action_text": action_text,
        "logo_use_cid": False,
        "logo_cid": "logo_cid",
    }

    try:
        tmpl = Template(_HTML_TEMPLATE)
        html_content = tmpl.render(Context(ctx))
    except Exception as exc:
        logger.exception("Failed to render email template: %s", exc)
        html_content = f"<h3>{title}</h3>{content_html}"

    text_content = strip_tags(html_content)
    subject_line = subject

    try:
        msg = EmailMultiAlternatives(subject=subject_line, body=text_content, from_email=from_email, to=[to_email])

        # If inline logo configured and exists, attach as CID
        if attach_inline_logo:
            # Resolve relative to BASE_DIR when needed
            logo_path = attach_inline_logo
            if not os.path.isabs(logo_path) and getattr(settings, "BASE_DIR", None):
                logo_path = os.path.join(getattr(settings, "BASE_DIR"), logo_path)

            if os.path.exists(logo_path):
                try:
                    with open(logo_path, "rb") as f:
                        logo_data = f.read()
                    msg.mixed_subtype = "related"
                    ctx["logo_use_cid"] = True
                    tmpl = Template(_HTML_TEMPLATE)
                    html_content = tmpl.render(Context(ctx))
                    msg.attach_alternative(html_content, "text/html")

                    image = MIMEImage(logo_data)
                    image.add_header("Content-ID", "<logo_cid>")
                    image.add_header("Content-Disposition", "inline", filename=os.path.basename(logo_path))
                    msg.attach(image)
                except Exception as exc_attach:
                    logger.exception("Failed to attach inline logo: %s", exc_attach)
                    ctx["logo_use_cid"] = False
                    tmpl = Template(_HTML_TEMPLATE)
                    html_content = tmpl.render(Context(ctx))
                    msg.attach_alternative(html_content, "text/html")
            else:
                logger.warning("EMAIL_LOGO_PATH set but file not found: %s", logo_path)
                ctx["logo_use_cid"] = False
                tmpl = Template(_HTML_TEMPLATE)
                html_content = tmpl.render(Context(ctx))
                msg.attach_alternative(html_content, "text/html")
        else:
            # No inline logo: render normal html (may use logo_url)
            ctx["logo_use_cid"] = False
            tmpl = Template(_HTML_TEMPLATE)
            html_content = tmpl.render(Context(ctx))
            msg.attach_alternative(html_content, "text/html")

        msg.send(fail_silently=False)
        logger.info("Reset code email sent to %s", to_email)
        return {"ok": True, "error": None}
    except Exception as exc_send:
        logger.exception("Failed to send reset email to %s: %s", to_email, exc_send)
        return {"ok": False, "error": exc_send}


class ResetCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Cet e-mail n'est associé à aucun compte.")
        return value

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        account = getattr(user, "account", None)
        if account is None:
            # If you expect account to always exist, raise or handle accordingly
            raise serializers.ValidationError("Compte utilisateur introuvable.")

        # 1) generate code and persist on account
        code = get_random_string(length=6, allowed_chars='0123456789')
        account.rest_code = code
        account.rest_code_expires = now() + timedelta(minutes=10)
        account.save()

        # 2) prepare email content
        title = self.context.get("title", "Code de réinitialisation")
        # Content: include code and instructions
        content_lines = [
            f"Bonjour {getattr(user, 'get_full_name', lambda: user.username)() if callable(getattr(user, 'get_full_name', None)) else getattr(user, 'username', '')},",
            "",
            "Vous avez demandé à réinitialiser votre mot de passe. Voici votre code de réinitialisation (valable 10 minutes):",
            "",
            f"Code: {code}",
            "",
            "Si vous n'avez pas demandé ce code, veuillez ignorer cet e-mail ou contacter un administrateur.",
        ]
        content_plain = "\n".join([ln for ln in content_lines if ln is not None])

        # 3) send styled email (no Notification record)
        send_result = _send_styled_email(
            to_email=email,
            subject=f"[{getattr(settings, 'SITE_NAME', 'VeYoo')}] {title}",
            title=title,
            content_plain=content_plain,
            recipient_name=user.username,
            action_url=None,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None)
        )

        if not send_result.get("ok"):
            # Log already done; optionally raise or return partial success
            logger.warning("Reset code saved but email failed to send: %s", send_result.get("error"))

        # return minimal info; do NOT include code in API response for security
        return {"email": email}
    

class ConfirmEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Cet e-mail n'est associé à aucun compte.")
        return value

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        account = getattr(user, "account", None)
        if account is None:
            raise serializers.ValidationError("Compte utilisateur introuvable.")

        # 1) Generate confirmation code and persist
        code = account.rest_code

        # 2) Prepare email content
        title = self.context.get("title", "Confirmez votre adresse e-mail")
        content_lines = [
            f"Bonjour {user.get_full_name() if hasattr(user, 'get_full_name') else getattr(user, 'username', '')},",
            "",
            "Merci de vous être inscrit sur notre plateforme.",
            "Veuillez confirmer votre adresse e-mail en utilisant le code ci-dessous (valable 10 minutes) :",
            "",
            f"Code: {code}",
            "",
            "Si vous n'avez pas créé de compte, veuillez ignorer cet e-mail.",
        ]
        content_plain = "\n".join(content_lines)

        # 3) Send styled email
        send_result = _send_styled_email(
            to_email=email,
            subject=f"[{getattr(settings, 'SITE_NAME', 'VeYoo')}] {title}",
            title=title,
            content_plain=content_plain,
            recipient_name= user.username,
            action_url=None,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None)
        )

        if not send_result.get("ok"):
            logger.warning("Confirmation code saved but email failed to send: %s", send_result.get("error"))

        return {"email": email}

class VerificationCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Cet e-mail n'est associé à aucun compte.")
        return value

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        account = getattr(user, "account", None)
        if account is None:
            raise serializers.ValidationError("Compte utilisateur introuvable.")

        # 1) Generate verification code and persist
        code = account.rest_code
       

        # 2) Prepare generic email content
        title = self.context.get("title", "Votre nouveau code de vérification")
        content_lines = [
            f"Bonjour {user.get_full_name() if hasattr(user, 'get_full_name') else getattr(user, 'username', '')},",
            "",
            "Voici votre nouveau code de vérification (valable 10 minutes) :",
            "",
            f"Code: {code}",
            "",
            "Si vous n'avez pas demandé ce code, veuillez ignorer cet e-mail.",
        ]
        content_plain = "\n".join(content_lines)

        # 3) Send styled email
        send_result = _send_styled_email(
            to_email=email,
            subject=f"[{getattr(settings, 'SITE_NAME', 'VeYoo')}] {title}",
            title=title,
            content_plain=content_plain,
            recipient_name=user.username,
            action_url=None,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None)
        )

        if not send_result.get("ok"):
            logger.warning("Verification code saved but email failed to send: %s", send_result.get("error"))

        # return minimal info; do NOT include code in API response for security
        return {"email": email}    