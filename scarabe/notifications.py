# app/services/notifications.py
import os
import logging
from datetime import date
from email.mime.image import MIMEImage

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template import Template, Context
from django.utils.html import strip_tags
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
from django.utils.safestring import mark_safe

from .models import Notification, NotificationStatus

logger = logging.getLogger(__name__)

DEFAULT_FROM_EMAIL = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@example.com')
SITE_NAME = getattr(settings, 'SITE_NAME', 'VeYoo')
SITE_URL = getattr(settings, 'SITE_URL', '')  # e.g. https://app.example.com


# ---------------------------------------------------------------------
# 1) create_notification - save Notification record
# ---------------------------------------------------------------------
@transaction.atomic
def create_notification(*, title, content, recipient, notification_date=None, notification_time=None, notification_status=None):
    # resolve recipient by ID or keep instance
    if isinstance(recipient, int):
        recipient = User.objects.get(pk=recipient)

    if recipient is None:
        raise ValueError("recipient must be a User instance or user id")

    notification_date = notification_date if notification_date is not None else date.today()
    notification_time = notification_time if notification_time is not None else timezone.localtime().time()
    notification_status = notification_status or NotificationStatus.UNREAD

    notif = Notification.objects.create(
        title=title,
        content=content,
        notification_date=notification_date,
        notification_time=notification_time,
        recipient=recipient,
        notification_status=notification_status
    )
    return notif


# ---------------------------------------------------------------------
# helper for building safe HTML from plaintext
# ---------------------------------------------------------------------
def _make_html_paragraphs(text):
    """Convert plaintext with newlines into safe HTML paragraphs."""
    lines = [ln.strip() for ln in (text or '').splitlines()]
    paragraphs = [f'<p style="margin:0 0 12px 0; color:#374151; line-height:1.5;">{ln}</p>' for ln in lines if ln]
    return ''.join(paragraphs) or '<p style="margin:0 0 12px 0; color:#374151;">(Aucune information)</p>'


# ---------------------------------------------------------------------
# 2) send_notification_email - styled HTML email (with plain text fallback)
# ---------------------------------------------------------------------
def send_notification_email(notification=None, *, title=None, content=None, recipient=None, site_url=None, from_email=None):
    """
    Send a styled HTML email for a notification. Either pass a Notification instance
    OR pass (title, content, recipient) and this will create the Notification record.
    Returns dict: { "ok": True/False, "error": None or exception, "notification_id": id_or_None }
    """

    # 1) ensure we have a Notification instance
    try:
        if notification is None:
            if not (title and content and recipient):
                raise ValueError("title, content and recipient are required when notification is not provided")
            notification = create_notification(title=title, content=content, recipient=recipient)
    except Exception as exc:
        logger.exception("Failed to create notification: %s", exc)
        return {"ok": False, "error": exc, "notification_id": None}

    # 2) recipient email check
    rec = notification.recipient
    to_email = getattr(rec, "email", None)
    if not to_email:
        err = ValueError("recipient has no email")
        logger.warning("Notification %s has no recipient email", notification.pk)
        return {"ok": False, "error": err, "notification_id": notification.pk}

    # 3) email settings
    from_email = from_email or DEFAULT_FROM_EMAIL
    site_url = site_url or SITE_URL or ""

    # 4) prepare safe HTML for notification.content (no <br/>)
    content_html = mark_safe(_make_html_paragraphs(notification.content))

    # 5) HTML template (inline styles, small and semantic)
    html_template = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>{{ site_name }} - Notification</title>
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
                        <div style="margin-top:4px;">ID: <strong style="color:#0b2545">{{ notification_id }}</strong></div>
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
                      <a href="{{ action_url }}" style="display:inline-block; text-decoration:none; padding:10px 14px; border-radius:8px; background:#0b2545; color:#fff; font-weight:600;">Voir la notification</a>
                    </div>
                  {% endif %}

                  <div style="margin-top:18px; color:#6b7280; font-size:13px;">
                    <strong>Destinataire:</strong> {{ recipient_name }}<br/>
                    <strong>Référence:</strong> {{ notification_id }} · <strong>Statut:</strong> {{ status }}
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

    # 6) build template context
    context = {
        "site_name": SITE_NAME,
        "site_url": site_url,
        "logo_url": getattr(settings, "EMAIL_LOGO_URL", None),  # prefer public URL if available
        "title": notification.title,
        "content_html": content_html,
        "notification_id": notification.pk,
        "recipient_name": notification.recipient.username or '',
        "status": dict(NotificationStatus.choices).get(notification.notification_status, notification.notification_status),
        "action_url": f"{site_url}/notifications/{notification.pk}" if site_url else "",
        "generation_date": timezone.localtime(notification.created_at).strftime("%d %B %Y %H:%M"),
        # inline image flags (may be toggled below)
        "logo_use_cid": False,
        "logo_cid": "logo_cid",
    }

    # prepare rendered html (we will re-render if embedding inline logo)
    try:
        tmpl = Template(html_template)
        html_content = tmpl.render(Context(context))
    except Exception as exc_render:
        logger.exception("Template render failed; falling back to simple HTML: %s", exc_render)
        html_content = f"<h3>{notification.title}</h3>{content_html}"

    text_content = strip_tags(html_content)
    subject = f"[{SITE_NAME}] {notification.title}"

    # 7) Attempt sending with inline logo if EMAIL_LOGO_PATH is configured
    attach_inline_logo = getattr(settings, "EMAIL_LOGO_PATH", None)

    try:
        # create email
        msg = EmailMultiAlternatives(subject=subject, body=text_content, from_email=from_email, to=[to_email])

        # If inline logo path is configured, attempt embedding it (preferred absolute)
        if attach_inline_logo:
            # resolve relative to BASE_DIR if not absolute
            if not os.path.isabs(attach_inline_logo) and getattr(settings, "BASE_DIR", None):
                attach_inline_logo = os.path.join(getattr(settings, "BASE_DIR"), attach_inline_logo)

            if os.path.exists(attach_inline_logo):
                try:
                    with open(attach_inline_logo, "rb") as f:
                        logo_data = f.read()

                    # set related multipart so cid works
                    msg.mixed_subtype = 'related'

                    # set tpl context to use cid
                    context["logo_use_cid"] = True
                    context["logo_cid"] = "logo_cid"

                    # re-render html with cid reference
                    tmpl = Template(html_template)
                    html_content = tmpl.render(Context(context))
                    msg.attach_alternative(html_content, "text/html")

                    # attach image with Content-ID
                    image = MIMEImage(logo_data)
                    image.add_header('Content-ID', '<logo_cid>')
                    image.add_header('Content-Disposition', 'inline', filename=os.path.basename(attach_inline_logo))
                    msg.attach(image)
                except Exception as exc_attach:
                    logger.exception("Failed to attach inline logo: %s", exc_attach)
                    # fallback: render without cid (use logo_url or placeholder)
                    context["logo_use_cid"] = False
                    tmpl = Template(html_template)
                    html_content = tmpl.render(Context(context))
                    msg.attach_alternative(html_content, "text/html")
            else:
                logger.warning("EMAIL_LOGO_PATH set but file not found: %s", attach_inline_logo)
                context["logo_use_cid"] = False
                tmpl = Template(html_template)
                html_content = tmpl.render(Context(context))
                msg.attach_alternative(html_content, "text/html")
        else:
            # no inline logo requested, use logo_url if present
            tmpl = Template(html_template)
            context["logo_use_cid"] = False
            html_content = tmpl.render(Context(context))
            msg.attach_alternative(html_content, "text/html")

        # send email
        msg.send(fail_silently=False)
        logger.info("Notification email sent to %s (notification=%s)", to_email, notification.pk)
        return {"ok": True, "error": None, "notification_id": notification.pk}

    except Exception as exc_send:
        logger.exception("Failed to send notification email: %s", exc_send)
        return {"ok": False, "error": exc_send, "notification_id": notification.pk}
