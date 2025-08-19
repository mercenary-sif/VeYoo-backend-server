from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _

from scarabe_server import settings


class AccountTypes(models.TextChoices):
    ADMIN = 'admin', _('Admin')
    MANAGER = 'manager', _('Manager')
    INSPECTOR = 'inspector', _('Inspector')

class AccountStatus(models.TextChoices):
    ACTIVE = 'active', 'Active'
    INACTIVE = 'inactive', 'Inactive'

class TireStatus(models.TextChoices):
    NEW   = 'new',   _('Neuf')
    WORN  = 'worn',  _('Usé')
    FLAT  = 'flat',  _('Crevé')

class BodyCondition(models.TextChoices):
    GOOD     = 'good',    _('Bon')
    DAMAGED  = 'damaged', _('Endommagé')

class EngineStatus(models.TextChoices):
    GOOD    = 'good',    _('Bon')
    FAULTY  = 'faulty',  _('Défaillant')

class FuelType(models.TextChoices):
    DIESEL    = 'Diesel',   _('Diesel')
    GASOLINE  = 'Gasoline', _('Essence')
    ELECTRIC  = 'Electric', _('Électrique')
    HYBRID    = 'Hybrid',   _('Hybride')

class ReservationStatus(models.TextChoices):
    PENDING = 'pending', _('Pending')
    ACCEPTED = 'accepted', _('Accepted')
    DECLINED = 'declined', _('Declined')
    COMPLETED = 'completed', _('Completed')

class ReservationType(models.TextChoices):
    NORMAL     = 'normal',     _('Normal')
    SAISONNIER = 'saisonnier', _('Saisonnier (3 mois)')
    ANNUEL     = 'annuel',     _('Annuel (1 an)')

class CheckStatus(models.TextChoices):
    PENDING     = 'pending',     _('Pending')
    IN_PROGRESS = 'in_progress', _('In Progress')
    COMPLETED   = 'completed',   _('Completed')
    FAILED      = 'failed',      _('Failed')

class MalfunctionStatus(models.TextChoices):
    REPORTED     = 'Reported',     _('Signalé')
    IN_PROGRESS  = 'In Progress',  _('En cours')
    RESOLVED     = 'Resolved',     _('Résolu')

class SeverityLevel(models.TextChoices):
    LOW      = 'Low',      _('Faible')
    MEDIUM   = 'Medium',   _('Moyenne')
    HIGH     = 'High',     _('Élevée')
    CRITICAL = 'Critical', _('Critique')
class MaterialStatus(models.TextChoices):
    GOOD                = 'good',               _('Bon')
    UNDER_MAINTENANCE   = 'under_maintenance',  _('En maintenance')
    PENDING_MAINTENANCE = 'pending_maintenance',_('Maintenance en attente')

class MaterialReservationStatus(models.TextChoices):
    AVAILABLE = 'available', _('Disponible')      
    RESERVED  = 'reserved',  _('Réservé')
    NOT_AVAILABLE = 'not_available', _('Hors service')  

class MaterialType(models.TextChoices):
    VEHICLE = 'vehicle', _('Véhicule')
    TOOL    = 'tool',    _('Outil')


class TicketType(models.TextChoices):
    COMPLAINT = 'complaint', _('Complaint')
    ISSUE = 'issue', _('Issue')

class PriorityLevel(models.TextChoices):
    LOW = 'low', _('Low')
    MEDIUM = 'medium', _('Medium')
    HIGH = 'high', _('High')

class AdvertisementStatus(models.TextChoices):
    ACTIVE   = 'active',  _('Activé')
    EXPIRED  = 'expired', _('Expiré')

class NotificationStatus(models.TextChoices):
    UNREAD = 'unread', _('Non lue')
    READ   = 'read',   _('Lue')

class SupportTicketStatus(models.TextChoices):
    OPEN     = 'open',    _('Ouvert')
    RESOLVED = 'resolved', _('Résolu')

class Account(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    email_verified = models.BooleanField(default=False)  # Shown with the green check
    whatsapp_number = models.CharField(max_length=15, blank=True, null=True)
    role = models.CharField(max_length=20, choices=AccountTypes.choices, default=AccountTypes.INSPECTOR)
    status = models.CharField(max_length=10, choices=AccountStatus.choices, default=AccountStatus.ACTIVE)

    created_at = models.DateTimeField(auto_now_add=True)     # Date d'inscription
    updated_at = models.DateTimeField(auto_now=True)         # Dernière modification
    last_connected = models.DateTimeField(blank=True, null=True)  # Dernière connexion
    registration_date = models.DateTimeField(blank=True, null=True)

    rest_code = models.CharField(max_length=10, blank=True, null=True)
    rest_code_expires = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.username


class Material(models.Model):
    photo                 = models.ImageField(upload_to='materials/' ,blank=True, null=True)
    status                = models.CharField(max_length=30, choices=MaterialStatus.choices)
    type                  = models.CharField(max_length=20, choices=MaterialType.choices)
    reservationStatus     = models.CharField(max_length=20, choices=MaterialReservationStatus.choices , default=MaterialReservationStatus.AVAILABLE)
    is_active             = models.BooleanField(default=True)
    
    description           = models.TextField(blank=True, null=True)
    category              = models.CharField(max_length=100, blank=True)
    name                  = models.CharField(max_length=100)

    last_maintenance_date = models.DateField(null=True, blank=True)
    inspection_due_date   = models.DateField(null=True, blank=True)
    
    created_at            = models.DateTimeField(auto_now_add=True)
    updated_at            = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.get_type_display()})"



class Vehicle(models.Model):
    material             = models.OneToOneField(Material, on_delete=models.CASCADE)
    license_plate        = models.CharField(max_length=50)
    model                = models.CharField(max_length=100)

    # your missing 'brand'
    brand                = models.CharField(max_length=100)

    year_of_manufacture  = models.PositiveIntegerField()
    color                = models.CharField(max_length=50)
    current_mileage      = models.PositiveIntegerField()
    fuel_level           = models.PositiveIntegerField()
    oil_level            = models.PositiveIntegerField()

    tire_status          = models.CharField(max_length=20, choices=TireStatus.choices)
    body_condition       = models.CharField(max_length=20, choices=BodyCondition.choices)
    engine_status        = models.CharField(max_length=20, choices=EngineStatus.choices)

    # your missing 'fuelType' and 'location'
    fuel_type            = models.CharField(max_length=20, choices=FuelType.choices, default=FuelType.DIESEL)
    location             = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.brand} {self.model} ({self.license_plate})"

class Tool(models.Model):
    material = models.OneToOneField(Material, on_delete=models.CASCADE, related_name="tool")
    serial_number = models.CharField(max_length=100, blank=True, null=True)
    manufacturer = models.CharField(max_length=100)
    purchase_date = models.DateField(blank=True, null=True)
    warranty_expiry = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"Tool: {self.material.name} - {self.serial_number or 'No Serial'}"
    

class Reservation(models.Model):
    # → who asked for the reservation
    created_by      = models.ForeignKey(
        User,
        related_name='created_reservations',
        on_delete=models.CASCADE
    )
    assigned_to = models.ForeignKey(
        User, 
        related_name='assigned_reservations', 
        on_delete=models.CASCADE , null=True)
    
    # → the material being reserved
    material        = models.ForeignKey(
        'scarabe.Material',
        on_delete=models.CASCADE
    )

    # → when the reservation begins/ends
    start_date      = models.DateField()
    end_date        = models.DateField()
    start_time      = models.TimeField(auto_now=True)
    end_time        = models.TimeField(null=True)
    # → why this reservation
    purpose         = models.CharField(max_length=255)
    notes           = models.TextField(blank=True, null=True)

    # → type of reservation (normal / saisonnier / annuel)
    reservation_type = models.CharField(
        max_length=12,
        choices=ReservationType.choices,
        default=ReservationType.NORMAL
    )
   
    # → current approval status
    status          = models.CharField(
        max_length=20,
        choices=ReservationStatus.choices,
        default=ReservationStatus.PENDING
    )

    # → timestamps
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)

    def __str__(self):
        return (f"{self.get_reservation_type_display()} reservation of “{self.purpose}” "
                f"for {self.material.name} from {self.start_date} to {self.end_date}")


class PreCheck(models.Model):
    reservation = models.ForeignKey(
        Reservation,
        on_delete=models.CASCADE,
        related_name='prechecks'
    )
    checked_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='performed_prechecks'
    )
    check_date = models.DateField(auto_now_add=True)
    check_time = models.TimeField(auto_now_add=True)

    # Each checklist item as its own Boolean
    car_body_ok            = models.BooleanField(null=True, blank=True, help_text="Carrosserie en bon état")
    tires_ok               = models.BooleanField(null=True, blank=True, help_text="Pneus en bon état")
    lighting_ok            = models.BooleanField(null=True, blank=True, help_text="Éclairage fonctionnel")
    next_service_within_1k = models.BooleanField(null=True, blank=True, help_text="Prochaine révision < 1000 km")
    adblue_ok              = models.BooleanField(null=True, blank=True, help_text="Liquide AdBlue suffisant")
    no_warning_lights      = models.BooleanField(null=True, blank=True, help_text="Aucun voyant allumé")
    clean_vehicle          = models.BooleanField(null=True, blank=True, help_text="Véhicule propre")
    docs_present           = models.BooleanField(null=True, blank=True, help_text="Documents présents")

    report = models.TextField(
        blank=True, null=True,
        help_text="Inspecteur’s written report"
    )

    status = models.CharField(
        max_length=20,
        choices=CheckStatus.choices,
        default=CheckStatus.PENDING
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"PreCheck #{self.id} for reservation {self.reservation.id} ({self.get_status_display()})"


class Malfunction(models.Model):
    # → which Material (vehicle or tool) this refers to
    material         = models.ForeignKey(Material, on_delete=models.CASCADE)

    # → text description of what’s broken
    description      = models.TextField()

    # → how bad it is
    severity         = models.CharField(
        max_length=10,
        choices=SeverityLevel.choices,
        default=SeverityLevel.MEDIUM
    )

    # → current state of the repair
    status           = models.CharField(
        max_length=15,
        choices=MalfunctionStatus.choices,
        default=MalfunctionStatus.REPORTED
    )

    # → who reported it (your form sends a free‑text “reportedBy”)
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reported_malfunctions')

    # → when it was declared
    declared_date    = models.DateField(auto_now_add=True)
    declared_time    = models.TimeField(auto_now_add=True)

    # → any extra notes from the form
    notes            = models.TextField(blank=True, null=True)

    # # → an array of existing or new photo URLs/names
    # photos           = models.JSONField(default=list)

    created_at       = models.DateTimeField(auto_now_add=True)
    updated_at       = models.DateTimeField(auto_now=True , null=True)

    def __str__(self):
        return f"{self.get_severity_display()} malfunction on {self.material.name}"

class MalfunctionPhoto(models.Model):
    malfunction = models.ForeignKey(
        Malfunction,
        related_name="photos",
        on_delete=models.CASCADE
    )
    photo = models.ImageField(upload_to="malfunctions/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
 
    def __str__(self):
        return f"Photo for {self.malfunction.material.name} @ {self.uploaded_at:%Y‑%m‑%d %H:%M}"
    @property
    def url(self):
        if self.photo and hasattr(self.photo, 'url'):
            return f"{settings.MEDIA_URL}{self.photo.name}"
        return ""
    
class Notification(models.Model):
    title = models.CharField(max_length=200, help_text=_("Titre de la notification") , default="Titre de la notification")
    content = models.TextField()
    notification_date = models.DateField()
    notification_time = models.TimeField()
    recipient = models.ForeignKey(User, on_delete=models.CASCADE)
    notification_status = models.CharField(
        max_length=10,
        choices=NotificationStatus.choices,
        default=NotificationStatus.UNREAD,
        db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def mark_as_read(self):
        if self.notification_status != NotificationStatus.READ:
            self.notification_status = NotificationStatus.READ
            self.save(update_fields=['notification_status'])


class Advertisement(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    priority = models.CharField(
        max_length=10,
        choices=PriorityLevel.choices,
        default=PriorityLevel.MEDIUM
    )
    status = models.CharField(
        max_length=20,
        choices=AdvertisementStatus.choices,
        default=AdvertisementStatus.ACTIVE
    )
    start_date = models.DateField()
    end_date = models.DateField()
    cover = models.ImageField(upload_to='advertisements/covers/', null=True, blank=True)
    pdf = models.FileField(upload_to='advertisements/pdfs/', null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True , related_name='ads_created')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True ,   related_name='ads_updated')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at       = models.DateTimeField(auto_now=True , null=True)


class SupportTicket(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    type = models.CharField(max_length=20, choices=TicketType.choices, default=TicketType.ISSUE)
    priority = models.CharField(max_length=10, choices=PriorityLevel.choices, default=PriorityLevel.MEDIUM)
    status = models.CharField(
        max_length=20,
        choices=SupportTicketStatus.choices,
        default=SupportTicketStatus.OPEN,
        db_index=True,
        help_text=_("Statut du ticket (ouvert / résolu)")
    )

    # creator and assignee
    created_by = models.ForeignKey(User, related_name='created_support_tickets', on_delete=models.CASCADE)
    assigned_to = models.ForeignKey(User, related_name='assigned_tickets', null=True, blank=True, on_delete=models.SET_NULL)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # optional text field to store an initial attachment note; actual files are in SupportAttachment
    def __str__(self):
        return f"[{self.id}] {self.title} ({self.status})"

class SupportReply(models.Model):
    ticket = models.ForeignKey(SupportTicket, related_name='replies', on_delete=models.CASCADE)
    author = models.ForeignKey(User, related_name='support_replies', on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
   
    def __str__(self):
        # author may be an ordinary User; use username for readability
        return f"Reply #{self.id} on Ticket {self.ticket.id} by {getattr(self.author, 'username', str(self.author))}"

class SupportAttachment(models.Model):
    file = models.FileField(upload_to='support/attachments/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # attach to either ticket or reply (one of them will be null)
    ticket = models.ForeignKey(SupportTicket, related_name='attachments', null=True, blank=True, on_delete=models.CASCADE)
    reply = models.ForeignKey(SupportReply, related_name='attachments', null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return f"Attachment #{self.id} ({self.file.name})"
