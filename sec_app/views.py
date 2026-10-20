from datetime import timedelta
import logging
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from . import rules
from .detection import record_event, get_client_ip, MAX_FIELD
from .models import SecurityAlert, SecurityEvent

logger = logging.getLogger('security')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('profile')

    error = None
    if request.method == 'POST':
        raw_username = request.POST.get('username', '').strip()[:MAX_FIELD]
        password = request.POST.get('password', '') # Hasło jest przetwarzane, ale NIGDY go nie logujemy ani nie zapisujemy!

        # Weryfikacja istnienia konta w bazie
        user_exists = User.objects.filter(username=raw_username).exists()
        username = raw_username if user_exists else f"{raw_username} (NOT_FOUND)"
        ip = get_client_ip(request)

        user = authenticate(request, username=raw_username, password=password)

        if user is not None:
            login(request, user)
            # Korelacja i liczniki (DET-001/002/005) liczy silnik detekcji na podstawie zapisanych zdarzeń            
            record_event(
                request,
                rules.LOGIN_SUCCESS,
                username=raw_username,
                status_code=302,
                details={"user_exists": True},
                message="Poprawne logowanie użytkownika"
            )
            return redirect('profile')

        record_event(
            request,
            rules.LOGIN_FAILURE,
            username=username,
            status_code=200,
            details={
                "user_exists": user_exists,
                "account_status": "EXISTING" if user_exists else "NON_EXISTENT"
            },
            message=f"Nieudana próba logowania na konto: {username}"
        )

        window_start = timezone.now() - timedelta(minutes=5)
        recent_failures_count = SecurityEvent.objects.filter(
            event_type=rules.LOGIN_FAILURE,
            username=username,
            ip_address=ip,
            timestamp__gte=window_start
        ).count()

        if recent_failures_count < 3:
            if recent_failures_count <= 1:
                desc = f"Jednorazowa nieudana próba logowania na konto '{username}'."
            else:
                desc = f"Kolejna nieudana próba logowania (próba nr {recent_failures_count}) na konto '{username}'."

            if not user_exists:
                desc += " Użytkownik nie istnieje w bazie (możliwe skanowanie / enumeracja kont)."

            SecurityAlert.objects.create(
                correlation_id=getattr(request, "correlation_id", "unknown"),
                ip_address=ip,
                username=username,
                alert_type="LOGIN_FAILED_WARNING",
                rule_id="WARN-001",
                description=desc,
                severity="WARNING"
            )

        error = "Nieprawidłowy login lub hasło."

    return render(request, 'sec_app/login.html', {'error': error})


def logout_view(request):
    logout(request)
    return redirect('login')


@login_required(login_url='login')
def profile_view(request):
    return render(request, 'sec_app/profile.html', {'user': request.user})


@login_required(login_url='login')
def change_role_view(request): # Endpoint do testowania eskalacji ról / uprawnień
    if request.method == 'POST':
        action = request.POST.get('action')
        user = request.user
        previous_is_staff = user.is_staff
        if action == 'make_staff':
            user.is_staff = True
            user.save()
        elif action == 'revoke_staff':
            user.is_staff = False
            user.save()
        # DET-006 / DET-007: reguły oceniają przejście is_staff False -> True
        record_event(
            request,
            rules.ROLE_CHANGED,
            username=user.username,
            status_code=302,
            details={
                "action": (action or "")[:30],
                "previous_is_staff": previous_is_staff,
                "is_staff": user.is_staff
            },
            message="Zmieniono uprawnienia użytkownika"
        )
        return redirect('profile')

    return render(request, 'sec_app/change_role.html')


@login_required(login_url='login')
def dashboard_view(request):
    # Podgląd alertów oraz ostatnich wpisów z pliku security_events.log
    alerts = SecurityAlert.objects.all().order_by('-timestamp')[:10]
    
    raw_logs = []
    try:
        with open(settings.SECURITY_LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            raw_logs = lines[-15:] # ostatnie 15 wpisów
    except FileNotFoundError:
        pass

    return render(request, 'sec_app/dashboard.html', {
        'alerts': alerts,
        'raw_logs': raw_logs
    })