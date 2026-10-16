import logging
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from .models import SecurityAlert

logger = logging.getLogger('security')

def login_view(request):
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')  # Hasło jest przetwarzane, ale NIGDY go nie logujemy!
        
        # Klucz do zliczania nieudanych prób logowania dla danej pary IP + login
        ip = request.META.get('REMOTE_ADDR')
        cache_key = f"failed_login_{username}_{ip}"
        attempts = cache.get(cache_key, 0)

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Sukces logowania – zerujemy licznik błędów
            cache.delete(cache_key)
            login(request, user)
            
            event_data = {
                "correlation_id": getattr(request, 'correlation_id', 'unknown'),
                "ip": ip,
                "user": username,
                "event": "LOGIN_SUCCESS",
                "alert": False
            }
            logger.info("Poprawne logowanie użytkownika", extra={"security_event": event_data})
            return redirect('profile')
        else:
            # Błędne logowanie – podbijamy licznik
            attempts += 1
            cache.set(cache_key, attempts, timeout=300)  # pamiętamy błędy przez 5 minut
            
            event_data = {
                "correlation_id": getattr(request, 'correlation_id', 'unknown'),
                "ip": ip,
                "user": username,
                "event": "LOGIN_FAILURE",
                "attempts": attempts,
                "alert": False
            }

            # REGUŁA: 3 nieudane próby -> generujemy ALERT (zgodnie ze scenariuszem testu nr 2)
            if attempts >= 3:
                event_data["alert"] = True
                event_data["alert_type"] = "BRUTE_FORCE_ATTEMPT"
                event_data["alert_severity"] = "CRITICAL"
                
                SecurityAlert.objects.create(
                    correlation_id=event_data["correlation_id"],
                    ip_address=ip,
                    username=username,
                    alert_type="BRUTE_FORCE_ATTEMPT",
                    description=f"Wykryto {attempts} nieudanych prób logowania z rzędu.",
                    severity="CRITICAL"
                )
                logger.error("ALERT: Wielokrotne nieudane próby logowania", extra={"security_event": event_data})
            else:
                logger.warning("Nieudana próba logowania", extra={"security_event": event_data})

            error = "Nieprawidłowy login lub hasło."

    return render(request, 'sec_app/login.html', {'error': error})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def profile_view(request):
    return render(request, 'sec_app/profile.html', {'user': request.user})

@login_required
def change_role_view(request):
    # Endpoint do testowania eskalacji ról / uprawnień
    if request.method == 'POST':
        action = request.POST.get('action')
        user = request.user
        if action == 'make_staff':
            user.is_staff = True
            user.save()
        elif action == 'revoke_staff':
            user.is_staff = False
            user.save()
            
        event_data = {
            "correlation_id": getattr(request, 'correlation_id', 'unknown'),
            "ip": request.META.get('REMOTE_ADDR'),
            "user": user.username,
            "event": "ROLE_CHANGED",
            "is_staff": user.is_staff,
            "alert": False
        }
        logger.info("Zmieniono uprawnienia użytkownika", extra={"security_event": event_data})
        return redirect('profile')

    return render(request, 'sec_app/change_role.html')

def dashboard_view(request):
    # Podgląd alertów oraz ostatnich wpisów z pliku security_events.log
    alerts = SecurityAlert.objects.all().order_by('-timestamp')[:10]
    
    raw_logs = []
    try:
        with open('security_events.log', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            raw_logs = lines[-15:]  # ostatnie 15 wpisów
    except FileNotFoundError:
        pass

    return render(request, 'sec_app/dashboard.html', {
        'alerts': alerts,
        'raw_logs': raw_logs
    })