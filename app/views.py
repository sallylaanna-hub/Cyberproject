from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from .models import Patient
from django.contrib.auth import login as auth_login, authenticate
from django.contrib.auth.models import User


@csrf_exempt
def login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Flaw 1: SQL Injection
        cursor = connection.cursor()
        query = f"SELECT * FROM auth_user WHERE username = '{username}'"
        cursor.execute(query)
        result = cursor.fetchone()

        # Flaw 1 FIX: parametrized query (prevents injection)
        #cursor = connection.cursor() 
        #query = "SELECT * FROM auth_user WHERE username = %s"
        #cursor.execute(query,[username])
        #result = cursor.fetchone()

        # Flaw 4: Identification and Authentication Failures (password can be anything)
        if result:
            user = User.objects.get(id=result[0])
            auth_login(request, user)

            auth_user = authenticate(request, username=username, password=password)
            password_verified = (auth_user is not None)
            request.session["password_status"] = password_verified
        
        # Flaw 5: Security and Monitoring Failures (not logging of log attempts)
            return HttpResponse("Logged in!")
        else:
            return HttpResponse("Login failed")

        # Flaw 4 FIX: check also password
            #user = authenticate(request, username=username, password=password)
        #if user is not None:
            #auth_login(request, user)
            #request.session["password_status"] = True
        # Flaw 5 FIX: logging successful and failed login attempts
            #print(f"LOGIN SUCCESS: {username}")
            #return HttpResponse("Logged in!")
        #else:
            #request.session["password_status"] = False
            #print(f"LOGIN FAILED: {username}")
            #return HttpResponse("Login failed")
    
    return HttpResponse("""
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <button type="submit">Login</button>
        </form>""")


def profile(request, user_id):
    # Flaw 2: no control of access to profile (any user can access any profile)
    patient = Patient.objects.get(id = user_id)
    
    # Flaw 2 FIX: users can access only own profile
    #if request.user.id != user_id:
        #return HttpResponse("Access denied")

    return HttpResponse(f"""
        Authenticated: {request.user.is_authenticated}<br>
        Logged in as: {request.user.username}<br><br>
        Password verified: {request.session.get("password_status")}<br>
        Name: {patient.name}<br>
        Diagnosis: {patient.diagnosis}
        """)
