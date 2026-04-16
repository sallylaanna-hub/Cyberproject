from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User

@csrf_exempt
def login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Flaw 1: SQL Injection
        # query = f"SELECT * FROM auth_user WHERE username = '{username}'"
        #cursor = connection.cursor()
        #cursor.execute(query)
        #result = cursor.fetchone()

        # Flaw 1 FIX: parametrized query (prevents injection)
        query = "SELECT * FROM auth_user WHERE username = %s"
        cursor = connection.cursor()
        cursor.execute(query,[username])
        result = cursor.fetchone()

        # Flaw 4: Identification and Authentication Failures (password can be anything)
        #if result:
            #return HttpResponse("Logged in!")
        #else:
            #return HttpResponse("Login failed")

        # Flaw 5: Security and Monitoring Failures
        #if result and password == result[1]:
            #return HttpResponse("Logged in!")
        #else:
            #return HttpResponse("Login failed")
        
        # Flaw 4 FIX: check also password
        # Flaw 5 FIX: keeping log when Login failed
        if result and password == result[1]:
            print(f"LOGIN SUCCESS: {username}") # 5 FIX
            return HttpResponse("Logged in!")
        else:
            print(f"LOGIN FAILED: {username}") # 5 FIX
            return HttpResponse("Login failed")
        
    return HttpResponse("""
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <button type="submit">Login</button>
        </form>
    """)

def profile(request, user_id):
    # Flaw 2: no control of access to profile, any user can access any profile
    # return HttpResponse(f"Profile page of user {user_id}")

    # Flaw 3: user may not exist and causes crash (and reveals debug to wrong people)
    #user = None
    #return HttpResponse(user.username)

    # Flaw 3 FIX: check before using the object
    user = None
    if user is None:
        return HttpResponse("User not found")
    return HttpResponse(user.username) 

    # Flaw 2 FIX: allow only for certain user for example user id: 1
    #if user_id !=1:
        #return HttpResponse("Access denied")
    
    #return HttpResponse(f"Profile page of user {user_id}")