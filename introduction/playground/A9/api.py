from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator

from .main import Log

@method_decorator(csrf_protect, name='dispatch')
def log_function_target(request):
    L = Log(request)
    if request.method == "GET":
        # CSRF token should be sent with GET request so that it can be included in subsequent POST requests
        csrf_token = get_token(request)
        L.info("GET request")
        return JsonResponse({"message":"normal get request", "method":"get", "csrf_token": csrf_token}, status=200)
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        L.info(f"POST request with username {username} and password {password}")
        if username == "admin" and password == "admin":
            return JsonResponse({"message":"Logged in successfully", "method":"post"}, status=200)
        return JsonResponse({"message":"Invalid credentials", "method":"post"}, status=401)
    if request.method == "PUT":
        L.info("PUT request")
        return JsonResponse({"message":"success", "method":"put"}, status=200)
    if request.method == "DELETE":
        if request.user.is_authenticated:
            return JsonResponse({"message":"User is authenticated", "method":"delete"}, status=200)
        L.error("DELETE request")
        return JsonResponse({"message":"permission denied", "method":"delete"}, status=403)
    if request.method == "PATCH":
        L.info("PATCH request")
        return JsonResponse({"message":"success", "method":"patch"}, status=200)
    if request.method == "UPDATE":
        return JsonResponse({"message":"success", "method":"update"}, status=200)
    return JsonResponse({"message":"method not allowed"}, status=405)
