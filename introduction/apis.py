import time
from django.middleware.csrf import get_token
import re

import requests
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt

from introduction.playground.A6.utility import check_vuln
from introduction.playground.A9.main import Log
from introduction.playground.ssrf import main

from .utility import *
from .views import authentication_decorator

def ssrf_code_checker(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            # CSRF token check
            csrf_token = request.POST.get('csrfmiddlewaretoken', '')
            request_csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
            if csrf_token != request_csrf_token or csrf_token != get_token(request):
                return JsonResponse({'message': 'CSRF token mismatch.'}, status=403)

            python_code = request.POST['python_code']
            html_code = request.POST['html_code']
            if not (ssrf_code_converter(python_code)):
                return JsonResponse({"status": "error", "message": "Invalid code"})
            test_bench1 = ssrf_html_input_extractor(html_code)
            
            if (len(test_bench1) > 4):
                return JsonResponse({'message': 'too many inputs in Html\n Try again'}, status=400)
            test_bench2 = ['secret.txt']
            correct_output1 = [{"blog": "blog1-passed"}, {"blog": "blog2-passed"}, {"blog": "blog3-passed"}, {"blog": "blog4-passed"}]
            outputs = []
            for inputs in test_bench1:
                outputs.append(main.ssrf_lab(inputs))
            if outputs == correct_output1:
                outputs = []
            else:
                return JsonResponse({'message': 'Testbench failed, Code is not working\n Try again'}, status=200)

            correct_output2 = [{"blog": "No blog found"}]
            for inputs in test_bench2:
                outputs.append(main.ssrf_lab(inputs))
            if outputs == correct_output2:
                return JsonResponse({'message': 'Congratulation, you have written a secure code.', 'passed': 1}, status=200)
            
            return JsonResponse({'message': 'Test bench passed but the code is not secure'}, status=200, safe=False)
        else:
            return JsonResponse({'message': 'method not allowed'}, status=405)
    else:
        return JsonResponse({'message': 'UnAuthenticated User'}, status=401)

# Insufficient Logging & Monitoring

# @authentication_decorator
def log_function_checker(request):
    if request.method == 'POST':
        # CSRF protection should be enabled
        csrf_token = request.POST.get("csrfmiddlewaretoken")
        log_code = request.POST.get('log_code')
        api_code = request.POST.get('api_code')
        
        # Sanitize log_code and api_code to remove CRLF characters
        log_code = re.sub(r'[\r\n]', '', log_code)
        api_code = re.sub(r'[\r\n]', '', api_code)
        
        dirname = os.path.dirname(__file__)
        log_filename = os.path.join(dirname, "playground/A9/main.py")
        api_filename = os.path.join(dirname, "playground/A9/api.py")
        
        with open(log_filename, "w") as f:
            f.write(log_code)
        
        with open(api_filename, "w") as f:
            f.write(api_code)
        
        # Clearing the log file before starting the test
        with open('test.log', 'w') as f:
            f.write("")
        
        url = "http://127.0.0.1:8000/2021/discussion/A9/target"
        payload = {'csrfmiddlewaretoken': csrf_token}
        
        # CSRF protection should be enforced in requests
        requests.request("POST", url, data=payload)
        
        with open('test.log', 'r') as f:
            lines = f.readlines()
        
        return JsonResponse({"message": "success", "logs": lines}, status=200)
    else:
        return JsonResponse({"message": "method not allowed"}, status=405)

#a7 codechecking api
@csrf_exempt
def A7_disscussion_api(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)

    try:
        code = request.POST.get('code')
    except:
        return JsonResponse({"message":"missing code"},status = 400)

    search_snipet = "AF_session_id.objects.get(sesssion_id = cookie).delete()"
    search_snipet2 = "AF_session_id.objects.get(sesssion_id=cookie).delete()"

    if (search_snipet in code) or (search_snipet2 in code):
        return JsonResponse({"message":"success"},status = 200)

    return JsonResponse({"message":"failure"},status = 400)

# a6 codechecking api
@csrf_protect
def A6_disscussion_api(request):
    test_bench = ["Pillow==8.0.0","PyJWT==2.4.0","requests==2.28.0","Django==4.0.4"]
    
    if request.method == 'POST':
        try:
            result = check_vuln(test_bench)
            print(len(result))
            if result:
                return JsonResponse({"message":"success","vulns":result},status = 200)
            return JsonResponse({"message":"failure"},status = 400)
        except Exception as e:
            return JsonResponse({"message":"failure"},status = 400)
    else:
        return JsonResponse({"message":"Method not allowed"}, status=405)

@csrf_protect
def A6_disscussion_api_2(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    try:
        code = request.POST.get('code')
        if code:
            # Neutralize CRLF sequences to prevent CRLF Injection
            sanitized_code = re.sub(r'\r?\n', '', code)
        else:
            return JsonResponse({"message":"missing code"},status = 400)
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, "playground/A6/utility.py")
        with open(filename,"w") as f:
            f.write(sanitized_code)
    except:
        return JsonResponse({"message":"error writing code"},status = 500)
    return JsonResponse({"message":"success"},status = 200)
