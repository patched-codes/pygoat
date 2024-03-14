import time
import os

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


# steps --> 
# 1. covert input code to corrosponding code and write in file
# 2. extract inputs form 2nd code 
# 3. Run the code 
# 4. get the result
@csrf_exempt
def ssrf_code_checker(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            python_code = request.POST['python_code']
            html_code = request.POST['html_code']
            if not (ssrf_code_converter(python_code)):
                return JsonResponse({"status": "error", "message": "Invalid code"})
            test_bench1 = ssrf_html_input_extractor(html_code)
            
            if (len(test_bench1) >4):
                return JsonResponse({'message':'too many inputs in Html\n Try again'},status = 400)
            test_bench2 = ['secret.txt']
            correct_output1 = [{"blog": "blog1-passed"}, {"blog": "blog2-passed"}, {"blog": "blog3-passed"}, {"blog": "blog4-passed"}]
            outputs = []
            for inputs in test_bench1:
                outputs.append(main.ssrf_lab(inputs))
            if outputs == correct_output1:
                outputs = []
            else:
                return JsonResponse({'message':'Testbench failed, Code is not working\n Try again'},status = 200)

            correct_output2 = [{"blog": "No blog found"}]
            for inputs in test_bench2:
                outputs.append(main.ssrf_lab(inputs))
            if outputs == correct_output2:
                return JsonResponse({'message':'Congratulation, you have written a secure code.', 'passed':1}, status = 200)
            
            return JsonResponse({'message':'Test bench passed but the code is not secure'}, status = 200,safe = False)
        else:
            return JsonResponse({'message':'method not allowed'},status = 405)
    else:
        return JsonResponse({'message':'UnAuthenticated User'},status = 401)

# Insufficient Logging & Monitoring

@csrf_exempt
# @authentication_decorator
def log_function_checker(request):
    if request.method == 'POST':
        csrf_token = request.POST.get("csrfmiddlewaretoken")
        log_code = request.POST.get('log_code')
        api_code = request.POST.get('api_code')
        dirname = os.path.dirname(__file__)
        log_filename = os.path.abspath(os.path.join(dirname, "playground/A9/main.py"))
        api_filename = os.path.abspath(os.path.join(dirname, "playground/A9/api.py"))
        if not log_filename.startswith(os.path.abspath(dirname)):
            return JsonResponse({"message": "Invalid path for log file"}, status=400)
        if not api_filename.startswith(os.path.abspath(dirname)):
            return JsonResponse({"message": "Invalid path for API file"}, status=400)
        with open(log_filename, "w") as f:
            f.write(log_code)
        with open(api_filename, "w") as f:
            f.write(api_code)
        # Clearing the log file before starting the test
        with open('test.log', 'w') as f:
            f.write("")
        url = "http://127.0.0.1:8000/2021/discussion/A9/target"
        payload = {'csrfmiddlewaretoken': csrf_token}
        requests.request("GET", url)
        requests.request("POST", url)
        requests.request("PATCH", url, data=payload)
        requests.request("DELETE", url)
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

#a6 codechecking api
@csrf_exempt
def A6_disscussion_api(request):
    test_bench = ["Pillow==8.0.0","PyJWT==2.4.0","requests==2.28.0","Django==4.0.4"]
    
    try:
        result = check_vuln(test_bench)
        print(len(result))
        if result:
            return JsonResponse({"message":"success","vulns":result},status = 200)
        return JsonResponse({"message":"failure"},status = 400)
    except Exception as e:
        return JsonResponse({"message":"failure"},status = 400)

@csrf_exempt
def A6_disscussion_api_2(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    try:
        code = request.POST.get('code')
        if not code:
            raise ValueError("No code provided")
        dirname = os.path.dirname(__file__)
        safe_path = os.path.normpath(os.path.join(dirname, "playground/A6/utility.py"))
        if not safe_path.startswith(os.path.join(dirname, "playground/A6/")):
            raise ValueError("Invalid file path")
        with open(safe_path, "w") as f:
            f.write(code)
    except Exception as e:
        return JsonResponse({"message": str(e)}, status=400)
    return JsonResponse({"message":"success"}, status=200)
