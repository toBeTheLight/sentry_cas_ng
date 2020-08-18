'http://sentry-qa.dev.zhaopin.com:9000/auth/login/zpfe/'

def CAS_LOGIN_REQUEST_JUDGE(request):
  import re
  pathReg = r'.*/auth/login/.*'
  return not request.GET.get('admin') and re.match(request.path, pathReg)

def CAS_LOGOUT_REQUEST_JUDGE(request):
  import re
  pathReg = r'.*/api/0/auth/.*'
  return re.match('/auth/login/zpfe/', pathReg) and 'DELETE' == 'DELETE'

print(not None)