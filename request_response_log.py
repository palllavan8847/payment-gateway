# Python imports
import os
import sys
import json
import traceback
import copy
import logging
import urlparse
import datetime
from django.conf import settings
from django.http import QueryDict, HttpResponse, HttpResponseBadRequest, Http404
from django.core.exceptions import ValidationError
from django.shortcuts import render
from django.views.debug import ExceptionReporter
from django.template.loader import render_to_string
from tastypie.exceptions import TastypieError
from tasks import exception_email
from exception import (ValidationException, ServerException, ValidationException)

#SYS-LOG
syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log', facility = logging.handlers.SysLogHandler.LOG_USER)
syslog_handler.setFormatter(logging.Formatter('django_application - %(levelname)s - %(message)s'))
logger = logging.getLogger('django_application')
logger.addHandler(syslog_handler)

#DJANGO APP-LOG
file_path = os.path.join(settings.LOG_FILE_PATH, 'logfile%s_%s.log' % (datetime.datetime.now().strftime('%Y%m%d%H%M%S'), os.getpid()))
handler = logging.FileHandler(file_path)
handler.setFormatter(logging.Formatter('%(asctime)s|%(levelname)s|%(thread)d|%(message)s ||||'))
logger.addHandler(handler)

nonlog_urls = ["admin", "static", "favicon.ico"]

def log_request_body(request, sessionkey):
	'''
	This function is used to log the request input data 
	'''
	if not request.body:
		return
	try:
	    request_input = json.loads(request.body)
	except:
	    request_input = QueryDict(request.body).dict()
	if request.FILES:
	    body_dict = request.POST.dict()
	    for data in request.FILES:
	        obj = request.FILES.getlist(data)[0]
	        request_input.update({'%s_name'%str(data): obj.name, '%s_size'%str(data): obj.size, '%s_content_type'%str(data): obj.content_type})
	logger.info("Request Body: Url: %s - Session key: %s - Input: %s"%(request.build_absolute_uri(), sessionkey, response_output(request_input)))
	return

def exception_email_format(request, exc_info):
	'''
	This function is used to  encrypt the sensitive input data and send email to notify server administrator
	'''
	if settings.DEBUG is False:
	    reporter = ExceptionReporter(request, is_email = True, *exc_info)
	    subject = r'Error:: IP %s : %s ' % (request.META.get('SERVER_ADDR'), reporter.exc_value)
	    input_data = get_request_body(request)
	    trace_data = reporter.get_traceback_data()
	    if input_data:
	        data_encrypt = response_output(input_data)
	        trace_data['input_data'] = data_encrypt
	    html_message = render_to_string('error_report.html', trace_data)
	    ### send exception email through celery
	    exception_email.delay_or_eager(subject, 'ERROR MAIL', fail_silently = True, html_message = html_message)
	return
	
def response_output(response_body):
	'''
	This function is used to remove the blacklisted fields  and encrypt the sensitive data from input (which will be useful while logging)
	'''
	copy_input_data = copy.deepcopy(response_body)
	if 'objects' in response_body:
	    for dat_index, values in enumerate(copy_input_data['objects']):
	        for patch_key, patch_value in values.iteritems():
	            if patch_key in settings.BLACKLISTED_FIELDS:
	                response_body['objects'][dat_index][patch_key] = '***removed***'
	            if patch_key in settings.CRYPT_FIELDS:
	                response_body['objects'][dat_index][patch_key] = dm_crypt.encrypt(str(patch_value))
	else:
		response_body_keys = set(response_body.keys())
		# Remove Blacklist fields
		blacklist_input = response_body_keys.intersection(settings.BLACKLISTED_FIELDS)
		if blacklist_input:
			filter(lambda x: response_body.update({x: 'removed'}) , blacklist_input)
		# Encrypt input fields
		encrypt_input = response_body_keys.intersection(settings.CRYPT_FIELDS)
		if encrypt_input:
			filter(lambda x: response_body.update({x: dm_crypt.encrypt(response_body[x])}) , encrypt_input)
	return response_body
	
class LogExceptionMiddleware(object):
    
    def process_request(self, request):
		"""
        Request logging in syslog and django log
        Keyword arguments:
            request - contains all user information including user and browser details
        """
		#request_url = request.path
        #if any (url_list in request_url for url_list in nonlog_urls):
        #    return
		if request.path.split('/')[0] in nonlog_urls:
			return
		sessionkey = ""
		if hasattr(request, 'session'):
		    sessionkey = request.session.session_key
		current_time = datetime.datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S.%f')[:-3]	
		logger.info("Request Info: Url: %s - Current Time: %s - Session key: %s - Ajax: %s - Header: %s"%(request.build_absolute_uri(), 
																										current_time, sessionkey, 
																										request.is_ajax(), str(request.META)))
		log_request_body(request, sessionkey)
		
    def process_response( self, request, response ):
		"""
        Response logging in syslog and django log
        Keyword arguments:
            request - contains request information includes user and browser details
			response - contains response information for a request
		Response : may be a json response or html content
        """
		if request.path.split('/')[0] in nonlog_urls:
			return
		current_time = datetime.datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S.%f')[:-3]
		sessionkey = ""
		if hasattr(request, 'session'):
		    sessionkey = request.session.session_key
		if "/api/v1/" in request_url or request.is_ajax():
		    if response.content:
		        try:
		            response_body = json.loads(response.content)
		        except ValueError:
		            logger.critical("Exception Response API: Session Key : %s - Url: %s - Current time : %s - Response : %s"
		                            %(sessionkey, request.build_absolute_uri(), current_time, response.content))
		            return HttpResponse(ServerException(message = "Unknown Exception please contact IT support"), 
									content_type = 'application/json', status = 500)
		        if isinstance(response_body, dict):
		            response_body = response_output(response_body)
		        elif isinstance(response_body, list):
					response_body = [ response_output(response_obj) if isinstance(response_obj, dict) else 
									response_obj for response_obj in response_body ]
		        logger.info("Response API: Session Key : %s - Url: %s - Current time : %s - Response : %s"
		                    %(sessionkey, request.build_absolute_uri(), current_time, response_body))
		else:
		    logger.info("Response Views: Session Key : %s - Url: %s - Current time : %s - Response Status Code : %s"
		                %(sessionkey, request.build_absolute_uri(), current_time, response.status_code))
		return response
    
    def process_exception(self, request, exception):
		"""
		Find exception, send custom exception to customers and send mail if the exception raises due to server side
		Keyword arguments:
		    request - contains request information includes user details, browser details
			exception - contains exception information
		Response : may be a json response or html content
		"""
		request_url = request.path
		keys = "Error : Session Key : %s - Error Traceback: "%(request.session.session_key)
		traceback_log = traceback.format_exc().replace('\n', '\n%s'%keys) 
		if type(exception) == ValidationError:
		    exception = ValidationException(message=exception.message)
		    logger.error(str("Error : Session Key : %s - Error Traceback: %s"%(request.session.session_key, traceback_log)))
		else:
		    exception = ServerException(message=_("Unknown Exception"))
		    exception_email_format(request, sys.exc_info())
		    logger.critical(str("Error : Session Key : %s - Error Traceback: %s"%(request.session.session_key, traceback_log)))
		if "/api/v1/" in request_url or request.is_ajax():
		    return HttpResponse(exception, content_type = 'application/json', status = getattr(exception, 'status_code', 500)) 
		return render(request, "error.html", {"code":exception.code, "message_agent":None, "message": exception.message},
					status = getattr(exception, 'status_code', 500))