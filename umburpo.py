# Created May 2017 by Rob Brown : https://twitter.com/RB256

from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.io import PrintWriter
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import base64
import binascii
import re

GREP_STRING = "Page generated by:"
GREP_STRING_BYTES = bytearray(GREP_STRING)
INJ_TEST = bytearray("|")
INJ_ERROR = "Unexpected pipe"
INJ_ERROR_BYTES = bytearray(INJ_ERROR)

BASE64_CHARS = re.compile("^([a-z]|[A-Z]|[0-9]|\+|\/|=)*?$")

class BurpExtender(IBurpExtender, IHttpListener, IParameter, IScannerCheck):

	_clientDependencyHandlerScanned = False

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName ("Umburpo")
		self._stdout = PrintWriter(callbacks.getStdout(), True)
		callbacks.registerHttpListener(self)
		callbacks.registerScannerCheck(self)
		return

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		self._stdout.println(
			("HTTP request to " if messageIsRequest else "HTTP response from ") +
			messageInfo.getHttpService().toString() +
			" [" + self._callbacks.getToolName(toolFlag) + "]")

		if not messageIsRequest:
			return

		if toolFlag == self._callbacks.TOOL_PROXY:
			return

		self._stdout.println("Lets do it")

		rawRequest = messageInfo.getRequest()
		request = self._helpers.analyzeRequest(rawRequest)

		params = request.getParameters()

		sParam = next((x for x in params if x.getType() == self.PARAM_URL and x.getName() == "s"), None)

		if sParam is None:
			self._stdout.println("Param not found")
			return

		self._stdout.println("Param found")

		minifyFileParam = sParam.getValue()
		needsB64ing = False

		self._stdout.println("Lets see if we need to encode it")

		try:
		    base64.decodestring(minifyFileParam)
		except binascii.Error:
		    needsB64ing = True

                is_only_b64 = BASE64_CHARS.match(minifyFileParam)

                if is_only_b64 is None:
                    needsB64ing = True

		if needsB64ing:
			self._stdout.println("Converting from " + minifyFileParam)
			messageInfo.setRequest(self._helpers.updateParameter(rawRequest, self._helpers.buildParameter("s", self._helpers.base64Encode(minifyFileParam), self.PARAM_URL)))
		else:
			self._stdout.println("Already encoded")

# here

	def _get_matches(self, response, match):
		matches = []
		start = 0
		reslen = len(response)
		matchlen = len(match)
		while start < reslen:
			start = self._helpers.indexOf(response, match, True, start, reslen)
			if start == -1:
				break
			matches.append(array('i', [start, start + matchlen]))
			start += matchlen

		return matches

	def doPassiveScan(self, baseRequestResponse):

		  	return None;

	def doActiveScan(self, baseRequestResponse, insertionPoint):

		if self._clientDependencyHandlerScanned:
			self._stdout.println("Already scanned")
			return None;

		service = baseRequestResponse.getHttpService();

		clientDependencyHandlerUrl = URL(service.getProtocol(), service.getHost(), service.GetPort(), "/DependencyHandlerFOO.axd")

		req = self._helpers.buildHttpRequest(clientDependencyHandlerUrl);

		self._helpers.addParameter(req, buildParameter("s", "L2pzL2NvbmZpZy5qczs", this.PARAM_URL))
		self._helpers.addParameter(req, buildParameter("t", "css", this.PARAM_URL))
		self._helpers.addParameter(req, buildParameter("dv", "2", this.PARAM_URL))

		rawResponse = self._callbacks.makeHttpRequest(service, req);

		self._stdout.println("Scanned")
		_clientDependencyHandlerScanned = True
		return None;

		return None;
		
		response = self._helpers.analyzeResponse(rawResponse)
		
		self._stdout.println(response.getStatusCode())
		
		body = self._helpers.bytesToString(rawResponse[response.getBodyOffset():])
		
		self._stdout.println(len(body))
		
		return body



		return None;
		# make a request containing our injection test in the insertion point
		checkRequest = insertionPoint.buildRequest(INJ_TEST)
		checkRequestResponse = self._callbacks.makeHttpRequest(
				baseRequestResponse.getHttpService(), checkRequest)

		# look for matches of our active check grep string
		matches = self._get_matches(checkRequestResponse.getResponse(), INJ_ERROR_BYTES)
		if len(matches) == 0:
			return None

		# get the offsets of the payload within the request, for in-UI highlighting
		requestHighlights = [insertionPoint.getPayloadOffsets(INJ_TEST)]

		# report the issue
		return [CustomScanIssue(
			baseRequestResponse.getHttpService(),
			self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
			[self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
			"Pipe injection",
			"Submitting a pipe character returned the string: " + INJ_ERROR,
			"High")]

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		# This method is called when multiple issues are reported for the same URL 
		# path by the same extension-provided check. The value we return from this 
		# method determines how/whether Burp consolidates the multiple issues
		# to prevent duplication
		#
		# Since the issue name is sufficient to identify our issues as different,
		# if both issues have the same name, only report the existing issue
		# otherwise report both issues
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1

		return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		pass

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
