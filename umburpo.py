# Created May 2017 by Rob Brown : https://twitter.com/RB256

from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.io import PrintWriter
import base64
import binascii

class BurpExtender(IBurpExtender, IHttpListener, IParameter):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName ("Umburpo")
		self._stdout = PrintWriter(callbacks.getStdout(), True)
		callbacks.registerHttpListener(self)
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

		sParam = next(x for x in params if x.getType() == self.PARAM_URL and x.getName() == "s")

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

		if needsB64ing:
			self._stdout.println("Converting from " + minifyFileParam)
			messageInfo.setRequest(self._helpers.updateParameter(rawRequest, self._helpers.buildParameter("s", self._helpers.base64Encode(minifyFileParam), self.PARAM_URL)))
		else:
			self._stdout.println("Already encoded")
