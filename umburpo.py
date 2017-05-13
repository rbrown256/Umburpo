# Created May 2017 by Rob Brown : https://twitter.com/RB256

from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.io import PrintWriter

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

		request = self._helpers.analyzeRequest(messageInfo.getRequest())

		params = request.getParameters()

		sParam = next(x for x in params if x.getType() == self.PARAM_URL)

		if not sParam is None:
			self._stdout.println("We have something" + sParam.getName())
