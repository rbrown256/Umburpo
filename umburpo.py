# Created May 2017 by Rob Brown : https://twitter.com/RB256

from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener):
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

		if self._callbacks.getToolName(toolFlag) == "Proxy":
			return

		self.stdout.println("Lets do it")

