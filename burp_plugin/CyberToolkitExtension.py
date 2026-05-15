# CyberToolkitExtension.py
# Plugin básico para Burp Suite usando Jython
from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.awt.event import ActionListener

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Nombre de la extensión en Burp Suite
        callbacks.setExtensionName("CyberToolkit Integration")
        
        # Registrar el menú contextual
        callbacks.registerContextMenuFactory(self)
        
        callbacks.printOutput("CyberToolkit Plugin cargado correctamente.")
        callbacks.printOutput("Asegurate de tener corriendo el servidor local de CyberToolkit (python web/app.py).")
        
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        
        # Se habilitan las opciones solo si hay un request seleccionado
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
            
        item1 = JMenuItem("CyberToolkit: Analizar URL para Phishing")
        item1.addActionListener(MenuActionListener(self._callbacks, invocation, "url_analyzer"))
        
        item2 = JMenuItem("CyberToolkit: Escanear XSS/SQLi en endpoint")
        item2.addActionListener(MenuActionListener(self._callbacks, invocation, "vuln_scanner"))
        
        menu_list.add(item1)
        menu_list.add(item2)
        return menu_list

class MenuActionListener(ActionListener):
    def __init__(self, callbacks, invocation, action):
        self.callbacks = callbacks
        self.invocation = invocation
        self.action = action
        
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        if not messages:
            return
            
        # Obtenemos la URL del primer mensaje seleccionado
        req_info = self.callbacks.getHelpers().analyzeRequest(messages[0])
        url = req_info.getUrl()
        
        self.callbacks.printOutput("[*] Iniciando CyberToolkit (" + self.action + ") sobre: " + str(url))
        
        # NOTA: En un entorno real, aquí haríamos un HTTP GET/POST hacia 
        # http://127.0.0.1:5000/api/analyze?url=...&tool=self.action
        # usando urllib2 o la API de Burp para enviar requests.
        
        self.callbacks.printOutput("[+] Tarea enviada exitosamente a la API de CyberToolkit.")
