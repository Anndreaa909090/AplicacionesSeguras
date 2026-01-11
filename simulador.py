import streamlit as st
import random
import pandas as pd
from datetime import datetime
from collections import defaultdict
import json

# ============================================
# 1. CARGAR Y ESTRUCTURAR LAS PREGUNTAS
# ============================================

def cargar_preguntas():
    """Estructura todas las preguntas del documento"""
    
    # ===== SECCIÓN 1: APLICACIONES SEGURAS =====
    seccion1 = [
        {
            "pregunta": "¿Una vulnerabilidad es un ataque exitoso que ha comprometido un sistema?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "¿La validación de entradas no es necesaria si se confía en los usuarios?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "¿Shellcoding se refiere a un tipo de malware utilizado para atacar aplicaciones?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "¿La seguridad de red se centra en proteger las aplicaciones y sistemas informáticos?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las aplicaciones juegan un papel fundamental en la vida cotidiana.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad de aplicaciones no es importante en redes sociales.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Una vulnerabilidad es una debilidad que puede ser explotada por una amenaza.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Los ataques de ingeniería social son considerados una amenaza para la seguridad de las aplicaciones.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Implementar políticas de contraseñas fuertes puede ayudar a prevenir accesos no autorizados.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La validación de entradas ayuda a prevenir ataques.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Cuál de los siguientes es un principio fundamental en el desarrollo de aplicaciones seguras?",
            "tipo": "opcion_multiple",
            "opciones": ["Diseño rápido", "Diseño seguro", "Diseño simple", "Diseño modular"],
            "respuesta": "Diseño seguro"
        },
        {
            "pregunta": "¿Qué se entiende por vulnerabilidad en el contexto de la seguridad de aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": ["Una amenaza externa", "Una debilidad que puede ser explotada", "Un tipo de malware", "Un firewall"],
            "respuesta": "Una debilidad que puede ser explotada"
        },
        {
            "pregunta": "¿Qué se debe hacer para evitar la inyección de SQL en una aplicación Java?",
            "tipo": "opcion_multiple",
            "opciones": ["Usar Statement", "Implementar PreparedStatement", "Usar concatenación de strings", "Desactivar la base de datos"],
            "respuesta": "Implementar PreparedStatement"
        },
        {
            "pregunta": "En el contexto de la seguridad de aplicaciones, ¿qué significa 'Shellcoding'?",
            "tipo": "opcion_multiple",
            "opciones": ["Un lenguaje de programación", "La explotación de un desbordamiento de buffer", "Un tipo de cifrado", "Una herramienta de testing"],
            "respuesta": "La explotación de un desbordamiento de buffer"
        },
        {
            "pregunta": "¿Cuál es un tipo común de vulnerabilidad?",
            "tipo": "opcion_multiple",
            "opciones": ["VPN", "Inyección", "Firewall", "Antivirus"],
            "respuesta": "Inyección"
        },
        {
            "pregunta": "¿Qué es una vulnerabilidad?",
            "tipo": "opcion_multiple",
            "opciones": ["Un ataque activo", "Una debilidad explotable", "Un firewall", "Un antivirus"],
            "respuesta": "Una debilidad explotable"
        },
        {
            "pregunta": "¿Cuál es un ejemplo de amenaza?",
            "tipo": "opcion_multiple",
            "opciones": ["Código limpio", "Malware", "Parche de seguridad", "Auditoría"],
            "respuesta": "Malware"
        },
        {
            "pregunta": "¿Cuál de las siguientes opciones representa una amenaza para la seguridad de las aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": ["Actualizaciones de software", "Ataques de hacking", "Copias de seguridad", "Documentación"],
            "respuesta": "Ataques de hacking"
        },
        {
            "pregunta": "Relaciona los principios de seguridad en el desarrollo de aplicaciones con su descripción:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Validación de Entradas": "Verificar y limpiar todas las entradas de usuario para evitar ataques",
                "Gestión de Permisos": "Implementar un modelo de permisos y privilegios adecuado",
                "Cifrado de Datos": "Proteger la confidencialidad de la información sensible",
                "Diseño Seguro": "Integrar la seguridad desde el principio del proceso de desarrollo"
            }
        },
        {
            "pregunta": "¿Cuál es el objetivo de los modelos de seguridad de aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": ["Aumentar velocidad", "Proteger datos y sistemas", "Reducir costos", "Eliminar usuarios"],
            "respuesta": "Proteger datos y sistemas"
        }
    ]
    
    # ===== SECCIÓN 2: CRIPTOGRAFÍA Y CIFRADO =====
    seccion2 = [
        {
            "pregunta": "Uno de los mejores algoritmos de Hashing es MD5.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "SHA-256 es un algoritmo Simétrico.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La función Hash es un proceso en dos direcciones (Reversible).",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Stream Cipher es un algoritmo que utiliza la misma clave para encriptar y desencriptar datos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El mejor algoritmo de Stream Cipher es RC4.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "ChaCha20 es un algoritmo asimétrico.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "TLS 1.3 se utiliza en protocolos con puertos 80 o 8080.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Criptografía de Flujo admite hasta 128 a 256 bits.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "En términos de Seguridad de Aplicaciones Seguras, es lo mismo Encriptación que Hashing.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El cifrado protege la confidencialidad de la información.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El hashing permite recuperar los datos originales.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "AES es un algoritmo de encriptación simétrica.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "DES es más seguro que AES.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La encriptación simétrica usa la misma clave.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La encriptación asimétrica es más rápida que la simétrica.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "HTTPS utiliza encriptación asimétrica.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "ChaCha20 es ideal para datos en tiempo real.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La gestión de claves es una buena práctica de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Qué algoritmo es obsoleto para hashing?",
            "tipo": "opcion_multiple",
            "opciones": ["SHA-256", "SHA-3", "MD5", "AES"],
            "respuesta": "MD5"
        },
        {
            "pregunta": "¿Cuál es una característica del hashing?",
            "tipo": "opcion_multiple",
            "opciones": ["Reversible", "Bidireccional", "Unidireccional", "Simétrica"],
            "respuesta": "Unidireccional"
        },
        {
            "pregunta": "¿Qué algoritmo de flujo es recomendado actualmente?",
            "tipo": "opcion_multiple",
            "opciones": ["RC4", "DES", "ChaCha20", "MD5"],
            "respuesta": "ChaCha20"
        },
        {
            "pregunta": "¿Qué combina la encriptación híbrida?",
            "tipo": "opcion_multiple",
            "opciones": ["Hash y firma", "Simétrica y asimétrica", "Red y hardware", "Software y red"],
            "respuesta": "Simétrica y asimétrica"
        },
        {
            "pregunta": "¿Qué algoritmo cifra datos en BitLocker?",
            "tipo": "opcion_multiple",
            "opciones": ["RSA", "AES", "MD5", "SHA-1"],
            "respuesta": "AES"
        },
        {
            "pregunta": "¿Para qué sirve la encriptación?",
            "tipo": "opcion_multiple",
            "opciones": ["Eliminar datos", "Proteger confidencialidad", "Acelerar sistemas", "Crear backups"],
            "respuesta": "Proteger confidencialidad"
        },
        {
            "pregunta": "¿Quién es Bruce Schneier?",
            "tipo": "opcion_multiple",
            "opciones": ["Hacker", "Criptógrafo", "Programador web", "Ingeniero civil"],
            "respuesta": "Criptógrafo"
        },
        {
            "pregunta": "¿Qué algoritmo se usa en JWT HS256?",
            "tipo": "opcion_multiple",
            "opciones": ["RSA", "AES", "HMAC", "ECC"],
            "respuesta": "HMAC"
        }
    ]
    
    # ===== SECCIÓN 3: SEGURIDAD DE LA INFORMACIÓN =====
    seccion3 = [
        {
            "pregunta": "¿Proporcionar confidencialidad a la información manejada por un sistema, es uno de los objetivos de seguridad?",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad de la información implica la implementación de estrategias que cubran los procesos de la organización en los cuales la información es el activo primordial.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Un sistema informático seguro e impenetrable a prueba de todo ataque se puede definir a un sistema donde se puede incluir técnicas sofisticadas de criptografía.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La simple negligencia de un empleado relativa a la política de claves de seguridad puede permitir el vulnerable al sistema más seguro del mundo.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Un sistema de seguridad incluye también a personas y procedimientos, más allá de los sistemas informáticos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Pensar que la tecnología puede solucionar tus problemas de seguridad, eso quiere decir que no comprendes los problemas y que no comprendes la tecnología.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La política de seguridad de una organización es estática.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La seguridad debe entenderse como un proceso dinámico.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El principio de privilegio mínimo busca reducir accesos innecesarios.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Todos los usuarios deberían tener privilegios de administrador.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La defensa en profundidad utiliza varios niveles de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La diversidad de defensa obliga al atacante a usar distintos conocimientos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Señala la información correcta:",
            "tipo": "opcion_multiple",
            "opciones": [
                "Http response splitting es una vulnerabilidad que permite inyectar código html en una aplicación web",
                "La inyección SQL no afecta bases de datos",
                "XSS es un protocolo de seguridad",
                "CSRF protege aplicaciones web"
            ],
            "respuesta": "Http response splitting es una vulnerabilidad que permite inyectar código html en una aplicación web"
        },
        {
            "pregunta": "¿Qué propiedad busca garantizar la seguridad de aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": ["Disponibilidad", "Confidencialidad", "Integridad", "Todas las anteriores"],
            "respuesta": "Todas las anteriores"
        },
        {
            "pregunta": "¿Qué describe el principio de privilegio mínimo?",
            "tipo": "opcion_multiple",
            "opciones": ["Dar acceso total", "Minimizar privilegios innecesarios", "Usar contraseñas fuertes", "Implementar cifrado"],
            "respuesta": "Minimizar privilegios innecesarios"
        },
        {
            "pregunta": "¿Qué busca la defensa en profundidad?",
            "tipo": "opcion_multiple",
            "opciones": ["Una sola barrera", "Varias capas de seguridad", "Solo firewalls", "Solo autenticación"],
            "respuesta": "Varias capas de seguridad"
        },
        {
            "pregunta": "Relaciona los tipos de ataques con su descripción:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Ataque de condiciones de carrera (TOCTOU)": "En un sistema multiusuario un atacante puede substituir un archivo en una ventana muy breve entre verificación y uso",
                "Ataque con sniffer": "Software que captura paquetes del tráfico de red para capturar nombres de usuario y passwords transmitidos en claro",
                "Ataque de hombre en medio": "El atacante intercepta la comunicación entre dos hosts y suplanta la identidad de una de las partes"
            }
        }
    ]
    
    # ===== SECCIÓN 4: VULNERABILIDADES Y AMENAZAS =====
    seccion4 = [
        {
            "pregunta": "Una Amenaza es una debilidad que puede ser explotada con la materialización de una o varias amenazas a un activo.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Una Vulnerabilidad es un evento que puede causar un incidente de seguridad produciendo pérdidas o daños potenciales en sus activos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Un incidente es todo aquello que permite que se pueda desarrollar una amenaza.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Un mal cifrado de la contraseña puede ser una vulnerabilidad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Si hay vulnerabilidad no hay riesgo de amenaza.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El desbordamiento de Buffer, ocurre cuando se aplica una Inyección SQL sobre el Código.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El impacto de un incidente de seguridad puede incluir robo de identidad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La inyección SQL modifica consultas de bases de datos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "CSRF es un tipo de ataque de inyección SQL.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El desbordamiento de buffer ocurre cuando no se controla la memoria.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Shellcoding es una técnica de defensa.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las contraseñas débiles representan una vulnerabilidad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las configuraciones predeterminadas suelen ser seguras.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Agregue la palabra correcta: Pérdida de datos, robo de identidad, interrupción del servicio, multas y sanciones, daño potencial a servicios, recursos o sistemas",
            "tipo": "opcion_multiple",
            "opciones": ["Vulnerabilidad", "Amenaza", "Impacto", "Riesgo"],
            "respuesta": "Impacto"
        },
        {
            "pregunta": "Cuál es la técnica de ataque del siguiente código: SELECT * FROM users WHERE username = 'admin' --' AND password = 'password';",
            "tipo": "opcion_multiple",
            "opciones": ["Cross-Site Scripting (XSS)", "Inyección SQL (SQL Injection)", "CSRF", "Buffer Overflow"],
            "respuesta": "Inyección SQL (SQL Injection)"
        },
        {
            "pregunta": "Cuál es la técnica de ataque del siguiente código: <script>alert('XSS');</script>",
            "tipo": "opcion_multiple",
            "opciones": ["Inyección SQL", "Cross-Site Scripting (XSS)", "CSRF", "Man-in-the-Middle"],
            "respuesta": "Cross-Site Scripting (XSS)"
        },
        {
            "pregunta": "¿Cuál NO es un impacto de un ataque de seguridad?",
            "tipo": "opcion_multiple",
            "opciones": ["Robo de datos", "Multas", "Mejora del sistema", "Interrupción del servicio"],
            "respuesta": "Mejora del sistema"
        },
        {
            "pregunta": "¿Qué problema surge con cuentas transmitidas sin seguridad?",
            "tipo": "opcion_multiple",
            "opciones": ["Mejor rendimiento", "Exposición de credenciales", "Alta disponibilidad", "Autenticación fuerte"],
            "respuesta": "Exposición de credenciales"
        },
        {
            "pregunta": "¿Qué servicio mal configurado puede causar ataques por scripts hostiles?",
            "tipo": "opcion_multiple",
            "opciones": ["DNS", "JavaScript en navegadores", "VPN", "SMTP"],
            "respuesta": "JavaScript en navegadores"
        },
        {
            "pregunta": "¿Qué dispositivo puede verse afectado por malas configuraciones?",
            "tipo": "opcion_multiple",
            "opciones": ["Router", "Firewall", "Equipo de red", "Todos los anteriores"],
            "respuesta": "Todos los anteriores"
        },
        {
            "pregunta": "Relaciona las vulnerabilidades con sus descripciones:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Equipos de red mal configurados": "ACLs mal configuradas, protocolos de enrutamiento o cadenas en firewall mal definidas",
                "Servicios de Internet mal configurados": "JavaScript activado en exploradores permite ataques mediante scripts hostiles",
                "Cuentas de usuario no seguras": "Información de cuentas transmitida de manera insegura expone credenciales",
                "Contraseñas débiles": "Contraseñas deficientes y fáciles de adivinar por aplicaciones de ciberataque"
            }
        }
    ]
    
    # ===== SECCIÓN 5: PRUEBAS Y ANÁLISIS DE SEGURIDAD =====
    seccion5 = [
        {
            "pregunta": "El escaneo de vulnerabilidades automatiza la identificación de configuraciones inseguras y debilidades conocidas.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El análisis dinámico evalúa el comportamiento del software en tiempo de ejecución para detectar problemas de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El análisis estático de código permite detectar vulnerabilidades sin necesidad de ejecutar la aplicación.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las herramientas de análisis de seguridad de código pueden generar falsos positivos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las pruebas de seguridad basadas en el riesgo tienen como objetivo principal verificar la estética del software.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las pruebas de seguridad buscan identificar vulnerabilidades.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La revisión de código analiza el código fuente.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las pruebas dinámicas analizan el código sin ejecutarlo.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El análisis estático se realiza sin ejecutar la aplicación.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las pruebas de penetración simulan ataques reales.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las pruebas basadas en requisitos detectan comportamiento hostil.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las pruebas basadas en riesgo analizan el sistema desde la perspectiva del atacante.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Un falso negativo significa que la herramienta no detectó un problema real.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "DAST analiza el código fuente sin ejecutar la aplicación.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "OWASP ZAP es una herramienta de pruebas dinámicas.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Cuál es el objetivo principal de las pruebas de penetración?",
            "tipo": "opcion_multiple",
            "opciones": ["Mejorar la UI", "Identificar vulnerabilidades explotables", "Reducir costos", "Aumentar velocidad"],
            "respuesta": "Identificar vulnerabilidades explotables"
        },
        {
            "pregunta": "¿Cuál de las siguientes herramientas se utiliza para realizar pruebas de penetración?",
            "tipo": "opcion_multiple",
            "opciones": ["SonarQube", "ZAP", "ESLint", "Jenkins"],
            "respuesta": "ZAP"
        },
        {
            "pregunta": "¿Qué técnica permite detectar vulnerabilidades y errores lógicos en el código fuente sin ejecutar la aplicación?",
            "tipo": "opcion_multiple",
            "opciones": ["Análisis dinámico", "Análisis estático de código", "Fuzzing", "Penetration testing"],
            "respuesta": "Análisis estático de código"
        },
        {
            "pregunta": "¿Qué tipo de prueba corresponde a caja blanca?",
            "tipo": "opcion_multiple",
            "opciones": ["Pruebas de penetración", "Análisis estático de código", "Análisis dinámico", "Fuzzing"],
            "respuesta": "Análisis estático de código"
        },
        {
            "pregunta": "¿Qué herramienta se usa para pruebas de penetración?",
            "tipo": "opcion_multiple",
            "opciones": ["SonarQube", "ESLint", "Metasploit", "PMD"],
            "respuesta": "Metasploit"
        },
        {
            "pregunta": "¿Qué evalúa el análisis dinámico?",
            "tipo": "opcion_multiple",
            "opciones": ["Código fuente", "Arquitectura", "Comportamiento en ejecución", "Documentación"],
            "respuesta": "Comportamiento en ejecución"
        },
        {
            "pregunta": "¿Qué técnica envía datos malformados al sistema?",
            "tipo": "opcion_multiple",
            "opciones": ["Análisis estático", "Fuzzing", "Revisión manual", "Escaneo de red"],
            "respuesta": "Fuzzing"
        },
        {
            "pregunta": "¿Qué herramienta es usada para análisis de código binario?",
            "tipo": "opcion_multiple",
            "opciones": ["OWASP ZAP", "Ghidra", "SonarQube", "Burp Suite"],
            "respuesta": "Ghidra"
        },
        {
            "pregunta": "¿Cuál es un objetivo de las pruebas basadas en riesgo?",
            "tipo": "opcion_multiple",
            "opciones": ["Mejorar la interfaz", "Verificar la operación bajo ataques", "Reducir costos", "Aumentar rendimiento"],
            "respuesta": "Verificar la operación bajo ataques"
        },
        {
            "pregunta": "¿Qué categoría pertenece al análisis híbrido?",
            "tipo": "opcion_multiple",
            "opciones": ["Caja blanca", "Caja negra", "Caja gris", "Caja cerrada"],
            "respuesta": "Caja gris"
        },
        {
            "pregunta": "¿Qué herramienta combina análisis estático y dinámico?",
            "tipo": "opcion_multiple",
            "opciones": ["Veracode", "Nmap", "Metasploit", "Nessus"],
            "respuesta": "Veracode"
        }
    ]
    
    seccion6 = [
        {
            "pregunta": "2FA y MFA significan exactamente lo mismo.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La autenticación responde a la pregunta '¿Quién eres?'.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La autorización verifica la identidad del usuario.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La biometría es un factor de autenticación.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "MFA puede incluir biometría y comportamiento.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La autenticación sin contraseña puede usar FIDO2.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El método tradicional de autenticación es muy resistente al phishing.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "SSO permite acceso a múltiples sistemas con una sola autenticación.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "OAuth es un protocolo de cifrado de discos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "DAC permite que el propietario decida los accesos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "MAC permite modificar reglas libremente.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "RBAC asigna permisos según roles.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "RBAC facilita la administración en organizaciones grandes.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "MAC se basa en políticas obligatorias y centralizadas.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Qué factor corresponde a 'algo que sabes'?",
            "tipo": "opcion_multiple",
            "opciones": ["Token", "Huella", "Contraseña", "Ubicación"],
            "respuesta": "Contraseña"
        },
        {
            "pregunta": "¿Qué factor corresponde a 'algo que tienes'?",
            "tipo": "opcion_multiple",
            "opciones": ["PIN", "Contraseña", "Token", "Patrón de comportamiento"],
            "respuesta": "Token"
        },
        {
            "pregunta": "¿Cuál es un ejemplo de 'algo que eres'?",
            "tipo": "opcion_multiple",
            "opciones": ["Token", "Huella dactilar", "Contraseña", "PIN"],
            "respuesta": "Huella dactilar"
        },
        {
            "pregunta": "¿Qué protocolo usa tickets para autenticación centralizada?",
            "tipo": "opcion_multiple",
            "opciones": ["LDAP", "Kerberos", "JWT", "RADIUS"],
            "respuesta": "Kerberos"
        },
        {
            "pregunta": "¿Qué tecnología transporta información de autenticación de forma compacta?",
            "tipo": "opcion_multiple",
            "opciones": ["LDAP", "JWT", "SSL", "AES"],
            "respuesta": "JWT"
        },
        {
            "pregunta": "¿Qué protocolo se usa para delegación de accesos?",
            "tipo": "opcion_multiple",
            "opciones": ["Kerberos", "OAuth 2.0", "RADIUS", "TACACS+"],
            "respuesta": "OAuth 2.0"
        },
        {
            "pregunta": "¿Qué pregunta responde la autorización?",
            "tipo": "opcion_multiple",
            "opciones": ["¿Quién eres?", "¿Dónde estás?", "¿Qué puedes hacer?", "¿Cuándo ingresas?"],
            "respuesta": "¿Qué puedes hacer?"
        },
        {
            "pregunta": "¿Cuál NO es un componente del control de acceso?",
            "tipo": "opcion_multiple",
            "opciones": ["Autenticación", "Autorización", "Auditoría", "Encriptación"],
            "respuesta": "Encriptación"
        },
        {
            "pregunta": "¿Qué modelo de control de acceso usan sistemas militares?",
            "tipo": "opcion_multiple",
            "opciones": ["DAC", "RBAC", "MAC", "ACL"],
            "respuesta": "MAC"
        },
        {
            "pregunta": "¿Qué modelo es ideal para sistemas empresariales?",
            "tipo": "opcion_multiple",
            "opciones": ["DAC", "MAC", "RBAC", "ABAC"],
            "respuesta": "RBAC"
        },
        {
            "pregunta": "¿Qué framework es ejemplo de autenticación?",
            "tipo": "opcion_multiple",
            "opciones": ["Hibernate", "Spring Security", "Maven", "React"],
            "respuesta": "Spring Security"
        },
        {
            "pregunta": "¿Qué se usa comúnmente para acceso seguro a APIs?",
            "tipo": "opcion_multiple",
            "opciones": ["Cookies", "JWT", "FTP", "HTTP"],
            "respuesta": "JWT"
        }
    ]
    
    # ===== SECCIÓN 7: PROTECCIÓN DE DATOS =====
    seccion7 = [
        {
            "pregunta": "El cifrado en tránsito usa HTTPS.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "AES-256 se usa para cifrado en reposo.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La rotación de claves mejora la seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La protección de datos sensibles solo aplica a datos financieros.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La confidencialidad es un pilar de la protección de datos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las listas blancas controlan qué entradas se aceptan.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las listas negras son más seguras que las blancas.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La sanitización limpia datos ingresados por usuarios.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La codificación URL permite transmisión segura de datos web.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La validación de entradas verifica formato, tipo y longitud.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Cuál de las siguientes técnicas se usa para cifrar datos almacenados en reposo?",
            "tipo": "opcion_multiple",
            "opciones": ["HTTP", "AES-256 y RSA", "FTP", "SMTP"],
            "respuesta": "AES-256 y RSA"
        },
        {
            "pregunta": "¿Qué acción permite detectar actividades inusuales en BD?",
            "tipo": "opcion_multiple",
            "opciones": ["Cifrado", "Auditoría", "Indexación", "Normalización"],
            "respuesta": "Auditoría"
        },
        {
            "pregunta": "¿Qué técnica elimina toda posibilidad de identificar a una persona?",
            "tipo": "opcion_multiple",
            "opciones": ["Pseudonimización", "Anonimización", "Tokenización", "Hashing"],
            "respuesta": "Anonimización"
        },
        {
            "pregunta": "¿Qué técnica es reversible mediante una clave?",
            "tipo": "opcion_multiple",
            "opciones": ["Anonimización", "Cifrado", "Pseudonimización", "Hashing"],
            "respuesta": "Pseudonimización"
        },
        {
            "pregunta": "¿Cuál sigue considerándose dato personal según la ley?",
            "tipo": "opcion_multiple",
            "opciones": ["Anonimizado", "Eliminado", "Pseudonimizado", "Público"],
            "respuesta": "Pseudonimizado"
        },
        {
            "pregunta": "¿Qué previene la validación de entradas?",
            "tipo": "opcion_multiple",
            "opciones": ["Ataques de fuerza bruta", "Inyección y exploits", "DDoS", "Malware"],
            "respuesta": "Inyección y exploits"
        },
        {
            "pregunta": "¿Qué técnica evita ataques XSS y SQL?",
            "tipo": "opcion_multiple",
            "opciones": ["Compresión", "Escapar caracteres", "Backup", "Cache"],
            "respuesta": "Escapar caracteres"
        }
    ]
    
    # ===== SECCIÓN 8: DESARROLLO SEGURO (SDLC) =====
    seccion8 = [
        {
            "pregunta": "Según OWASP, una aplicación segura mitiga vulnerabilidades críticas y recurrentes.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Una aplicación segura no necesita proteger los datos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El SDLC integra seguridad en todas las fases del desarrollo.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad solo debe aplicarse en la etapa de pruebas.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El S-SDLC busca garantizar confidencialidad, integridad y disponibilidad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El análisis de riesgos es parte del desarrollo seguro.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El modelado de amenazas no forma parte del S-SDLC.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El desarrollo seguro reduce la cantidad de vulnerabilidades explotables.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las buenas prácticas de seguridad solo aplican al código final.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El mantenimiento es una etapa del ciclo de vida seguro.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Un software seguro no necesita manejar excepciones.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El manejo seguro de errores evita la divulgación de información sensible.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Qué significa SDLC?",
            "tipo": "opcion_multiple",
            "opciones": ["Secure Data Life Control", "Software Development Life Cycle", "System Design Level Control", "Secure Development Logic Code"],
            "respuesta": "Software Development Life Cycle"
        },
        {
            "pregunta": "¿En qué etapa se definen los requisitos de seguridad?",
            "tipo": "opcion_multiple",
            "opciones": ["Implementación", "Pruebas", "Planificación", "Despliegue"],
            "respuesta": "Planificación"
        },
        {
            "pregunta": "¿En qué fase se identifican los riesgos de seguridad?",
            "tipo": "opcion_multiple",
            "opciones": ["Diseño", "Análisis", "Mantenimiento", "Pruebas"],
            "respuesta": "Análisis"
        },
        {
            "pregunta": "¿En qué fase se codifica la aplicación?",
            "tipo": "opcion_multiple",
            "opciones": ["Diseño", "Implementación", "Análisis", "Pruebas"],
            "respuesta": "Implementación"
        },
        {
            "pregunta": "¿En qué etapa se realizan pruebas de seguridad?",
            "tipo": "opcion_multiple",
            "opciones": ["Diseño", "Implementación", "Pruebas", "Despliegue"],
            "respuesta": "Pruebas"
        },
        {
            "pregunta": "¿Qué práctica captura errores usando try-catch?",
            "tipo": "opcion_multiple",
            "opciones": ["Auditoría", "Control de excepciones", "Análisis estático", "Cifrado"],
            "respuesta": "Control de excepciones"
        },
        {
            "pregunta": "¿Qué busca el manejo centralizado de errores?",
            "tipo": "opcion_multiple",
            "opciones": ["Velocidad", "Coherencia", "Rendimiento", "Usabilidad"],
            "respuesta": "Coherencia"
        }
    ]
    
    # ===== SECCIÓN 9: CODIFICACIÓN SEGURA =====
    seccion9 = [
        {
            "pregunta": "La codificación segura incluye manejo de entradas de datos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El desbordamiento de buffer es un defecto de implementación.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La privacidad no es parte de la codificación segura.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Inicializar variables correctamente es una buena práctica.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Confiar en URLs externas es una práctica segura.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El uso de bibliotecas de terceros puede introducir riesgos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Los falsos positivos son más peligrosos que los falsos negativos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Los errores del programador pueden causar vulnerabilidades.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Confiar ciegamente en software de terceros es una mala práctica.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "OutOfMemoryError está relacionado con problemas de memoria.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Cuál es una mala práctica?",
            "tipo": "opcion_multiple",
            "opciones": ["Revisar código", "Almacenar contraseñas cifradas", "Visualizar contraseñas en pantalla", "Validar entradas"],
            "respuesta": "Visualizar contraseñas en pantalla"
        },
        {
            "pregunta": "¿Qué práctica es insegura?",
            "tipo": "opcion_multiple",
            "opciones": ["Usar librerías seguras", "Transmitir contraseñas cifradas", "Codificar contraseñas en la aplicación", "Validar parámetros"],
            "respuesta": "Codificar contraseñas en la aplicación"
        },
        {
            "pregunta": "¿Qué vulnerabilidad se mitiga validando entradas?",
            "tipo": "opcion_multiple",
            "opciones": ["DDoS", "Inyección SQL", "Phishing", "Spoofing"],
            "respuesta": "Inyección SQL"
        },
        {
            "pregunta": "¿Qué técnica mitiga XSS?",
            "tipo": "opcion_multiple",
            "opciones": ["Hashing", "Escapar y codificar datos", "Compresión", "Backup"],
            "respuesta": "Escapar y codificar datos"
        },
        {
            "pregunta": "¿Qué previene el buffer overflow?",
            "tipo": "opcion_multiple",
            "opciones": ["Firewalls", "Programación segura", "VPN", "IDS"],
            "respuesta": "Programación segura"
        },
        {
            "pregunta": "¿Cuál es un ejercicio básico de seguridad?",
            "tipo": "opcion_multiple",
            "opciones": ["Implementar JWT", "Leer solo números", "Firmar software", "Crear VPN"],
            "respuesta": "Leer solo números"
        },
        {
            "pregunta": "¿Qué se utiliza para evitar inyección SQL en Java?",
            "tipo": "opcion_multiple",
            "opciones": ["Statement", "PreparedStatement", "Driver", "HashMap"],
            "respuesta": "PreparedStatement"
        }
    ]
    
    # ===== SECCIÓN 10: SPRING SECURITY =====
    seccion10 = [
        {
            "pregunta": "Spring Security se basa en el OWASP Top 10.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Spring Security solo maneja autenticación.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La inyección SQL es una vulnerabilidad común en aplicaciones web.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "JPA permite consultas parametrizadas para prevenir SQLi.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "SQL Injection ocurre cuando la entrada del usuario se ejecuta como código.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "CSRF afecta a peticiones que modifican estado.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El token CSRF debe validarse solo en peticiones GET.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Content-Security-Policy ayuda a mitigar XSS.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "X-Content-Type-Options previene MIME Sniffing.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El hardening es opcional en aplicaciones Spring Boot.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La autorización a nivel de método aplica mínimo privilegio.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "@PreAuthorize y @PostAuthorize controlan accesos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La autorización solo se aplica a nivel de controlador.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La validación de entrada trata la información como datos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El Mass Assignment es un riesgo de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Qué framework se usa para seguridad en Spring Boot?",
            "tipo": "opcion_multiple",
            "opciones": ["Hibernate", "Spring MVC", "Spring Security", "Thymeleaf"],
            "respuesta": "Spring Security"
        },
        {
            "pregunta": "¿Qué técnica previene SQL Injection en Spring Boot?",
            "tipo": "opcion_multiple",
            "opciones": ["Concatenar consultas", "Consultas parametrizadas", "Variables globales", "Logs"],
            "respuesta": "Consultas parametrizadas"
        },
        {
            "pregunta": "¿Qué cabecera fuerza el uso de HTTPS?",
            "tipo": "opcion_multiple",
            "opciones": ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"],
            "respuesta": "Strict-Transport-Security"
        },
        {
            "pregunta": "¿Qué cabecera previene Clickjacking?",
            "tipo": "opcion_multiple",
            "opciones": ["CSP", "HSTS", "X-Frame-Options", "Authorization"],
            "respuesta": "X-Frame-Options"
        },
        {
            "pregunta": "¿En qué métodos HTTP se valida el token CSRF?",
            "tipo": "opcion_multiple",
            "opciones": ["GET", "POST, PUT, DELETE", "OPTIONS", "HEAD"],
            "respuesta": "POST, PUT, DELETE"
        },
        {
            "pregunta": "¿Qué técnica se usa para validar entradas en Spring Boot?",
            "tipo": "opcion_multiple",
            "opciones": ["Regex manual", "Bean Validation", "Logs", "JWT"],
            "respuesta": "Bean Validation"
        },
        {
            "pregunta": "¿Qué anotación pertenece a Bean Validation?",
            "tipo": "opcion_multiple",
            "opciones": ["@Autowired", "@Valid", "@Service", "@Entity"],
            "respuesta": "@Valid"
        },
        {
            "pregunta": "¿Qué vulnerabilidad previene Bean Validation?",
            "tipo": "opcion_multiple",
            "opciones": ["DDoS", "Mass Assignment", "Spoofing", "Sniffing"],
            "respuesta": "Mass Assignment"
        },
        {
            "pregunta": "¿Qué anotación se usa para autorización a nivel de método?",
            "tipo": "opcion_multiple",
            "opciones": ["@NotNull", "@PreAuthorize", "@Pattern", "@Valid"],
            "respuesta": "@PreAuthorize"
        },
        {
            "pregunta": "¿Qué principio se refuerza con autorización por roles?",
            "tipo": "opcion_multiple",
            "opciones": ["Disponibilidad", "Mínimo privilegio", "Redundancia", "Tolerancia a fallos"],
            "respuesta": "Mínimo privilegio"
        }
    ]

    seccion11 = [
        {
            "pregunta": "OWASP define una aplicación segura como aquella que mitiga vulnerabilidades críticas y recurrentes.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Una aplicación segura no necesita controles de seguridad si funciona correctamente.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El ataque a Equifax ocurrió por no aplicar un parche disponible.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El caso Equifax fue causado por una vulnerabilidad desconocida.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La deuda de seguridad se relaciona con fallos de gestión.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Las vulnerabilidades de día cero ya no representan un riesgo.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La defensa en profundidad sigue siendo clave en seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El hardening ayuda a detectar fallos de configuración.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El ataque a Equifax ocurrió por una inyección en Apache Struts.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El hardening reduce configuraciones débiles por defecto.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El monitoreo es parte de una estrategia de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Conocer una vulnerabilidad es suficiente para estar protegido.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las pruebas dinámicas identifican vulnerabilidades reales.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad debe combinar configuración, pruebas y monitoreo.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Qué organización define buenas prácticas para aplicaciones web seguras?",
            "tipo": "opcion_multiple",
            "opciones": ["ISO", "IEEE", "OWASP", "NIST"],
            "respuesta": "OWASP"
        },
        {
            "pregunta": "¿Qué tipo de fallo ocurrió en el caso Equifax?",
            "tipo": "opcion_multiple",
            "opciones": ["Error de cifrado", "Fallo de gestión", "Ataque de día cero", "Error de hardware"],
            "respuesta": "Fallo de gestión"
        },
        {
            "pregunta": "¿Qué tipo de prueba simula ataques reales en ejecución?",
            "tipo": "opcion_multiple",
            "opciones": ["SAST", "DAST", "Revisión manual", "Auditoría"],
            "respuesta": "DAST"
        },
        {
            "pregunta": "¿Qué herramienta DAST se menciona en el material?",
            "tipo": "opcion_multiple",
            "opciones": ["SonarQube", "Nessus", "OWASP ZAP", "Fortify"],
            "respuesta": "OWASP ZAP"
        },
        {
            "pregunta": "¿Qué tipo de vulnerabilidades puede detectar DAST?",
            "tipo": "opcion_multiple",
            "opciones": ["Solo errores de sintaxis", "Fallos lógicos y de configuración", "Errores de compilación", "Problemas de UI"],
            "respuesta": "Fallos lógicos y de configuración"
        },
        {
            "pregunta": "¿Qué enseña el caso Equifax?",
            "tipo": "opcion_multiple",
            "opciones": ["Usar nuevos frameworks", "Aplicar parches a tiempo", "Evitar auditorías", "Desactivar firewalls"],
            "respuesta": "Aplicar parches a tiempo"
        },
        {
            "pregunta": "¿Qué perspectiva ofrece OWASP ZAP?",
            "tipo": "opcion_multiple",
            "opciones": ["Usuario final", "Administrador", "Atacante", "Desarrollador frontend"],
            "respuesta": "Atacante"
        },
        {
            "pregunta": "¿Qué fortalece la resiliencia de aplicaciones web?",
            "tipo": "opcion_multiple",
            "opciones": ["Solo cifrado", "Configuración segura y pruebas dinámicas", "UI moderna", "Más servidores"],
            "respuesta": "Configuración segura y pruebas dinámicas"
        },
        {
            "pregunta": "¿Qué principio busca integrar seguridad desde el inicio del desarrollo?",
            "tipo": "opcion_multiple",
            "opciones": ["Cifrado de datos", "Diseño seguro", "Gestión de permisos", "Auditoría"],
            "respuesta": "Diseño seguro"
        }
    ]
    
    # ===== SECCIÓN 12: SEGURIDAD EN LA NUBE =====
    seccion12 = [
        {
            "pregunta": "Amazon VPC (Virtual Private Cloud) es un servicio de AWS que permite crear una red virtual privada dentro de la nube.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Azure App Service es un servicio de plataforma como servicio (PaaS) de Microsoft Azure.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La computación en la nube es un modelo de entrega bajo demanda que permite el acceso ubicuo y escalable a recursos compartidos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Amazon DynamoDB es un servicio de base de datos NoSQL totalmente administrado de AWS.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La computación en la nube define un nuevo modelo en el que los proveedores cloud comparten recursos accesibles en Internet bajo demanda.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "AWS (Amazon Web Services) es una plataforma de servicios en la nube desarrollada por Flex.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "AWS Lambda es un servicio de computación sin servidor (serverless) de Amazon Web Services.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El Portal de Azure es una interfaz web desarrollada por Microsoft que permite administrar todos los servicios de Azure.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Man-in-the-Middle es un tipo de ataque.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La rotación de claves reduce riesgos de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La auditoría y monitoreo ayudan a detectar ataques.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Marque lo correcto en relación a Amazon S3",
            "tipo": "opcion_multiple",
            "opciones": [
                "Solo almacena imágenes",
                "No tiene cifrado",
                "Todas son correctas: es un servicio de almacenamiento de objetos seguro, escalable y con gestión de permisos mediante IAM",
                "No permite acceso por Internet"
            ],
            "respuesta": "Todas son correctas: es un servicio de almacenamiento de objetos seguro, escalable y con gestión de permisos mediante IAM"
        },
        {
            "pregunta": "Relaciona las características principales de Computación en la Nube:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Acceso remoto": "Se accede por Internet desde cualquier lugar",
                "Mantenimiento gestionado": "El proveedor se encarga de actualizaciones, seguridad y disponibilidad",
                "Escalabilidad": "Permite aumentar o disminuir recursos según la demanda",
                "Pago por uso": "Se paga por los recursos utilizados"
            }
        },
        {
            "pregunta": "Relaciona los modelos de servicio:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "IaaS (Infrastructure as a Service)": "Proporciona infraestructura básica (máquinas virtuales, redes, almacenamiento)",
                "PaaS (Platform as a Service)": "Ofrece una plataforma para desarrollar y desplegar aplicaciones sin preocuparse por la infraestructura",
                "SaaS (Software as a Service)": "Brinda aplicaciones listas para usar a través de internet como Gmail o Microsoft 365"
            }
        },
        {
            "pregunta": "Relaciona los tipos de nube:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Nube pública": "Los recursos se comparten entre varios usuarios (por ejemplo, AWS, Azure)",
                "Nube privada": "Los recursos son usados solo por una organización",
                "Nube híbrida": "Combina recursos de nubes públicas y privadas"
            }
        },
        {
            "pregunta": "Relaciona las categorías de los servicios de Azure:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Almacenamiento (Storage)": "Blob Storage, File Storage, Disk Storage",
                "Cómputo (Compute)": "Azure Virtual Machines, Azure Functions, App Service",
                "Redes (Networking)": "Virtual Network, Load Balancer, VPN Gateway",
                "Bases de datos (Databases)": "Azure SQL Database, Cosmos DB, MySQL, PostgreSQL"
            }
        }
    ]
    
    # ===== SECCIÓN 13: TIPOS DE SEGURIDAD =====
    seccion13 = [
        {
            "pregunta": "La seguridad de hardware protege dispositivos físicos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad de software se enfoca en redes únicamente.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La seguridad de red usa firewalls y VPN.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad de aplicaciones web incluye codificación segura.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad de la información protege datos sensibles.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El cifrado de datos no se utiliza para proteger la confidencialidad de la información sensible.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las contraseñas débiles son una práctica recomendada en la gestión de cuentas de usuario.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Un algoritmo simétrico es fundamental para videoconferencias y que al utilizar un simétrico se vuelve más lento.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La Encriptación Híbrida entrega seguridad pero no velocidad debido a su alta complejidad de implementación.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "AES para intercambio de claves. RSA para la encriptación de datos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Hashing es importante para Firmas digitales para autenticación de software.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "RSA-2048 (simétrica) + AES-256 (asimétrica).",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Evitar un ataque side-channel, es aplicar expresiones regulares a nuestro código.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Señala cuál es una vulnerabilidad de implementación:",
            "tipo": "opcion_multiple",
            "opciones": [
                "Solo XSS",
                "Solo SQLI",
                "Solo CSRF",
                "Todas las anteriores son ciertas (XSS, SQLI, CSRF)"
            ],
            "respuesta": "Todas las anteriores son ciertas (XSS, SQLI, CSRF)"
        },
        {
            "pregunta": "La siguiente definición corresponde a la Seguridad de aplicaciones:",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Qué framework gestiona JPA/Hibernate?",
            "tipo": "opcion_multiple",
            "opciones": ["Seguridad de red", "Persistencia de datos", "UI", "Logging"],
            "respuesta": "Persistencia de datos"
        },
        {
            "pregunta": "¿Qué tipo de auditoría soporta Spring Boot según el material?",
            "tipo": "opcion_multiple",
            "opciones": ["Auditoría contable", "Auditoría SAST", "Auditoría física", "Auditoría legal"],
            "respuesta": "Auditoría SAST"
        },
        {
            "pregunta": "Marque lo correcto en relación a AWS:",
            "tipo": "opcion_multiple",
            "opciones": [
                "No tiene infraestructura global",
                "Solo tiene una región",
                "La infraestructura global está dividida en regiones geográficas y zonas de disponibilidad",
                "No proporciona continuidad del negocio"
            ],
            "respuesta": "La infraestructura global está dividida en regiones geográficas y zonas de disponibilidad"
        },
        {
            "pregunta": "Marque lo correcto en relación a AWS Management Console:",
            "tipo": "opcion_multiple",
            "opciones": [
                "Solo funciona desde línea de comandos",
                "Es una interfaz web gráfica que permite administrar todos los servicios de AWS",
                "No permite crear recursos",
                "Solo sirve para ver métricas"
            ],
            "respuesta": "Es una interfaz web gráfica que permite administrar todos los servicios de AWS"
        },
        {
            "pregunta": "Marque lo correcto en relación a la seguridad en nube pública y privada:",
            "tipo": "opcion_multiple",
            "opciones": [
                "En la nube pública el cliente no tiene responsabilidad",
                "En la nube pública se comparte la responsabilidad entre proveedor y cliente (modelo de responsabilidad compartida)",
                "En la nube privada no hay control de acceso",
                "La seguridad física no importa en la nube"
            ],
            "respuesta": "En la nube pública se comparte la responsabilidad entre proveedor y cliente (modelo de responsabilidad compartida)"
        },
        {
            "pregunta": "Marque lo correcto en relación a las opciones para desplegar apps desde App Service Azure:",
            "tipo": "opcion_multiple",
            "opciones": [
                "Solo con Visual Studio",
                "Despliegue con Visual Studio, DevOps pipelines, portal de Azure y contenedores Docker",
                "Solo con contenedores",
                "No se puede desplegar desde el portal"
            ],
            "respuesta": "Despliegue con Visual Studio, DevOps pipelines, portal de Azure y contenedores Docker"
        }
    ]

    # Combinar todas las secciones
    todas_preguntas = (seccion1 + seccion2 + seccion3 + seccion4 + seccion5 + 
                       seccion6 + seccion7 + seccion8 + seccion9 + seccion10 + 
                       seccion11 + seccion12 + seccion13)
    
    # Asegurar que cada pregunta tenga un ID único y sección
    secciones = [
        ("Aplicaciones Seguras", seccion1),
        ("Criptografía", seccion2),
        ("Seguridad de la Información", seccion3),
        ("Seguridad en la Nube", seccion4),
        ("Docker y Contenedores", seccion5),
        ("Inteligencia Artificial", seccion6),
        ("Agentes Inteligentes", seccion7),
        ("Machine Learning", seccion8),
        ("Redes Neuronales", seccion9),
        ("Visión por Computadora", seccion10),
        ("Procesamiento de Lenguaje", seccion11),
        ("Vulnerabilidades", seccion12),
        ("Seguridad General", seccion13)
    ]
    
    id_global = 0
    for nombre_seccion, preguntas_seccion in secciones:
        for pregunta in preguntas_seccion:
            pregunta["id_unico"] = id_global
            pregunta["seccion"] = nombre_seccion
            id_global += 1
    
    return todas_preguntas

# ============================================
# 2. FUNCIONES DE GESTIÓN DE SESIÓN
# ============================================

def inicializar_sesion():
    """Inicializa las variables de sesión de Streamlit"""
    if 'inicializado' not in st.session_state:
        todas_preguntas = cargar_preguntas()
        
        st.session_state.banco_completo_preguntas = todas_preguntas.copy()
        st.session_state.preguntas_usadas = set()  # IDs de preguntas ya usadas
        st.session_state.historial_tests = []  # Historial de tests realizados
        st.session_state.test_actual = None
        st.session_state.estado = "inicio"  # inicio, test_activo, resultados
        st.session_state.inicializado = True

def obtener_preguntas_disponibles():
    """Retorna preguntas que no han sido usadas"""
    disponibles = [
        p for p in st.session_state.banco_completo_preguntas 
        if p["id_unico"] not in st.session_state.preguntas_usadas
    ]
    return disponibles

def reiniciar_banco_preguntas():
    """Reinicia el banco de preguntas cuando se agoten"""
    st.session_state.preguntas_usadas = set()
    st.info("🔄 Se ha reiniciado el banco de preguntas. Puedes continuar con el test.")

# ============================================
# 3. FUNCIONES DEL TEST
# ============================================

def crear_nuevo_test():
    """Crea un nuevo test con 90 preguntas aleatorias"""
    preguntas_disponibles = obtener_preguntas_disponibles()
    
    # Validar si hay suficientes preguntas
    if len(preguntas_disponibles) < 90:
        if len(st.session_state.banco_completo_preguntas) < 90:
            st.error("❌ Error: El banco debe tener al menos 90 preguntas.")
            return None
        else:
            # Reiniciar automáticamente
            reiniciar_banco_preguntas()
            preguntas_disponibles = obtener_preguntas_disponibles()
    
    # Seleccionar 90 preguntas aleatorias
    preguntas_seleccionadas = random.sample(preguntas_disponibles, 90)
    
    # Marcar como usadas
    for pregunta in preguntas_seleccionadas:
        st.session_state.preguntas_usadas.add(pregunta["id_unico"])
    
    # Crear objeto de test
    test = {
        "id": len(st.session_state.historial_tests) + 1,
        "fecha_inicio": datetime.now(),
        "preguntas": preguntas_seleccionadas,
        "respuestas": {},  # {indice: respuesta}
        "indice_actual": 0,
        "completado": False,
        "fecha_finalizacion": None,
        "puntaje": None,
        "detalle_resultados": None
    }
    
    return test

def validar_respuesta(pregunta, respuesta_usuario):
    """Valida si una respuesta es correcta y retorna información detallada"""
    resultado = {
        "correcta": False,
        "puntos": 0,
        "respuesta_usuario": respuesta_usuario,
        "respuesta_correcta": None,
        "explicacion": ""
    }
    
    if respuesta_usuario is None:
        resultado["explicacion"] = "❌ No respondiste esta pregunta."
        return resultado
    
    if pregunta["tipo"] == "true_false":
        resultado["respuesta_correcta"] = pregunta["respuesta"]
        if respuesta_usuario == pregunta["respuesta"]:
            resultado["correcta"] = True
            resultado["puntos"] = 1
            resultado["explicacion"] = f"✅ Correcto. La respuesta es {'Verdadero' if respuesta_usuario else 'Falso'}."
        else:
            resultado["explicacion"] = f"❌ Incorrecto. Tu respuesta: {'Verdadero' if respuesta_usuario else 'Falso'}. La respuesta correcta es: {'Verdadero' if pregunta['respuesta'] else 'Falso'}."
    
    elif pregunta["tipo"] == "opcion_multiple":
        resultado["respuesta_correcta"] = pregunta["respuesta"]
        if respuesta_usuario == pregunta["respuesta"]:
            resultado["correcta"] = True
            resultado["puntos"] = 1
            resultado["explicacion"] = f"✅ Correcto. '{respuesta_usuario}' es la respuesta correcta."
        else:
            resultado["explicacion"] = f"❌ Incorrecto. Tu respuesta: '{respuesta_usuario}'. La respuesta correcta es: '{pregunta['respuesta']}'."
    
    elif pregunta["tipo"] == "unir_conceptos":
        resultado["respuesta_correcta"] = pregunta["conceptos"]
        aciertos = 0
        total_relaciones = len(pregunta["conceptos"])
        detalles = []
        
        for concepto, respuesta_correcta in pregunta["conceptos"].items():
            if respuesta_usuario.get(concepto) == respuesta_correcta:
                aciertos += 1
                detalles.append(f"✅ {concepto}: Correcto")
            else:
                detalles.append(f"❌ {concepto}: Tu respuesta: '{respuesta_usuario.get(concepto, 'Sin respuesta')}' | Correcta: '{respuesta_correcta}'")
        
        # Sistema de puntos proporcional
        if aciertos == total_relaciones:
            resultado["correcta"] = True
            resultado["puntos"] = 1
            resultado["explicacion"] = "✅ Perfecto. Todas las relaciones son correctas.\n" + "\n".join(detalles)
        elif aciertos >= total_relaciones / 2:
            resultado["puntos"] = 0.5
            resultado["explicacion"] = f"⚠️ Parcial. {aciertos}/{total_relaciones} relaciones correctas.\n" + "\n".join(detalles)
        else:
            resultado["explicacion"] = f"❌ Incorrecto. Solo {aciertos}/{total_relaciones} relaciones correctas.\n" + "\n".join(detalles)
    
    return resultado

def calcular_resultados(test):
    """Calcula los resultados finales del test"""
    puntaje_total = 0
    detalle = []
    
    for i, pregunta in enumerate(test["preguntas"]):
        respuesta_usuario = test["respuestas"].get(i)
        resultado = validar_respuesta(pregunta, respuesta_usuario)
        
        puntaje_total += resultado["puntos"]
        
        detalle.append({
            "numero": i + 1,
            "pregunta": pregunta["pregunta"],
            "tipo": pregunta["tipo"],
            "seccion": pregunta.get("seccion", "Sin categoría"),
            "correcta": resultado["correcta"],
            "puntos": resultado["puntos"],
            "explicacion": resultado["explicacion"],
            "respuesta_usuario": resultado["respuesta_usuario"],
            "respuesta_correcta": resultado["respuesta_correcta"]
        })
    
    # Calcular estadísticas
    total_preguntas = len(test["preguntas"])
    correctas = sum(1 for d in detalle if d["correcta"])
    incorrectas = total_preguntas - correctas
    porcentaje = (puntaje_total / total_preguntas) * 100
    aprobado = puntaje_total >= 68
    
    # Análisis por sección
    errores_por_seccion = defaultdict(int)
    total_por_seccion = defaultdict(int)
    
    for item in detalle:
        seccion = item["seccion"]
        total_por_seccion[seccion] += 1
        if not item["correcta"]:
            errores_por_seccion[seccion] += 1
    
    resultados = {
        "puntaje_total": puntaje_total,
        "total_preguntas": total_preguntas,
        "correctas": correctas,
        "incorrectas": incorrectas,
        "porcentaje": porcentaje,
        "aprobado": aprobado,
        "detalle": detalle,
        "errores_por_seccion": dict(errores_por_seccion),
        "total_por_seccion": dict(total_por_seccion)
    }
    
    return resultados

# ============================================
# 4. FUNCIONES DE INTERFAZ
# ============================================

def mostrar_pregunta(pregunta, indice, test):
    """Muestra una pregunta según su tipo con validación"""
    st.markdown(f"### 📝 Pregunta {indice + 1} de 90")
    st.markdown(f"**Categoría:** {pregunta.get('seccion', 'General')}")
    st.write("")
    
    # Contenedor para la pregunta
    with st.container():
        st.markdown(f"**{pregunta['pregunta']}**")
        st.write("")
        
        if pregunta["tipo"] == "true_false":
            # Radio button para Verdadero/Falso
            respuesta_actual = test["respuestas"].get(indice)
            if respuesta_actual is not None:
                index_actual = 0 if respuesta_actual else 1
            else:
                index_actual = None
            
            respuesta = st.radio(
                "Selecciona tu respuesta:",
                ["Verdadero", "Falso"],
                index=index_actual,
                key=f"pregunta_{indice}_{pregunta['id_unico']}"
            )
            
            # Guardar respuesta automáticamente
            test["respuestas"][indice] = (respuesta == "Verdadero")
        
        elif pregunta["tipo"] == "opcion_multiple":
            opciones = pregunta["opciones"].copy()
            
            # Usar un seed basado en el ID para que el orden sea consistente
            random.seed(pregunta["id_unico"])
            random.shuffle(opciones)
            random.seed()  # Reset seed
            
            respuesta_actual = test["respuestas"].get(indice)
            index_actual = opciones.index(respuesta_actual) if respuesta_actual in opciones else None
            
            respuesta = st.radio(
                "Selecciona la opción correcta:",
                opciones,
                index=index_actual,
                key=f"pregunta_{indice}_{pregunta['id_unico']}"
            )
            
            test["respuestas"][indice] = respuesta
        
        elif pregunta["tipo"] == "unir_conceptos":
            st.write("**Relaciona cada concepto con su definición:**")
            st.write("")
            
            conceptos = list(pregunta["conceptos"].keys())
            todas_definiciones = list(pregunta["conceptos"].values())
            
            # Mezclar definiciones de forma consistente
            random.seed(pregunta["id_unico"])
            random.shuffle(todas_definiciones)
            random.seed()
            
            respuestas_unir = test["respuestas"].get(indice, {})
            if not isinstance(respuestas_unir, dict):
                respuestas_unir = {}
            
            for concepto in conceptos:
                st.markdown(f"**{concepto}**")
                
                # Crear opciones para este concepto
                definicion_correcta = pregunta["conceptos"][concepto]
                opciones_definiciones = [definicion_correcta]
                
                # Añadir otras definiciones
                otras = [d for d in todas_definiciones if d != definicion_correcta]
                opciones_definiciones.extend(otras[:min(3, len(otras))])
                
                # Mezclar opciones de forma consistente
                random.seed(pregunta["id_unico"] + hash(concepto))
                random.shuffle(opciones_definiciones)
                random.seed()
                
                respuesta_actual = respuestas_unir.get(concepto)
                index_actual = opciones_definiciones.index(respuesta_actual) if respuesta_actual in opciones_definiciones else 0
                
                seleccion = st.selectbox(
                    f"Definición para {concepto}:",
                    opciones_definiciones,
                    index=index_actual,
                    key=f"unir_{indice}_{pregunta['id_unico']}_{concepto}"
                )
                
                respuestas_unir[concepto] = seleccion
            
            test["respuestas"][indice] = respuestas_unir

def mostrar_navegacion_preguntas(test):
    """Muestra navegación visual de las preguntas"""
    st.write("---")
    st.markdown("### 🗺️ Navegación Rápida")
    
    cols = st.columns(15)
    for i in range(90):
        col_index = i % 15
        with cols[col_index]:
            # Determinar el estado de la pregunta
            if i in test["respuestas"]:
                emoji = "✅"
                tipo = "secondary"
            else:
                emoji = "⬜"
                tipo = "secondary"
            
            if i == test["indice_actual"]:
                emoji = "👉"
            
            if st.button(f"{emoji}{i+1}", key=f"nav_{i}", type=tipo, use_container_width=True):
                test["indice_actual"] = i
                st.rerun()

def mostrar_resultados(test, resultados):
    """Muestra los resultados del test de forma detallada"""
    st.title("🎯 Resultados del Test")
    st.write(f"**Test N°:** {test['id']}")
    st.write(f"**Fecha:** {test['fecha_finalizacion'].strftime('%d/%m/%Y %H:%M')}")
    st.write("")
    
    # Métricas principales
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Puntaje", f"{resultados['puntaje_total']:.1f}/90")
    with col2:
        st.metric("Porcentaje", f"{resultados['porcentaje']:.1f}%")
    with col3:
        st.metric("✅ Correctas", resultados['correctas'])
    with col4:
        st.metric("❌ Incorrectas", resultados['incorrectas'])
    
    # Barra de progreso
    st.progress(resultados['porcentaje'] / 100)
    st.write("")
    
    # Estado de aprobación
    if resultados['aprobado']:
        st.success("### ✅ ¡APROBADO! ¡Felicidades! 🎉")
        st.balloons()
    else:
        st.error(f"### ❌ NO APROBADO")
        st.info(f"Necesitas al menos 68 puntos. Te faltaron {68 - resultados['puntaje_total']:.1f} puntos.")
    
    st.write("---")
    
    # Análisis por sección
    st.markdown("### 📊 Análisis por Categoría")
    
    if resultados['errores_por_seccion']:
        df_secciones = pd.DataFrame([
            {
                "Categoría": seccion,
                "Total": resultados['total_por_seccion'][seccion],
                "Errores": errores,
                "Aciertos": resultados['total_por_seccion'][seccion] - errores,
                "% Acierto": f"{((resultados['total_por_seccion'][seccion] - errores) / resultados['total_por_seccion'][seccion] * 100):.1f}%"
            }
            for seccion, errores in sorted(
                resultados['errores_por_seccion'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )
        ])
        
        st.dataframe(df_secciones, use_container_width=True, hide_index=True)
        
        st.write("")
        st.markdown("**💡 Áreas para mejorar:**")
        top_errores = sorted(
            resultados['errores_por_seccion'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:3]
        
        for seccion, errores in top_errores:
            st.write(f"- **{seccion}**: {errores} errores")
    
    st.write("---")
    
    # Revisión detallada
    st.markdown("### 📋 Revisión Detallada")
    
    filtro = st.selectbox(
        "Filtrar preguntas:",
        ["Todas las preguntas", "Solo incorrectas ❌", "Solo correctas ✅"],
        key="filtro_resultados"
    )
    
    detalle_filtrado = resultados['detalle']
    if filtro == "Solo incorrectas ❌":
        detalle_filtrado = [d for d in resultados['detalle'] if not d['correcta']]
    elif filtro == "Solo correctas ✅":
        detalle_filtrado = [d for d in resultados['detalle'] if d['correcta']]
    
    if not detalle_filtrado:
        st.info("No hay preguntas que mostrar con el filtro seleccionado.")
    else:
        st.write(f"**Mostrando {len(detalle_filtrado)} preguntas**")
        st.write("")
        
        for item in detalle_filtrado:
            icono = "✅" if item['correcta'] else "❌"
            titulo = f"{icono} Pregunta {item['numero']}: {item['pregunta'][:80]}..."
            
            with st.expander(titulo, expanded=False):
                col1, col2 = st.columns([1, 3])
                
                with col1:
                    if item['correcta']:
                        st.success(f"✅ Correcta\n\n**+{item['puntos']} pts**")
                    else:
                        st.error(f"❌ Incorrecta\n\n**{item['puntos']} pts**")
                
                with col2:
                    st.markdown(f"**Categoría:** {item['seccion']}")
                    st.markdown(f"**Tipo:** {item['tipo'].replace('_', ' ').title()}")
                
                st.write("")
                st.markdown("**Pregunta:**")
                st.info(item['pregunta'])
                
                st.markdown("**Explicación:**")
                st.write(item['explicacion'])
    
    st.write("---")
    
    # Exportar resultados
    st.markdown("### 💾 Exportar Resultados")
    
    resumen_texto = generar_resumen_texto(test, resultados)
    
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            label="📄 Descargar Resumen (TXT)",
            data=resumen_texto,
            file_name=f"resultados_test_{test['id']}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain"
        )
    
    with col2:
        # Crear CSV con detalle
        df_detalle = pd.DataFrame(resultados['detalle'])
        csv = df_detalle.to_csv(index=False)
        
        st.download_button(
            label="📊 Descargar Detalle (CSV)",
            data=csv,
            file_name=f"detalle_test_{test['id']}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )

def generar_resumen_texto(test, resultados):
    """Genera un resumen en texto plano"""
    linea = "=" * 80
    resumen = f"""
{linea}
RESULTADOS DEL TEST DE SEGURIDAD INFORMÁTICA
{linea}

Test N°: {test['id']}
Fecha: {test['fecha_finalizacion'].strftime('%d/%m/%Y %H:%M')}

RESUMEN GENERAL:
{linea}
Puntaje Total: {resultados['puntaje_total']:.1f}/90
Porcentaje: {resultados['porcentaje']:.1f}%
Estado: {'APROBADO ✅' if resultados['aprobado'] else 'NO APROBADO ❌'}

Preguntas Correctas: {resultados['correctas']}
Preguntas Incorrectas: {resultados['incorrectas']}
Total de Preguntas: {resultados['total_preguntas']}

ANÁLISIS POR CATEGORÍA:
{linea}
"""
    
    for seccion, total in resultados['total_por_seccion'].items():
        errores = resultados['errores_por_seccion'].get(seccion, 0)
        aciertos = total - errores
        porcentaje_acierto = (aciertos / total * 100) if total > 0 else 0
        resumen += f"\n{seccion}:"
        resumen += f"\n  - Total: {total} preguntas"
        resumen += f"\n  - Aciertos: {aciertos}"
        resumen += f"\n  - Errores: {errores}"
        resumen += f"\n  - % Acierto: {porcentaje_acierto:.1f}%\n"
    
    resumen += f"\n{linea}\nDETALLE DE PREGUNTAS:\n{linea}\n"
    
    for item in resultados['detalle']:
        resumen += f"\nPregunta {item['numero']}: {item['pregunta']}\n"
        resumen += f"Categoría: {item['seccion']}\n"
        resumen += f"Tipo: {item['tipo'].replace('_', ' ').title()}\n"
        resumen += f"Estado: {'✅ Correcta' if item['correcta'] else '❌ Incorrecta'}\n"
        resumen += f"Puntos: {item['puntos']}\n"
        resumen += f"{item['explicacion']}\n"
        resumen += "-" * 80 + "\n"
    
    return resumen

# ============================================
# 5. INTERFAZ PRINCIPAL
# ============================================

def main():
    st.set_page_config(
        page_title="Simulador de Seguridad Informática",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Inicializar sesión
    inicializar_sesion()
    
    # Título principal
    st.title("🔐 Simulador de Preguntas de Seguridad Informática")
    st.markdown("*Preparación para exámenes de certificación en seguridad*")
    st.write("")
    
    # Sidebar con información
    with st.sidebar:
        st.header("📊 Panel de Control")
        
        total_banco = len(st.session_state.banco_completo_preguntas)
        usadas = len(st.session_state.preguntas_usadas)
        disponibles = total_banco - usadas
        
        st.metric("Total en Banco", total_banco)
        st.metric("Preguntas Disponibles", disponibles)
        st.metric("Preguntas Usadas", usadas)
        st.metric("Tests Realizados", len(st.session_state.historial_tests))
        
        st.write("")
        st.progress(usadas / total_banco if total_banco > 0 else 0)
        st.caption(f"{(usadas/total_banco*100):.1f}% del banco utilizado")
        
        st.write("---")
        
        # Historial de tests
        if st.session_state.historial_tests:
            st.subheader("📜 Historial")
            for test_hist in reversed(st.session_state.historial_tests[-5:]):
                if test_hist.get('completado'):
                    resultados = test_hist.get('detalle_resultados')
                    if resultados:
                        icono = "✅" if resultados['aprobado'] else "❌"
                        st.write(f"{icono} Test #{test_hist['id']}: {resultados['puntaje_total']:.1f}/90")
        
        st.write("---")
        
        # Información y ayuda
        with st.expander("ℹ️ Información", expanded=False):
            st.markdown("""
            **Características:**
            - 90 preguntas por test
            - Preguntas sin repetición
            - Puntaje mínimo: 68/90
            - Análisis detallado
            - Exportación de resultados
            
            **Tipos de preguntas:**
            - Verdadero/Falso
            - Opción múltiple
            - Relacionar conceptos
            """)
        
        st.write("")
        if st.button("🔄 Reiniciar Todo", type="secondary", use_container_width=True):
            if st.session_state.get('confirmar_reinicio', False):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
            else:
                st.session_state.confirmar_reinicio = True
                st.warning("⚠️ Presiona nuevamente para confirmar")
    
    # Contenido principal según el estado
    if st.session_state.estado == "inicio":
        mostrar_pantalla_inicio()
    
    elif st.session_state.estado == "test_activo":
        mostrar_pantalla_test()
    
    elif st.session_state.estado == "resultados":
        mostrar_pantalla_resultados()

def mostrar_pantalla_inicio():
    """Pantalla inicial del simulador"""
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("## 🎯 Bienvenido al Simulador")
        st.write("Este simulador te ayudará a prepararte para exámenes de seguridad informática con preguntas de diversas categorías.")
        
        st.write("")
        st.markdown("### 📚 Categorías Disponibles:")
        
        categorias = [
            "🔒 Aplicaciones Seguras",
            "🔐 Criptografía",
            "📊 Seguridad de la Información",
            "☁️ Seguridad en la Nube",
            "🐳 Docker y Contenedores",
            "🤖 Inteligencia Artificial",
            "🧠 Machine Learning",
            "🔬 Redes Neuronales",
            "👁️ Visión por Computadora",
            "💬 Procesamiento de Lenguaje Natural",
            "🔍 Vulnerabilidades",
            "🛡️ Seguridad General"
        ]
        
        cols = st.columns(3)
        for i, cat in enumerate(categorias):
            with cols[i % 3]:
                st.write(cat)
        
        st.write("")
        st.write("---")
        
        # Verificar si hay preguntas disponibles
        disponibles = len(obtener_preguntas_disponibles())
        
        if disponibles < 90:
            st.warning(f"⚠️ Solo quedan {disponibles} preguntas disponibles. El banco se reiniciará automáticamente.")
        
        if st.button("🚀 Comenzar Nuevo Test", type="primary", use_container_width=True):
            test = crear_nuevo_test()
            if test:
                st.session_state.test_actual = test
                st.session_state.estado = "test_activo"
                st.rerun()
    
    with col2:
        st.markdown("### 📋 Instrucciones")
        st.info("""
        **Cómo funcionar:**
        
        1️⃣ Cada test tiene **90 preguntas** aleatorias
        
        2️⃣ Las preguntas **no se repiten** entre tests
        
        3️⃣ Puntaje mínimo: **68/90** (75.6%)
        
        4️⃣ Puedes **navegar** entre preguntas
        
        5️⃣ Las respuestas se **guardan automáticamente**
        
        6️⃣ Al finalizar verás un **análisis detallado**
        
        7️⃣ Podrás **exportar** tus resultados
        """)
        
        st.write("")
        
        if st.session_state.historial_tests:
            mejor_puntaje = max(
                [t.get('puntaje', 0) for t in st.session_state.historial_tests if t.get('completado', False)],
                default=0
            )
            st.metric("🏆 Mejor Puntaje", f"{mejor_puntaje:.1f}/90")

def mostrar_pantalla_test():
    """Pantalla donde se realiza el test"""
    test = st.session_state.test_actual
    
    if not test:
        st.error("❌ Error: No hay test activo")
        st.session_state.estado = "inicio"
        st.rerun()
        return
    
    # Barra de progreso superior
    progreso = (test["indice_actual"] + 1) / 90
    st.progress(progreso)
    
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown(f"**Progreso:** {test['indice_actual'] + 1}/90 preguntas")
    with col2:
        respondidas = len(test["respuestas"])
        st.markdown(f"**Respondidas:** {respondidas}/90")
    with col3:
        faltantes = 90 - respondidas
        if faltantes > 0:
            st.markdown(f"**⚠️ Faltan:** {faltantes}")
        else:
            st.markdown(f"**✅ Todas respondidas**")
    
    st.write("")
    
    # Mostrar pregunta actual
    pregunta_actual = test["preguntas"][test["indice_actual"]]
    mostrar_pregunta(pregunta_actual, test["indice_actual"], test)
    
    st.write("")
    st.write("---")
    
    # Controles de navegación
    col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 2])
    
    with col1:
        if test["indice_actual"] > 0:
            if st.button("⬅️ Anterior", use_container_width=True):
                test["indice_actual"] -= 1
                st.rerun()
        else:
            st.button("⬅️ Anterior", disabled=True, use_container_width=True)
    
    with col2:
        if test["indice_actual"] < 89:
            if st.button("Siguiente ➡️", use_container_width=True):
                test["indice_actual"] += 1
                st.rerun()
        else:
            st.button("Siguiente ➡️", disabled=True, use_container_width=True)
    
    with col3:
        if st.button("🔄 Primera", use_container_width=True):
            test["indice_actual"] = 0
            st.rerun()
    
    with col4:
        if st.button("⏭️ Última", use_container_width=True):
            test["indice_actual"] = 89
            st.rerun()
    
    with col5:
        # Validar si todas las preguntas están respondidas
        todas_respondidas = len(test["respuestas"]) == 90
        
        if todas_respondidas:
            if st.button("✅ Finalizar Test", type="primary", use_container_width=True):
                finalizar_test(test)
        else:
            sin_responder = 90 - len(test["respuestas"])
            st.button(
                f"⚠️ Finalizar ({sin_responder} sin responder)", 
                type="secondary", 
                use_container_width=True,
                on_click=lambda: mostrar_confirmacion_finalizar(test)
            )
    
    # Navegación visual de preguntas
    mostrar_navegacion_preguntas(test)
    
    # Alerta si hay preguntas sin responder
    sin_responder = 90 - len(test["respuestas"])
    if sin_responder > 0:
        st.info(f"ℹ️ Tienes {sin_responder} pregunta(s) sin responder. Las preguntas sin respuesta contarán como incorrectas.")

def mostrar_confirmacion_finalizar(test):
    """Muestra confirmación para finalizar test con preguntas sin responder"""
    sin_responder = 90 - len(test["respuestas"])
    
    if 'confirmar_finalizar' not in st.session_state:
        st.session_state.confirmar_finalizar = False
    
    if st.session_state.confirmar_finalizar:
        finalizar_test(test)
    else:
        st.session_state.confirmar_finalizar = True
        st.warning(f"⚠️ Tienes {sin_responder} preguntas sin responder. ¿Deseas continuar?")

def finalizar_test(test):
    """Finaliza el test y calcula los resultados"""
    test["completado"] = True
    test["fecha_finalizacion"] = datetime.now()
    
    # Calcular resultados
    resultados = calcular_resultados(test)
    
    # Guardar resultados en el test
    test["puntaje"] = resultados["puntaje_total"]
    test["detalle_resultados"] = resultados
    
    # Agregar al historial
    st.session_state.historial_tests.append(test)
    
    # Cambiar estado
    st.session_state.estado = "resultados"
    st.rerun()

def mostrar_pantalla_resultados():
    """Pantalla de resultados del test"""
    test = st.session_state.test_actual
    
    if not test or not test.get("completado"):
        st.error("❌ Error: No hay resultados para mostrar")
        st.session_state.estado = "inicio"
        st.rerun()
        return
    
    resultados = test["detalle_resultados"]
    
    if not resultados:
        st.error("❌ Error: No se pudieron calcular los resultados")
        st.session_state.estado = "inicio"
        st.rerun()
        return
    
    # Mostrar resultados detallados
    mostrar_resultados(test, resultados)
    
    st.write("")
    st.write("---")
    
    # Botones de acción
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 Realizar Otro Test", type="primary", use_container_width=True):
            st.session_state.test_actual = None
            st.session_state.estado = "inicio"
            if 'confirmar_finalizar' in st.session_state:
                del st.session_state.confirmar_finalizar
            st.rerun()
    
    with col2:
        if st.button("📊 Ver Historial Completo", use_container_width=True):
            mostrar_historial_completo()
    
    with col3:
        if st.button("🏠 Volver al Inicio", use_container_width=True):
            st.session_state.test_actual = None
            st.session_state.estado = "inicio"
            if 'confirmar_finalizar' in st.session_state:
                del st.session_state.confirmar_finalizar
            st.rerun()

def mostrar_historial_completo():
    """Muestra el historial completo de tests realizados"""
    st.write("---")
    st.markdown("### 📜 Historial Completo de Tests")
    
    if not st.session_state.historial_tests:
        st.info("No hay tests realizados aún.")
        return
    
    # Crear DataFrame con el historial
    datos_historial = []
    for test in st.session_state.historial_tests:
        if test.get("completado"):
            resultados = test.get("detalle_resultados")
            if resultados:
                datos_historial.append({
                    "Test #": test["id"],
                    "Fecha": test["fecha_finalizacion"].strftime("%d/%m/%Y %H:%M"),
                    "Puntaje": f"{resultados['puntaje_total']:.1f}/90",
                    "Porcentaje": f"{resultados['porcentaje']:.1f}%",
                    "Estado": "✅ Aprobado" if resultados['aprobado'] else "❌ Reprobado",
                    "Correctas": resultados['correctas'],
                    "Incorrectas": resultados['incorrectas']
                })
    
    if datos_historial:
        df_historial = pd.DataFrame(datos_historial)
        st.dataframe(df_historial, use_container_width=True, hide_index=True)
        
        # Estadísticas generales
        st.write("")
        st.markdown("### 📈 Estadísticas Generales")
        
        total_tests = len(datos_historial)
        aprobados = sum(1 for t in st.session_state.historial_tests if t.get("completado") and t.get("detalle_resultados", {}).get("aprobado", False))
        
        puntajes = [t.get("detalle_resultados", {}).get("puntaje_total", 0) for t in st.session_state.historial_tests if t.get("completado")]
        promedio = sum(puntajes) / len(puntajes) if puntajes else 0
        mejor = max(puntajes) if puntajes else 0
        peor = min(puntajes) if puntajes else 0
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Tests", total_tests)
        with col2:
            st.metric("Aprobados", f"{aprobados}/{total_tests}")
        with col3:
            st.metric("Promedio", f"{promedio:.1f}/90")
        with col4:
            st.metric("Mejor Puntaje", f"{mejor:.1f}/90")
        
        # Gráfico de evolución si hay suficientes datos
        if len(puntajes) > 1:
            st.write("")
            st.markdown("### 📊 Evolución de Puntajes")
            
            df_evolucion = pd.DataFrame({
                "Test": [f"Test {i+1}" for i in range(len(puntajes))],
                "Puntaje": puntajes
            })
            
            st.line_chart(df_evolucion.set_index("Test"), height=300)

if __name__ == "__main__":
    main()