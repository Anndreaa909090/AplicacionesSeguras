import streamlit as st
import random
import pandas as pd
from datetime import datetime
from collections import defaultdict

# ============================================
# 1. CARGAR Y ESTRUCTURAR LAS PREGUNTAS
# ============================================

def cargar_preguntas():
    """Estructura todas las preguntas de Aplicaciones Seguras"""
    
    preguntas = [
        # Verdadero/Falso (64 preguntas)
        {
            "pregunta": "Un mal cifrado de la contraseña puede ser una vulnerabilidad.",
            "tipo": "true_false",
            "respuesta": True
        },

        {
            "pregunta": "Con esta salida de seguridad permite solo los grupos pueden acceder al archivo: rwx------",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El privilegio mínimo puede ser similar a un DAC.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Con esta salida otros grupos sí pueden modificar el archivo: rw-r--r--",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La siguiente definición corresponde a la Seguridad de aplicaciones: Las aplicaciones juegan un papel fundamental en nuestras vidas cotidianas, desde aplicaciones bancarias hasta redes sociales, y confiamos en ellas para simplificar tareas, comunicarnos y acceder a servicios esenciales.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Shellcoding se refiere a un tipo de malware utilizado para atacar aplicaciones?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "¿Proporcionar confidencialidad a la información manejada por un sistema es uno de los objetivos de seguridad?",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿La validación de entradas no es necesaria si se confía en los usuarios?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Un sistema informático seguro e impenetrable a prueba de todo ataque se puede definir como totalmente seguro.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Un Principio de diseño Seguro de aplicaciones es evitar la simplicidad porque es como dejar una vulnerabilidad al descubierto.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Si hay vulnerabilidad no hay riesgo de amenaza.",
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
            "pregunta": "La seguridad de la información implica la implementación de estrategias que cubran los procesos de la organización en los cuales la información es el activo primordial.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "El desbordamiento de buffer ocurre cuando se aplica una inyección SQL.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Una Vulnerabilidad es un evento que puede causar un incidente de seguridad produciendo pérdidas o daños potenciales en sus activos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Con esta salida cada tipo de usuario puede modificar no leer: -wx-wx-wx",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "¿Una vulnerabilidad es un ataque exitoso que ha comprometido un sistema?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Implementar políticas de contraseñas fuertes puede ayudar a prevenir accesos no autorizados.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Los ataques de ingeniería social son considerados una amenaza para la seguridad de las aplicaciones.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Una amenaza es una debilidad que puede ser explotada con la materialización de una o varias amenazas a un activo.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "¿La seguridad de red se centra en proteger las aplicaciones y sistemas informáticos?",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Pensar que la tecnología puede solucionar tus problemas de seguridad, eso quiere decir que no comprendes los problemas y que no comprendes la tecnología.",
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
            "pregunta": "Uno de los mejores algoritmos de Hashing es MD5.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "SHA-256 es un algoritmo simétrico.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La función Hash es un proceso en dos direcciones (reversible).",
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
            "pregunta": "Un algoritmo simétrico es fundamental para videoconferencias y al utilizar un simétrico se vuelve más lento.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La encriptación híbrida entrega seguridad pero no velocidad debido a su alta complejidad de implementación.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "AES para intercambio de claves y RSA para la encriptación de datos.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Hashing es importante para firmas digitales para autenticación de software.",
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
            "pregunta": "Criptografía de flujo admite hasta 128 a 256 bits.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Un incidente es todo aquello que permite que se pueda desarrollar una amenaza.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El desbordamiento de buffer ocurre cuando se aplica una inyección SQL sobre el código.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "RSA-2048 (simétrica) + AES-256 (asimétrica).",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Evitar un ataque side-channel es aplicar expresiones regulares al código.",
            "tipo": "true_false",
            "respuesta": False
        },
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
            "pregunta": "El principio de privilegio mínimo implica otorgar a los usuarios el máximo nivel de acceso posible para facilitar su trabajo.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las pruebas de seguridad basadas en el riesgo tienen como objetivo principal verificar la estética del software.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El fuzzing testing se utiliza para descubrir errores inesperados enviando datos malformados al sistema.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "Los falsos negativos son más peligrosos que los falsos positivos desde una perspectiva de seguridad.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La gestión de parches y actualizaciones de seguridad solo es necesaria para sistemas operativos, no para aplicaciones de software.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Las pruebas de seguridad deben ser diseñadas sin considerar los riesgos del sistema.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La autenticación de múltiples factores (MFA) requiere que el usuario verifique su identidad mediante al menos dos elementos diferentes.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La revisión de código es una práctica que se realiza únicamente al final del ciclo de desarrollo de software.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "La revisión de código y las pruebas de penetración son prácticas de seguridad que se realizan solo después de que el software ha sido implantado.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El sistema MAC (Control de Acceso Basado en Políticas) permite modificar las reglas de acceso según las necesidades del usuario.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "El uso de bibliotecas y componentes de terceros no presenta riesgos de seguridad en el desarrollo de aplicaciones.",
            "tipo": "true_false",
            "respuesta": False
        },
        {
            "pregunta": "Un sistema informático seguro e impenetrable a prueba de todo ataque se puede definir a un sistema donde se puede incluir técnicas sofisticadas de criptografía, detección de intrusos y seguimiento de la actividad interna.",
            "tipo": "true_false",
            "respuesta": False
        },

        {
            "pregunta": "En contraposición a la seguridad de la información, seguridad informática es un concepto más restrictivo que caracteriza la seguridad técnica de los sistemas informáticos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La pregunta fundamental sobre si el coste de la no-seguridad es mayor que el de la seguridad se relaciona con análisis coste-beneficio.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "La seguridad de la información implica que en contraposición, seguridad informática es un concepto más restrictivo que caracteriza la seguridad técnica de los sistemas informáticos.",
            "tipo": "true_false",
            "respuesta": True
        },
        {
            "pregunta": "HTTP response splitting es una vulnerabilidad que permite inyectar código HTML en una aplicación web.",
            "tipo": "true_false",
            "respuesta": True
        },
        
        # Opción Múltiple (24 preguntas)
        {
            "pregunta": "Señala la afirmación falsa:",
            "tipo": "opcion_multiple",
            "opciones": [
                "Todas las anteriores son falsas",
                "El patrón de diseño MVC tiene tres capas: vista-controlador-modelo",
                "La seguridad de una aplicación debe aplicarse a todas las capas de la misma",
                "Las capas de una aplicación web son: presentación-negocio-persistencia (base de datos)"
            ],
            "respuesta": "Todas las anteriores son falsas"
        },
        {
            "pregunta": "Cuál es la técnica de ataque del siguiente código SQL: SELECT * FROM users WHERE username = 'admin' --' AND password = 'password';",
            "tipo": "opcion_multiple",
            "opciones": [
                "Inyección SQL (SQL Injection)",
                "Cross-Site Scripting (XSS)",
                "Cross-Site Request Forgery (CSRF)",
                "Buffer Overflow"
            ],
            "respuesta": "Inyección SQL (SQL Injection)"
        },
        {
            "pregunta": "Señala cuál es una vulnerabilidad de implementación:",
            "tipo": "opcion_multiple",
            "opciones": [
                "Todas las anteriores son ciertas",
                "Desbordamiento de buffer",
                "Inyección SQL",
                "Validación incorrecta de entradas"
            ],
            "respuesta": "Todas las anteriores son ciertas"
        },
        {
            "pregunta": "¿Cuáles son los niveles de ataques que existen en el software?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Nivel de Datos, Presentación, Diseño, Implementación y Operación",
                "Nivel de Red, Aplicación y Sistema",
                "Nivel Físico, Lógico y de Usuario",
                "Nivel Básico, Intermedio y Avanzado"
            ],
            "respuesta": "Nivel de Datos, Presentación, Diseño, Implementación y Operación"
        },
        {
            "pregunta": "¿Cuál es la técnica de ataque del siguiente código? <script>alert('XSS');</script>",
            "tipo": "opcion_multiple",
            "opciones": [
                "Cross-Site Scripting (XSS)",
                "Inyección SQL",
                "Buffer Overflow",
                "Man-in-the-Middle"
            ],
            "respuesta": "Cross-Site Scripting (XSS)"
        },
        {
            "pregunta": "Agregue la palabra correcta: Pérdida de datos, robo de identidad, interrupción del servicio, multas y sanciones, daño potencial a servicios, recursos o sistema.",
            "tipo": "opcion_multiple",
            "opciones": [
                "Impacto",
                "Amenaza",
                "Vulnerabilidad",
                "Riesgo"
            ],
            "respuesta": "Impacto"
        },
        {
            "pregunta": "Señala la información correcta:",
            "tipo": "opcion_multiple",
            "opciones": [
                "HTTP response splitting es una vulnerabilidad que permite inyectar código HTML en una aplicación web",
                "HTTP response splitting es un tipo de cifrado",
                "HTTP response splitting es un protocolo seguro",
                "HTTP response splitting es un método de autenticación"
            ],
            "respuesta": "HTTP response splitting es una vulnerabilidad que permite inyectar código HTML en una aplicación web"
        },
        {
            "pregunta": "¿Cuál de los siguientes es un principio fundamental en el desarrollo de aplicaciones seguras?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Diseño seguro",
                "Diseño complejo",
                "Diseño rápido",
                "Diseño económico"
            ],
            "respuesta": "Diseño seguro"
        },
        {
            "pregunta": "¿Cuáles son los objetivos de seguridad de los sistemas TIC?",
            "tipo": "opcion_multiple",
            "opciones": [
                "No repudio, trazabilidad, autenticación, autorización y control de acceso, confidencialidad, disponibilidad e integridad",
                "Solo confidencialidad y disponibilidad",
                "Solo autenticación y autorización",
                "Solo integridad y trazabilidad"
            ],
            "respuesta": "No repudio, trazabilidad, autenticación, autorización y control de acceso, confidencialidad, disponibilidad e integridad"
        },
        {
            "pregunta": "¿Qué se entiende por vulnerabilidad en el contexto de la seguridad de aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Una debilidad que puede ser explotada",
                "Un ataque exitoso",
                "Una amenaza potencial",
                "Un incidente de seguridad"
            ],
            "respuesta": "Una debilidad que puede ser explotada"
        },
        {
            "pregunta": "La pregunta fundamental en la gestión es, si el coste de la «no-seguridad» es mayor que el de la «seguridad», esto se relaciona con:",
            "tipo": "opcion_multiple",
            "opciones": [
                "La gestión de la seguridad tiene que fundamentarse en un análisis coste-beneficio",
                "El presupuesto de TI",
                "La velocidad de desarrollo",
                "La satisfacción del usuario"
            ],
            "respuesta": "La gestión de la seguridad tiene que fundamentarse en un análisis coste-beneficio"
        },
        {
            "pregunta": "¿Qué se debe hacer para evitar la inyección de SQL en una aplicación Java?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Implementar PreparedStatement",
                "Usar concatenación de strings",
                "Deshabilitar la validación",
                "Aumentar permisos de base de datos"
            ],
            "respuesta": "Implementar PreparedStatement"
        },
        {
            "pregunta": "Señala cuál es la técnica de ataque de vulnerabilidad de diseño:",
            "tipo": "opcion_multiple",
            "opciones": [
                "TOCTOU (Time-of-check to time-of-use)",
                "SQL Injection",
                "XSS",
                "CSRF"
            ],
            "respuesta": "TOCTOU (Time-of-check to time-of-use)"
        },
        {
            "pregunta": "En el contexto de la seguridad de aplicaciones, ¿qué significa 'Shellcoding'?",
            "tipo": "opcion_multiple",
            "opciones": [
                "La explotación de un desbordamiento de buffer",
                "Un tipo de cifrado",
                "Un método de autenticación",
                "Una técnica de respaldo"
            ],
            "respuesta": "La explotación de un desbordamiento de buffer"
        },
        {
            "pregunta": "¿Cuál de las siguientes opciones representa una amenaza para la seguridad de las aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Ataques de hacking",
                "Actualizaciones de software",
                "Copias de seguridad",
                "Monitoreo de red"
            ],
            "respuesta": "Ataques de hacking"
        },
        {
            "pregunta": "¿Cuál es el objetivo principal de las pruebas de penetración?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Identificar vulnerabilidades explotables",
                "Mejorar la interfaz de usuario",
                "Aumentar la velocidad del sistema",
                "Reducir costos de desarrollo"
            ],
            "respuesta": "Identificar vulnerabilidades explotables"
        },
        {
            "pregunta": "¿Cuál de las siguientes técnicas se usa para cifrar datos almacenados en reposo?",
            "tipo": "opcion_multiple",
            "opciones": [
                "AES-256 y RSA",
                "MD5 y SHA-1",
                "HTTP y HTTPS",
                "TCP y UDP"
            ],
            "respuesta": "AES-256 y RSA"
        },
        {
            "pregunta": "¿Cuál de las siguientes herramientas se utiliza para realizar pruebas de penetración?",
            "tipo": "opcion_multiple",
            "opciones": [
                "ZAP (Zed Attack Proxy)",
                "Microsoft Word",
                "Adobe Photoshop",
                "Google Chrome"
            ],
            "respuesta": "ZAP (Zed Attack Proxy)"
        },
        {
            "pregunta": "¿Qué técnica permite detectar vulnerabilidades y errores lógicos en el código fuente sin ejecutar la aplicación?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Análisis estático de código",
                "Análisis dinámico",
                "Fuzzing testing",
                "Pruebas de carga"
            ],
            "respuesta": "Análisis estático de código"
        },
        {
            "pregunta": "¿Cuál de los siguientes es un objetivo de las pruebas de seguridad basadas en el riesgo?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Verificar la operación confiable del software bajo condiciones hostiles de ataque",
                "Mejorar el diseño visual",
                "Reducir el tiempo de desarrollo",
                "Aumentar las funcionalidades"
            ],
            "respuesta": "Verificar la operación confiable del software bajo condiciones hostiles de ataque"
        },
        {
            "pregunta": "¿Cuál es la primera etapa del ciclo de vida del desarrollo seguro de aplicaciones (SDLC)?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Planificación",
                "Implementación",
                "Pruebas",
                "Despliegue"
            ],
            "respuesta": "Planificación"
        },
        {
            "pregunta": "¿Para evitar el desbordamiento de búfer?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Validación de Entradas",
                "Aumentar memoria RAM",
                "Deshabilitar firewall",
                "Usar passwords débiles"
            ],
            "respuesta": "Validación de Entradas"
        },
        {
            "pregunta": "¿Qué práctica se recomienda para el manejo de errores en aplicaciones?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Usar bloques try-catch",
                "Mostrar mensajes de error detallados al usuario",
                "Ignorar los errores",
                "Reiniciar la aplicación automáticamente"
            ],
            "respuesta": "Usar bloques try-catch"
        },
        {
            "pregunta": "¿Qué tipo de pruebas se centran en el comportamiento del software en tiempo de ejecución?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Análisis dinámico",
                "Análisis estático",
                "Revisión de código",
                "Documentación"
            ],
            "respuesta": "Análisis dinámico"
        },
        {
            "pregunta": "¿Qué se debe hacer para mitigar el riesgo de inyección SQL?",
            "tipo": "opcion_multiple",
            "opciones": [
                "Escapar caracteres especiales",
                "Deshabilitar la base de datos",
                "Usar solo consultas GET",
                "Aumentar el tiempo de sesión"
            ],
            "respuesta": "Escapar caracteres especiales"
        },
        
        # Unir Conceptos (5 preguntas)
        {
            "pregunta": "Relaciona cada tipo de ataque con su descripción:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Sniffer": "Software que captura paquetes del tráfico de red para obtener nombres de usuario y passwords",
                "Secuestro de sesiones": "Explota debilidades del protocolo TCP/IP secuestrando una conexión establecida",
                "Ataque de hombre en medio": "El atacante intercepta la comunicación entre dos hosts y suplanta la identidad de una de las partes",
                "Ataque de condiciones de carrera (TOCTOU)": "Se aprovecha de una ventana de tiempo entre tareas para substituir archivos o comprometer la seguridad"
            }
        },
        {
            "pregunta": "Relaciona cada principio de seguridad con su implementación:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Proteger la confidencialidad de la información sensible": "Cifrado de Datos",
                "Implementar un modelo de permisos y privilegios adecuado": "Gestión de Permisos",
                "Verificar y limpiar todas las entradas de usuario para evitar ataques": "Validación de entradas",
                "Integrar la seguridad desde el principio del proceso de desarrollo": "Diseño Seguro"
            }
        },
        {
            "pregunta": "Relaciona cada vulnerabilidad con su categoría:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Transmisión insegura de credenciales": "Cuentas de usuario no seguras",
                "Contraseñas fáciles de adivinar": "Cuentas del sistema con contraseñas débiles",
                "Configuraciones por defecto inseguras": "Configuraciones predeterminadas no seguras",
                "Mala configuración de equipos": "Equipos de red mal configurados",
                "Servicios expuestos o mal ajustados": "Servicios de Internet mal configurados"
            }
        },
        {
            "pregunta": "Relaciona cada función de control de acceso con su descripción:",
            "tipo": "unir_conceptos",
            "conceptos": {
                "Control de Acceso": "Permite acceder a la información manejada por un sistema o a los recursos del mismo",
                "Autenticar": "Verificar la identidad de las personas que acceden al sistema",
                "Identificar": "Determinar quién es el usuario que intenta acceder al sistema"
            }
        }
    ]
    
    # Asignar IDs únicos y sección
    for i, pregunta in enumerate(preguntas):
        pregunta["id_unico"] = i
        pregunta["seccion"] = "Aplicaciones Seguras"
    
    return preguntas

# ============================================
# 2. FUNCIONES DE GESTIÓN DE SESIÓN
# ============================================

def inicializar_sesion():
    """Inicializa las variables de sesión de Streamlit"""
    if 'inicializado' not in st.session_state:
        todas_preguntas = cargar_preguntas()
        
        st.session_state.banco_completo_preguntas = todas_preguntas.copy()
        st.session_state.preguntas_usadas = set()
        st.session_state.historial_tests = []
        st.session_state.test_actual = None
        st.session_state.estado = "inicio"
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
    """Crea un nuevo test con 45 preguntas aleatorias"""
    preguntas_disponibles = obtener_preguntas_disponibles()
    
    # Validar si hay suficientes preguntas
    if len(preguntas_disponibles) < 45:
        if len(st.session_state.banco_completo_preguntas) < 45:
            st.error("❌ Error: El banco debe tener al menos 45 preguntas.")
            return None
        else:
            reiniciar_banco_preguntas()
            preguntas_disponibles = obtener_preguntas_disponibles()
    
    # Seleccionar 45 preguntas aleatorias
    preguntas_seleccionadas = random.sample(preguntas_disponibles, 45)
    
    # Marcar como usadas
    for pregunta in preguntas_seleccionadas:
        st.session_state.preguntas_usadas.add(pregunta["id_unico"])
    
    # Crear objeto de test
    test = {
        "id": len(st.session_state.historial_tests) + 1,
        "fecha_inicio": datetime.now(),
        "preguntas": preguntas_seleccionadas,
        "respuestas": {},
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
    aprobado = puntaje_total >= 34  # 75% de 45 = 33.75, redondeamos a 34
    
    resultados = {
        "puntaje_total": puntaje_total,
        "total_preguntas": total_preguntas,
        "correctas": correctas,
        "incorrectas": incorrectas,
        "porcentaje": porcentaje,
        "aprobado": aprobado,
        "detalle": detalle
    }
    
    return resultados

# ============================================
# 4. FUNCIONES DE INTERFAZ
# ============================================

def mostrar_pregunta(pregunta, indice, test):
    """Muestra una pregunta según su tipo con validación"""
    st.markdown(f"### 📝 Pregunta {indice + 1} de 45")
    st.markdown(f"**Categoría:** {pregunta.get('seccion', 'General')}")
    st.write("")
    
    with st.container():
        st.markdown(f"**{pregunta['pregunta']}**")
        st.write("")
        
        if pregunta["tipo"] == "true_false":
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
            
            test["respuestas"][indice] = (respuesta == "Verdadero")
        
        elif pregunta["tipo"] == "opcion_multiple":
            opciones = pregunta["opciones"].copy()
            
            random.seed(pregunta["id_unico"])
            random.shuffle(opciones)
            random.seed()
            
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
            
            random.seed(pregunta["id_unico"])
            random.shuffle(todas_definiciones)
            random.seed()
            
            respuestas_unir = test["respuestas"].get(indice, {})
            if not isinstance(respuestas_unir, dict):
                respuestas_unir = {}
            
            for concepto in conceptos:
                st.markdown(f"**{concepto}**")
                
                definicion_correcta = pregunta["conceptos"][concepto]
                opciones_definiciones = [definicion_correcta]
                
                otras = [d for d in todas_definiciones if d != definicion_correcta]
                opciones_definiciones.extend(otras[:min(3, len(otras))])
                
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
    for i in range(45):
        col_index = i % 15
        with cols[col_index]:
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
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Puntaje", f"{resultados['puntaje_total']:.1f}/45")
    with col2:
        st.metric("Porcentaje", f"{resultados['porcentaje']:.1f}%")
    with col3:
        st.metric("✅ Correctas", resultados['correctas'])
    with col4:
        st.metric("❌ Incorrectas", resultados['incorrectas'])
    
    st.progress(resultados['porcentaje'] / 100)
    st.write("")
    
    if resultados['aprobado']:
        st.success("### ✅ ¡APROBADO! ¡Felicidades! 🎉")
        st.balloons()
    else:
        st.error(f"### ❌ NO APROBADO")
        st.info(f"Necesitas al menos 34 puntos (75%). Te faltaron {34 - resultados['puntaje_total']:.1f} puntos.")
    
    st.write("---")
    
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
RESULTADOS DEL TEST DE APLICACIONES SEGURAS
{linea}

Test N°: {test['id']}
Fecha: {test['fecha_finalizacion'].strftime('%d/%m/%Y %H:%M')}

RESUMEN GENERAL:
{linea}
Puntaje Total: {resultados['puntaje_total']:.1f}/45
Porcentaje: {resultados['porcentaje']:.1f}%
Estado: {'APROBADO ✅' if resultados['aprobado'] else 'NO APROBADO ❌'}

Preguntas Correctas: {resultados['correctas']}
Preguntas Incorrectas: {resultados['incorrectas']}
Total de Preguntas: {resultados['total_preguntas']}

{linea}
DETALLE DE PREGUNTAS:
{linea}
"""
    
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
        page_title="Simulador de Aplicaciones Seguras",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    inicializar_sesion()
    
    st.title("🔐 Simulador de Aplicaciones Seguras")
    st.markdown("*Preparación para exámenes de seguridad en desarrollo de aplicaciones*")
    st.write("")
    
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
        
        if st.session_state.historial_tests:
            st.subheader("📜 Historial")
            for test_hist in reversed(st.session_state.historial_tests[-5:]):
                if test_hist.get('completado'):
                    resultados = test_hist.get('detalle_resultados')
                    if resultados:
                        icono = "✅" if resultados['aprobado'] else "❌"
                        st.write(f"{icono} Test #{test_hist['id']}: {resultados['puntaje_total']:.1f}/45")
        
        st.write("---")
        
        with st.expander("ℹ️ Información", expanded=False):
            st.markdown("""
            **Características:**
            - 45 preguntas por test
            - Preguntas sin repetición
            - Puntaje mínimo: 34/45 (75%)
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
        st.write("Este simulador te ayudará a prepararte para exámenes de Aplicaciones Seguras con preguntas sobre seguridad en el desarrollo de software.")
        
        st.write("")
        st.markdown("### 📚 Temas Cubiertos:")
        
        temas = [
            "🔒 Principios de Seguridad",
            "🛡️ Vulnerabilidades Comunes",
            "🔐 Autenticación y Autorización",
            "💉 Inyección SQL y XSS",
            "🧪 Pruebas de Seguridad",
            "📊 Análisis de Código",
            "🔍 Gestión de Riesgos",
            "⚙️ Configuraciones Seguras"
        ]
        
        cols = st.columns(2)
        for i, tema in enumerate(temas):
            with cols[i % 2]:
                st.write(tema)
        
        st.write("")
        st.write("---")
        
        disponibles = len(obtener_preguntas_disponibles())
        
        if disponibles < 45:
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
        **Cómo funciona:**
        
        1️⃣ Cada test tiene **45 preguntas** aleatorias
        
        2️⃣ Las preguntas **no se repiten** entre tests
        
        3️⃣ Puntaje mínimo: **34/45** (75%)
        
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
            st.metric("🏆 Mejor Puntaje", f"{mejor_puntaje:.1f}/45")

def mostrar_pantalla_test():
    """Pantalla donde se realiza el test"""
    test = st.session_state.test_actual
    
    if not test:
        st.error("❌ Error: No hay test activo")
        st.session_state.estado = "inicio"
        st.rerun()
        return
    
    progreso = (test["indice_actual"] + 1) / 45
    st.progress(progreso)
    
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown(f"**Progreso:** {test['indice_actual'] + 1}/45 preguntas")
    with col2:
        respondidas = len(test["respuestas"])
        st.markdown(f"**Respondidas:** {respondidas}/45")
    with col3:
        faltantes = 45 - respondidas
        if faltantes > 0:
            st.markdown(f"**⚠️ Faltan:** {faltantes}")
        else:
            st.markdown(f"**✅ Todas respondidas**")
    
    st.write("")
    
    pregunta_actual = test["preguntas"][test["indice_actual"]]
    mostrar_pregunta(pregunta_actual, test["indice_actual"], test)
    
    st.write("")
    st.write("---")
    
    col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 2])
    
    with col1:
        if test["indice_actual"] > 0:
            if st.button("⬅️ Anterior", use_container_width=True):
                test["indice_actual"] -= 1
                st.rerun()
        else:
            st.button("⬅️ Anterior", disabled=True, use_container_width=True)
    
    with col2:
        if test["indice_actual"] < 44:
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
            test["indice_actual"] = 44
            st.rerun()
    
    with col5:
        todas_respondidas = len(test["respuestas"]) == 45
        
        if todas_respondidas:
            if st.button("✅ Finalizar Test", type="primary", use_container_width=True):
                finalizar_test(test)
        else:
            sin_responder = 45 - len(test["respuestas"])
            if st.button(f"⚠️ Finalizar ({sin_responder} sin responder)", type="secondary", use_container_width=True):
                if st.session_state.get('confirmar_finalizar', False):
                    finalizar_test(test)
                else:
                    st.session_state.confirmar_finalizar = True
                    st.warning(f"⚠️ Tienes {sin_responder} preguntas sin responder. Presiona nuevamente para confirmar.")
    
    mostrar_navegacion_preguntas(test)
    
    sin_responder = 45 - len(test["respuestas"])
    if sin_responder > 0:
        st.info(f"ℹ️ Tienes {sin_responder} pregunta(s) sin responder. Las preguntas sin respuesta contarán como incorrectas.")

def finalizar_test(test):
    """Finaliza el test y calcula los resultados"""
    test["completado"] = True
    test["fecha_finalizacion"] = datetime.now()
    
    resultados = calcular_resultados(test)
    
    test["puntaje"] = resultados["puntaje_total"]
    test["detalle_resultados"] = resultados
    
    st.session_state.historial_tests.append(test)
    
    st.session_state.estado = "resultados"
    if 'confirmar_finalizar' in st.session_state:
        del st.session_state.confirmar_finalizar
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
    
    mostrar_resultados(test, resultados)
    
    st.write("")
    st.write("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Realizar Otro Test", type="primary", use_container_width=True):
            st.session_state.test_actual = None
            st.session_state.estado = "inicio"
            if 'confirmar_finalizar' in st.session_state:
                del st.session_state.confirmar_finalizar
            st.rerun()
    
    with col2:
        if st.button("🏠 Volver al Inicio", use_container_width=True):
            st.session_state.test_actual = None
            st.session_state.estado = "inicio"
            if 'confirmar_finalizar' in st.session_state:
                del st.session_state.confirmar_finalizar
            st.rerun()

if __name__ == "__main__":
    main()
