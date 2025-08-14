# 🔐 OAuth2 Authorization Server + Resource Server + Client Application
**Este proyecto es una implementación práctica del flujo Authorization Code de OAuth 2.1 usando Spring Boot 3 y Spring Security, simulando un ecosistema de autenticación y autorización moderno.**.

Incluye tres aplicaciones principales:

## 📦 Estructura de Proyectos

| Proyecto | Descripción| Puerto por configurar |
|----------------------|--------------------------------------------|-------------------------------------------|
| `authorization-server`       | Servidor de Autorización que gestiona el inicio de sesión, emite tokens de acceso y refresh. Implementa el flujo OAuth 2.1 con Spring Authorization Server. | `9000`|
| `resource-server`  | API protegida que expone recursos (endpoints). Valida y procesa los tokens emitidos por el Authorization Server. | `9001`|
| `client-server`  | Aplicación cliente que interactúa con el usuario final. Inicia el flujo OAuth, redirige al login del Authorization Server y consume el Resource Server usando el token recibido. | `8081`|

## 🧠 ¿Qué es OAuth 2.1?

OAuth 2.1 es un marco de autorización estándar para delegar acceso seguro a recursos protegidos, sin necesidad de compartir credenciales directamente entre aplicaciones.

En este proyecto usamos el flujo Authorization Code, donde:

1. El usuario inicia sesión en el Authorization Server.
2. El Authorization Server devuelve un authorization code al Client.
3. El Client intercambia ese código por un Access Token (y opcionalmente un Refresh Token).
4. El Client usa el token para acceder a recursos protegidos en el Resource Server.

## 🔄 Flujo de Autenticación
<img width="998" height="629" alt="Captura de pantalla 2025-08-14 150755" src="https://github.com/user-attachments/assets/95196fec-6e0b-468b-9558-9d97c9c3fe47" />

## 🚀 Cómo levantar el proyecto
1️⃣ Variables de entorno necesarias

Cada servicio debe configurarse con variables de entorno. 
## 🧪 Prueba del flujo completo

1. Levantar los tres proyectos:

- authorization-server
- resource-server
- client-server

2. Acceder a la app cliente:
3. Autenticarse en el Authorization Server.
4. Visualizar los datos protegidos obtenidos desde el Resource Server usando el token.

## 📌 Buenas prácticas aplicadas

 Uso de Spring Authorization Server para OAuth 2.1.

- Separación clara de responsabilidades entre Auth Server, Resource Server y Client.
- Variables de entorno para configuración segura.
- Flujo Authorization Code con PKCE opcional.
- Validación de tokens en cada servicio protegido.
