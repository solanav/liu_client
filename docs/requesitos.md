# Resumen
El programa debe separarse en tres partes.
1. El descargador
2. El programa principal con toda la funcionalidad
3. El watchdog, que observa que el programa principal funciona y en caso contrario lo repara y/o reinstala.

# 1. Descargador

La unica funcion de este programa es descargar y ejecutar el programa principal, que se encargara de instalarse a si mismo y al watchdog.

Como requerimiento, el descargador debe tener una version en bash y una en C como minimo. Se pueden considerar otras versiones en Python, LUA y otros lenguajes simples. Cada uno de estos no deberia constar de mas de 10 lineas de codigo.

# 2. Programa principal

1. Peso del ejecutable todo lo ligero que se pueda.
2. Strings usadas en el programa tienen que estar ofuscadas.
3. Capacidad para crear y ejecutar plugins.
4. Instalacion silenciosa y semi-aleatoria.
5. Extremadamente resistente a fallos tanto externos como internos.
6. Debe instalar el watchdog
7. Debe recopilar informacion sobre el ordenador en que se ha instalado. Esto es: sistema operativo, version, version de un programa aleatorio, usuarios, localizacion, hora local, lista de programas, usuario conectado o desconectado, etc. Tambien es muy importante que el programa sea capaz de escanear la red y recopilar toda la informacion posible sobre los ordenadores conectados. 
8. Debe poder encriptar y enviar esta informacion al servidor mediante http (preferiblemente con SSL).
9. Debe poder permitir la apertura de una conexion ssh inversa.
10. Debe permitir la desinstalacion completa o parcial (dejando el watchdog).
11. Se deben poder descargar archivos aleatorios del servidor. La subida de archivos debe estar restringida a logs (puntos 7 y 8).

# 3. Watchdog

1. Todo lo ligero que se pueda
2. Se tiene que poder quedar en modo de espera. Dejara de ejecutar todas sus funciones principales. Solo podra escuchar instrucciones del servidor.
3. Debe poder instalarse en multiples localizaciones, randomizadas.
4. Se debe poder inyectar en otros programas.
5. Debe comprobar cada poco tiempo si el programa principal esta funcionando.
6. En caso de fallo en el programa principal, lo volvera a ejecutar y encaso de varios fallos seguidos, informara al servidor y quedara en modo de espera.
7. Debe tener la capacidad de reinstalarse en lugares al azar cada cierto tiempo.
8. Debe poder hacer modificaciones muy simples del ejecutable del programa principal para cambiar su hash.