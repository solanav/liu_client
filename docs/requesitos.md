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
2. Al reiniciarse el ordenador, el programa debe volver a ejecutarse.
3. Strings usadas en el programa tienen que estar ofuscadas.
4. Capacidad para crear y ejecutar plugins.
5. Instalacion silenciosa y semi-aleatoria.
6. Extremadamente resistente a fallos tanto externos como internos.
7. Debe instalar el watchdog
8. Debe recopilar informacion sobre el ordenador en que se ha instalado. Esto es: sistema operativo, version, version de un programa aleatorio, usuarios, localizacion, hora local, lista de programas, usuario conectado o desconectado, etc. Tambien es muy importante que el programa sea capaz de escanear la red y recopilar toda la informacion posible sobre los ordenadores conectados. 
9. Debe poder encriptar y enviar esta informacion al servidor mediante http (preferiblemente con SSL).
10. Debe poder permitir la apertura de una conexion ssh inversa.
11. Debe permitir la desinstalacion completa o parcial (dejando el watchdog).
12. Se deben poder descargar archivos aleatorios del servidor. La subida de archivos debe estar restringida a logs (puntos 7 y 8).

# 3. Watchdog

1. Todo lo ligero que se pueda
2. Al reiniciarse el ordenador, el programa debe volver a ejecutarse. Para evitar problemas, el watchdog debe esperar un rato despues de ser iniciado para darle tiempo al programa principal para que se inicie.
3. Se tiene que poder quedar en modo de espera. Dejara de ejecutar todas sus funciones principales. Solo podra escuchar instrucciones del servidor.
4. Debe poder instalarse en multiples localizaciones, randomizadas.
5. Se debe poder inyectar en otros programas.
6. Debe comprobar cada poco tiempo si el programa principal esta funcionando.
7. En caso de fallo en el programa principal, lo volvera a ejecutar y encaso de varios fallos seguidos, informara al servidor y quedara en modo de espera.
8. Debe tener la capacidad de reinstalarse en lugares al azar cada cierto tiempo.
9. Debe poder hacer modificaciones muy simples del ejecutable del programa principal para cambiar su hash.

# Especificaciones y otras anotaciones

Para networking, el programa descargador usara curl principalmente, aunque si no esta disponible se puede usar wget u otras alternativas. El programa principal debe usar libcurl para comunicarse con el servidor.

El protocolo de comunicacion servidor-cliente debe ser https. En la primera iteracion podemos usar http para simplificar y hacer debug.

La ip del servidor debe estar ofuscada, al igual que el resto de strings que puedan identificar al programa. Esto se puede hacer mediante macros en C y aunque no es muy efectivo, defiende al programa de una linea de ataque muy simple.

Muchas partes del codigo se pueden extraer y reutilizar del codigo de Yao, esto incluye minimo la instalacion del programa y la comunicacion con el servidor.

No nos podemos permitir perder absolutamente nada de memoria. Este programa va a estar en ejecucion durante periodos muy largos de tiempo y no debe llamar la atencion ni en uso de CPU ni en uso de RAM.

# Partes del programa principal

Será necesario un modulo que funcione como una base de datos que posea varios elementos con su respectiva informacion. Podemos hacer que una primera versión solo permina x cantidad de elementos conectados simultaneamente y mediante un pago se amplie o sea ilimitada. Esta base de datos poseerá los datos de todos los usuarios y se encontrará en el servidor principal. Cuando un usuario quiera añadir un dispositivo nuevo se comprueba primero si está en la base de datos y si no está se añade. Este modulo debería encontrarse en el servidor y podemos hacer una versión más sencilla para el uso del usuario.

Los elementos se clasificaran segun sus características tales como su sistema operativo, el tipo de elemento, su direccion, forma de conexión (inalambrica, cable...), si se puede controlar o solo monitorizar, su usuario.

Los usuarios deberán tener un nombre de usuario unico,una contraseña ,un id unico, una lista de los elementos que tiene actualmente conectados, y su ordenador o dispositivo principal. Todos los dispositivos que conecte serán almacenados en la base de datos principal y aunque los desconecte su información más reciente se encontrará ahí. Si los vuelve a conectar se actualizará la base de datos y si es nuevo se añadirá a la base de datos.

El modulo principal se ejecutará en cada ordenador, de modo que permitirá al usuario acceder a toda la informacion de la base de datos que le corresponda (o queramos mostrarle). Supongamos que primero requiere de autentificación y tras eso siempre funciona igual.


