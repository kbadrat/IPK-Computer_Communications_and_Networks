# IPK - Projekt 1
**Author: Vladyslav Kovalets - xkoval21**

## Popis
Server v jazyce C/C++ komunikuje prostřednictvím protokolu HTTP a poskytuje různé informace o systému. Server naslouchá na zadaném portu a vrací požadované informace podle url. Zpracovává hlavičky HTTP a generuje správné HTTP odpovědi. Je spustitelný v prostředí Linux Ubuntu 20.04 LTS.

## Spuštění
Makefile vytvoří spustitelný soubor **hinfosvc**.

```./hinfosvc [port]```

## Použití
Komunikace se serverem je možná pomocí webového prohlížeče nebo nástrojů(wget, curl), který zvládá odesílat HTTP požadavky.

Formát požadavku : ```GET server:port/pozadavek```

Server může zpracovat čtyři typy požadavků.
| Požadavek   | Odpověď              		   | 
| ---------   | -------------------------------|
| `\hostname` | Doménové jméno                 |
| `\cpu-name` | Název procesoru                |
| `\load`     | Aktuální informace o procesoru |
| `\cokoliv`  | Špatný požadavek               |

## Funkce
- **int args_handler(int argc, char \*argv[])** 
- - Zkontroluje, zda byl program správně spuštěn a zda je zadán port
- **int server_go(int port, int listener)**     
- - Vytvoří a nakonfiguruje server
- **void requests_handler(int listener)**       
- - Zpracování požadavků
- **void about_hostname(int new_socket)**       
- - Zpracuje a odešle odpověď s názvem domény
- **void about_cpu(int new_socket)**            
- - Zpracuje a odešle odpověď o modelu procesoru.
- **void about_cpu_load(int new_socket)**       
- - Zpracuje a odešle odpověď o zatížení procesoru
- **char\* concat(char \*s1, char \*s2)**       
- - Zřetězení řetězců