
# ZADÁNÍ

Úkolem je vytvoření serveru v jazyce C/C++ komunikujícího prostřednictvím protokolu HTTP, který bude poskytovat různé informace o systému. Server bude naslouchat na zadaném portu a podle URL bude vracet požadované informace. Server musí správně zpracovávat hlavičky HTTP a vytvářet správné HTTP odpovědi. Typ odpovědi bude `text/plain`. Komunikace se serverem by měla být možná jak pomocí webového prohlížeče, tak nástroji typu `wget` a `curl`. Server musí být spustitelný v prostředí Linux Ubuntu 20.04 LTS (https://ubuntu.com/).

Server bude přeložitelný pomocí Makefile, který vytvoří spustitelný soubor `hinfosvc`. Tento server bude spustitelný s argumentem označujícím lokální port, na kterém bude naslouchat požadavkům:

```
./hinfosvc 12345
```

Server bude možné ukončit pomocí CTRL+C. Server bude umět zpracovat následující tři typy dotazů, které jsou na server zaslané příkazem GET:

1. **Získání doménového jména**

    Vrací síťové jméno počítače včetně domény, například:

    ```
    GET http://servername:12345/hostname
    ```

    Odpověď:
    ```
    merlin.fit.vutbr.cz
    ```

2. **Získání informací o CPU**

    Vrací informaci o procesoru, například:

    ```
    GET http://servername:12345/cpu-name
    ```

    Odpověď:
    ```
    Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz
    ```

3. **Aktuální zátěž**

    Vrací aktuální informace o zátěži. Tento vyžaduje výpočet z hodnot uvedených v souboru `/proc/stat`. Výsledek je například:

    ```
    GET http://servername:12345/load
    ```

    Odpověď:
    ```
    65%
    ```

Potřebné informace pro odpověď lze v systému získat pomocí některých příkazů systému (`uname`, `lscpu`) a/nebo ze souborů v adresáři `/proc`.

### IMPLEMENTACE

Implementace serveru bude v jazyce C/C++. Pro implementaci serveru je nutné využít knihovnu soketů. Není přípustné využívat knihovny pro zpracování HTTP a podobně - cílem je vytvořit lehký server, který má minimum závislostí.

### DOKUMENTACE

Součástí projektu bude dokumentace, kterou bude představovat soubor `Readme.md`, jenž bude obsahovat:
- Stručný popis projektu
- Způsob spuštění projektu
- Příklady použití projektu

### ODEVZDÁNÍ

Odevzdává se jeden soubor - archív pojmenovaný vaším loginem. Archiv může být typu ZIP případně GZIP, například:

```
xnovak00.zip
```

V archivu musí být kompletní zdrojové kódy, soubory `Makefile` a `Readme.md`.

### HODNOCENÍ

Hodnotí se funkčnost implementace (3/4 hodnocení) a její kvalita (1/4 hodnocení):
- Struktura projektu
- Srozumitelnost a jednoduchost kódu
- Dokumentace
- Množství závislostí na dalších knihovnách (rozumný balanc mezi tím, co si napsat sám a co použít z knihoven)
