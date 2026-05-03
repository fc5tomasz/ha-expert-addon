# HA Expert

`HA Expert` to dodatek Home Assistant do bezpiecznego zdalnego wsparcia i konfiguracji.

## Co robi

- klient wpisuje tylko:
  - `client_login`
  - `ha_token`
- w panelu dodatku klika `Połącz z ekspertem`
- dodatek zestawia prywatne połączenie, zgłasza się do operatora i pozwala operatorowi:
  - zobaczyć status klienta
  - zobaczyć adres HA i port
  - pobrać log Home Assistant przez samo urządzenie
  - uruchamiać bezpieczne operacje runtime przez `hx`

## Runtime HA Expert

Wersja `0.2.0` zachowuje dotychczasowy model połączenia i dodaje runtime po stronie HA klienta:

- `client_login` identyfikuje klienta i jest wysyłany do operatora
- `ha_token` jest używany lokalnie przez add-on do API Home Assistant
- add-on nadal zestawia Tailscale i heartbeat do operatora tak jak wcześniej
- nazwa, slug i panel dodatku pozostają bez zmian:
  - `HA Expert`
  - `ha_expert`
  - panel `HA Expert`
- runtime obsługuje diagnostykę, logi, historię, logbook, YAML automatyzacji/skryptów, dry-run, backup, rollback i `core-check`
- realne zmiany YAML wymagają jawnego potwierdzenia po stronie operatora

## Instalacja

1. Dodaj repozytorium `HA Expert` do sklepu dodatków Home Assistant.
2. Zainstaluj dodatek `HA Expert`.
3. W konfiguracji dodatku wpisz:
   - `client_login`
   - `ha_token`
4. Uruchom dodatek.
5. Otwórz panel `HA Expert` i kliknij `Połącz z ekspertem`.

## Uwagi

- Dodatek korzysta z Tailscale w tle i nie wymaga ręcznej konfiguracji VPN po stronie klienta.
- Panel klienta pokazuje tylko stan połączenia i przycisk `Połącz z ekspertem` / `Rozłącz`.
- Narzędzie jest niezależne od starszego `Ha-expert-Client`.
- Operacje eksperckie są sterowane po stronie operatora przez `hx`, panel klienta pozostaje prosty.

## Testy

Lekkie testy bezpieczeństwa runtime można uruchomić bez Home Assistant:

```bash
python3 -m unittest discover -s tests -v
```

## Wersja

Aktualna wersja repo: `0.2.0`
