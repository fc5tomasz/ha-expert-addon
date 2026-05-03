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

## Wersja

Aktualna wersja repo: `0.1.10`
