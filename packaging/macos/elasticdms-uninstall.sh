#!/usr/bin/env bash
#
# elasticdms-uninstall.sh — nimmt den Ordnerclient wieder von diesem Mac herunter.
#
# DER GRUND, warum es dieses Skript gibt: Der macOS-Installer kennt keine Deinstallation, und
# Intune bietet fuer den Apptyp „macOS app (PKG)" ausdruecklich keine Uninstall-Zuweisung. Ohne
# ein mitgeliefertes Skript bliebe auf jedem Geraet Rueckstand — die File-Provider-Domaene samt
# Eintrag in der Finder-Seitenleiste, das Anmeldeobjekt in /Library/LaunchAgents, der Ordner
# ~/Library/Application Support/de.elasticdms.folderclient mit der Rendezvous-Datei und die
# Schluesselbundeintraege unter dem Dienst de.elasticdms.folderclient. Bei einem Archiv, das
# GoBD- und DSGVO-Argumente traegt, ist liegengebliebenes Geraetegeheimnis keine Kleinigkeit.
#
# Dieses Skript reist im Buendel mit und liegt nach der Installation unter
# /Applications/elasticdms.app/Contents/Resources/elasticdms-uninstall.sh — dort, wo es noch da
# ist, wenn man es braucht.
#
# Aufrufe:
#   elasticdms-uninstall.sh remove   # raeumt ab (fragt vor den Daten des Nutzers nach)
#   elasticdms-uninstall.sh verify     # zeigt nur, was noch da ist; aendert nichts
#   elasticdms-uninstall.sh help
#
# Umgebungsvariablen:
#   OHNE_RUECKFRAGE=ja   Beantwortet jede Rueckfrage mit „ja" — fuer MDM-Skripte, die keinen
#                        Bildschirm haben. Ohne Bildschirm und ohne diese Variable bleiben die
#                        Daten des Nutzers stehen; stilles Loeschen ist keine Vorgabe.
#
# ALS WER: als der angemeldete Nutzer, NICHT als root. Die File-Provider-Domaene gehoert dem
# Nutzer, nicht dem System; aus einem als root laufenden Installerskript ist sie unerreichbar.
# Fuer /Applications und /Library/LaunchAgents fragt das Skript einzeln per sudo nach.

set -euo pipefail

APP="/Applications/elasticdms.app"
LOGIN_ITEM="/Library/LaunchAgents/de.elasticdms.folderclient.plist"
LABEL="de.elasticdms.folderclient"
# Der Dienstname des Schluesselbunds steht in crates/app/src/vault.rs als SERVICE; er ist
# derselbe wie die Buendelkennung.
SERVICE="de.elasticdms.folderclient"
DATA_DIR="$HOME/Library/Application Support/de.elasticdms.folderclient"
# Die Domaenen erscheinen als ~/Library/CloudStorage/elasticdms-<Anzeigename>
# (crates/fileprovider/src/domain.rs).
CLOUD_PATTERN="$HOME/Library/CloudStorage/elasticdms-"
RECEIPTS=(de.elasticdms.folderclient.app de.elasticdms.folderclient.loginitem)

report() { printf '\033[1m==> %s\033[0m\n' "$*"; }
hint() { printf '    %s\n' "$*"; }
error() {
	printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2
	exit 1
}

# ── Handreichungen ───────────────────────────────────────────────────────────

verify_environment() {
	[ "$(uname -s)" = "Darwin" ] ||
		error "elasticdms-uninstall.sh läuft nur auf macOS (hier: $(uname -s))."
	# Als root waere Schritt 1 nicht auszufuehren: `NSFileProviderManager` kennt nur die Domaenen
	# des aufrufenden Nutzers, und $HOME zeigte auf /var/root. Das Skript raeumte dann die
	# falschen Ordner ab und liesse die richtigen stehen.
	[ "$(id -u)" != "0" ] ||
		error "Bitte als angemeldeter Nutzer starten, nicht mit sudo: die File-Provider-Domäne gehört dem Nutzer, und als root zeigt \$HOME auf /var/root."
}

# Eine Rueckfrage, deren Vorgabe „nein" ist. Ohne Bildschirm (MDM, CI) gilt OHNE_RUECKFRAGE.
ask() {
	local text="$1" response
	if [ "${OHNE_RUECKFRAGE:-}" = "ja" ]; then
		hint "$text — ja (OHNE_RUECKFRAGE)"
		return 0
	fi
	if [ ! -t 0 ]; then
		hint "$text — nein (kein Bildschirm; OHNE_RUECKFRAGE=ja erzwänge ja)"
		return 1
	fi
	read -r -p "    $text [j/N] " response || response=""
	case "$response" in
	j | J | yes | Ja | JA) return 0 ;;
	*) return 1 ;;
	esac
}

# Fuehrt einen Befehl mit Root-Rechten aus — nur fuer die drei Stellen ausserhalb des
# Heimverzeichnisses. Alles andere laeuft mit den Rechten des Nutzers.
as_root() {
	if [ "$(id -u)" = "0" ]; then
		"$@"
	else
		sudo "$@"
	fi
}

# Listet die Ordner, die eine noch bestehende Domaene hinterlaesst.
cloud_folder() {
	/bin/ls -d "$CLOUD_PATTERN"* 2>/dev/null || true
}

# ── Aufgaben ─────────────────────────────────────────────────────────────────

task_help() {
	awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${BASH_SOURCE[0]}"
}

# Zeigt den Stand, ohne etwas zu aendern — der ehrliche Abschluss jeder Deinstallation und
# zugleich das, was man vorher wissen will.
task_verify() {
	verify_environment
	local rest=0
	report "Was von elasticdms noch auf diesem Mac liegt"

	if [ -d "$APP" ]; then
		hint "Programm:          $APP"
		rest=1
	else
		hint "Programm:          entfernt"
	fi

	if [ -f "$LOGIN_ITEM" ]; then
		hint "Anmeldeobjekt:     $LOGIN_ITEM"
		rest=1
	else
		hint "Anmeldeobjekt:     entfernt"
	fi

	if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
		hint "launchd:           gui/$(id -u)/$LABEL ist noch geladen"
		rest=1
	else
		hint "launchd:           nicht geladen"
	fi

	local folder
	folder="$(cloud_folder)"
	if [ -n "$folder" ]; then
		printf '    Domänen:           %s\n' "$folder"
		rest=1
	else
		hint "Domänen:           keine unter ~/Library/CloudStorage"
	fi

	if [ -d "$DATA_DIR" ]; then
		hint "Daten:             $DATA_DIR"
		rest=1
	else
		hint "Daten:             entfernt"
	fi

	local key
	key="$(count_keychain_items)"
	if [ "$key" != "0" ]; then
		hint "Schlüsselbund:     Einträge unter dem Dienst $SERVICE vorhanden"
		rest=1
	else
		hint "Schlüsselbund:     keine Einträge unter dem Dienst $SERVICE"
	fi

	local acknowledgement
	for acknowledgement in "${RECEIPTS[@]}"; do
		if pkgutil --pkg-info "$acknowledgement" >/dev/null 2>&1; then
			hint "Paketquittung:     $acknowledgement"
			rest=1
		fi
	done

	[ "$rest" = "0" ] && report "Nichts mehr da." || true
	return 0
}

# 1 oder 0 — ob der Schluesselbund noch einen Eintrag unter dem Dienst fuehrt. `security` fragt
# dabei nicht nach dem Kennwort, solange nur gelesen wird.
count_keychain_items() {
	if security find-generic-password -s "$SERVICE" >/dev/null 2>&1; then
		printf '1'
	else
		printf '0'
	fi
}

task_remove() {
	verify_environment

	# ── 1. Die Domaene zuerst ────────────────────────────────────────────────
	# Vor allem anderen, und nur hier geht die Reihenfolge nicht anders herum: nach `rm -rf` der
	# App gibt es keinen Anbieter mehr, und die Domaene bliebe samt Seitenleisteneintrag stehen.
	# Eine spaetere Neuinstallation traefe dann auf eine Domaene ohne Anbieter.
	report "Schritt 1 von 6: die File-Provider-Domäne"
	local folder
	folder="$(cloud_folder)"
	if [ -z "$folder" ]; then
		hint "Keine Domäne unter ~/Library/CloudStorage — nichts zu tun."
	else
		printf '    Es besteht noch mindestens eine Domäne:\n%s\n' "$folder"
		cat <<-'END'

		    Diesen einen Schritt kann das Skript nicht tun. Eine Domäne entfernt nur der
		    Anbieter selbst über NSFileProviderManager, im Kontext des angemeldeten Nutzers;
		    ein Befehlszeilenwerkzeug dafür gibt es nicht (fileproviderctl kennt kein
		    „domain remove“). Der Weg ist:

		        elasticdms starten → Menüleistensymbol → „Abmelden“

		    Das ruft MacFileSystem::clear_everything auf und entfernt jede elasticdms-Domäne mit
		    NSFileProviderDomainRemovalModeRemoveAll, also samt aller lokalen Kopien.

		END
		if ! ask "Trotzdem weitermachen und die Domäne stehen lassen?"; then
			error "Abgebrochen. Bitte zuerst in elasticdms „Abmelden“ wählen und dann erneut starten."
		fi
	fi

	# ── 2. Das laufende Programm ─────────────────────────────────────────────
	report "Schritt 2 von 6: das laufende Programm beenden"
	if pgrep -x elasticdms >/dev/null 2>&1; then
		# Kein -9: die App raeumt beim Beenden ihre Einzelinstanzsperre ab.
		pkill -x elasticdms || true
		hint "beendet"
	else
		hint "läuft nicht"
	fi

	# ── 3. Das Anmeldeobjekt ─────────────────────────────────────────────────
	report "Schritt 3 von 6: das Anmeldeobjekt"
	# `bootout` auch dann, wenn die Plist schon weg ist: launchd haelt den Dienst sonst bis zur
	# naechsten Anmeldung weiter.
	if launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null; then
		hint "gui/$(id -u)/$LABEL entladen"
	else
		hint "war nicht geladen"
	fi
	if [ -f "$LOGIN_ITEM" ]; then
		as_root rm -f "$LOGIN_ITEM"
		hint "$LOGIN_ITEM gelöscht"
	fi
	# Eine Kopie im Heimverzeichnis legt dieses Paket nie an; sie kann aber von einem Handversuch
	# stammen und ueberlebte sonst jede Deinstallation.
	if [ -f "$HOME/Library/LaunchAgents/$LABEL.plist" ]; then
		rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
		hint "~/Library/LaunchAgents/$LABEL.plist gelöscht"
	fi

	# ── 4. Das Programm ──────────────────────────────────────────────────────
	report "Schritt 4 von 6: das Programm"
	if [ -d "$APP" ]; then
		as_root rm -rf "$APP"
		hint "$APP gelöscht"
	else
		hint "war nicht installiert"
	fi
	local acknowledgement
	for acknowledgement in "${RECEIPTS[@]}"; do
		if pkgutil --pkg-info "$acknowledgement" >/dev/null 2>&1; then
			as_root pkgutil --forget "$acknowledgement" >/dev/null
			hint "Paketquittung $acknowledgement vergessen"
		fi
	done

	# ── 5. Die Daten des Nutzers ─────────────────────────────────────────────
	report "Schritt 5 von 6: die Daten dieses Nutzers"
	if [ -d "$DATA_DIR" ]; then
		if ask "$DATA_DIR löschen (enthält den lokalen Zustand und bridge.json)?"; then
			rm -rf "$DATA_DIR"
			hint "gelöscht"
		else
			hint "bleibt stehen"
		fi
	else
		hint "kein Datenordner vorhanden"
	fi

	# ── 6. Der Schluesselbund ────────────────────────────────────────────────
	# Hier liegt der Geraeteschluessel (ADR-D03). Wer ihn stehen laesst, laesst ein
	# Anmeldegeheimnis auf einem Geraet zurueck, das den Client nicht mehr hat.
	report "Schritt 6 von 6: der Schlüsselbund (Dienst $SERVICE)"
	if [ "$(count_keychain_items)" = "0" ]; then
		hint "keine Einträge"
	elif ask "Alle Einträge unter dem Dienst $SERVICE löschen (enthält den Geräteschlüssel)?"; then
		local count=0
		# `delete-generic-password` loescht je Aufruf einen Eintrag; die Schranke verhindert eine
		# Endlosschleife, falls `security` eines Tages 0 zurueckgibt, ohne etwas zu loeschen.
		while [ "$count" -lt 100 ] && security delete-generic-password -s "$SERVICE" >/dev/null 2>&1; do
			count=$((count + 1))
		done
		hint "$count Eintrag/Einträge gelöscht"
	else
		hint "bleiben stehen"
	fi

	printf '\n'
	task_verify
	cat <<-'END'

	    Falls in „Systemeinstellungen → Allgemein → Anmeldeobjekte und Erweiterungen“ noch ein
	    Eintrag „elasticdms“ hängt, obwohl hier alles entfernt ist: das ist die
	    Background-Task-Management-Datenbank von macOS. Sie lässt sich nur ganz zurücksetzen —
	    `sudo sfltool resetbtm`, danach neu anmelden. Das betrifft auch die Anmeldeobjekte
	    aller anderen Programme; deshalb steht es hier als letztes Mittel und nicht im Ablauf.
	END
}

# ── Verteiler ────────────────────────────────────────────────────────────────

main() {
	local task="${1:-help}"
	if ! declare -F "task_$task" >/dev/null; then
		printf 'Unbekannte Aufgabe „%s“.\n\n' "$task" >&2
		task_help >&2
		exit 2
	fi
	"task_$task"
}

main "$@"
