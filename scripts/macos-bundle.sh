#!/usr/bin/env bash
#
# macos-bundle.sh — builds elasticdms.app together with the file provider extension inside it.
#
# THE REASON this script exists: a File Provider extension only runs out of a signed .app bundle.
# `cargo build` delivers two loose programs, and macOS never looks at loose programs. Everything
# between those two programs and a folder in Finder — the bundle layout, two Info.plists, the
# entitlements, and the signature in the right order — has to be exactly right, and when it is not,
# nobody says a word: the system discards the extension silently, the folder stays empty, and
# `NSFileProviderManager.addDomain` reports at most a meaningless -2001 (measured, ADR-D05). That
# knowledge stands here as a script, not in somebody's head.
#
# Calls:
#   scripts/macos-bundle.sh build      # compile, bundle, sign, check
#   scripts/macos-bundle.sh verify     # only the checks, on a finished bundle
#   scripts/macos-bundle.sh install    # copies to ~/Applications (changes the system!)
#   scripts/macos-bundle.sh help
#
# Environment variables:
#   PROFILE=debug|release       Which cargo profile is bundled (default: debug).
#   SIGNING_IDENTITY=…          Signing identity; default "-" (ad hoc). With a real Developer ID
#                               identity the hardened runtime comes on top, without which no
#                               notarisation passes.
#   BINARY_DIR=…                Where the two programs come from, and with them the iconset that
#                               crates/app/build.rs writes beside them; default target/<PROFILE>.
#                               scripts/macos-package.sh sets target/universal here, because a
#                               delivery bundle carries universal programs, and `lipo` has to run
#                               before `codesign` — afterwards it would cut the signature apart.
#                               It copies the iconset there as well; a picture has no architecture.
#   BUNDLE_DIR=…                Where the bundle arises or lies; default target/bundle. That lets
#                               macos-package.sh check the same rules against the unpacked package
#                               payload instead of against a second, transcribed list.
#
# Two things this script explicitly does NOT do:
#   * `codesign --deep`. That switch signs nested parts with the entitlements of the outer bundle —
#     the extension would extend its sandbox or lose it entirely. Apple has advised against it for
#     years. Here the signing goes from the inside out, every bundle with its own entitlements.
#   * Install. `build` touches nothing outside target/.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES="$ROOT/packaging/macos"
PROFILE="${PROFILE:-debug}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"

OUTPUT_DIR="${BUNDLE_DIR:-$ROOT/target/bundle}"
APP="$OUTPUT_DIR/elasticdms.app"
APPEX="$APP/Contents/PlugIns/elasticdms-fileprovider.appex"

# The uninstall script travels inside the bundle, under Contents/Resources. The reason is the order
# when removing: the File Provider domain belongs to the signed-in user, and whoever deletes
# /Applications/elasticdms.app first has no provider left — the domain would stay standing in the
# sidebar as a corpse. So the script has to be where it is still present when it is needed: next to
# the program it clears away.
UNINSTALL_SCRIPT="elasticdms-uninstall.sh"

# The icon. It is NOT a file in the repository: crates/app/build.rs draws the ten images out of
# crates/app/src/icon.rs — the same code the menu bar icon comes from — and puts them beside the
# built program as elasticdms.iconset. Here `iconutil` makes the container out of them that Finder
# reads. The name has to be the one CFBundleIconFile in packaging/macos/elasticdms-Info.plist
# names; `verify_app_plist` holds the two together.
ICONSET="elasticdms.iconset"
ICON_FILE="elasticdms.icns"

APP_BINARY="elasticdms"
APPEX_BINARY="elasticdms-fileprovider"

# Has to agree with NSExtensionPrincipalClass in the extension's Info.plist; `task_verify` holds
# both against the source.
EXTENSION_SOURCE="$ROOT/crates/fileprovider/src/extension.rs"

report() { printf '\033[1m==> %s\033[0m\n' "$*"; }
error() {
	printf '\033[1;31mError:\033[0m %s\n' "$*" >&2
	exit 1
}

# ── Helpers ──────────────────────────────────────────────────────────────────

# The script builds a macOS bundle; on any other system it would produce nonsense instead of
# keeping quiet.
verify_environment() {
	[ "$(uname -s)" = "Darwin" ] || error "macos-bundle.sh only runs on macOS (here: $(uname -s))."
	command -v codesign >/dev/null || error "codesign is missing; please install the Xcode command line tools."
	command -v plutil >/dev/null || error "plutil is missing; please install the Xcode command line tools."
	verify_profile
}

# Checks PROFILE once and sets the switch for cargo.
#
# Here and not in a substitution `$(…)`: there `error` would run in a subshell whose `exit` ends
# only the subshell — the script would then silently go on building the default profile. Exactly
# the kind of function that silently does the wrong thing.
PROFILE_FLAG=""
verify_profile() {
	case "$PROFILE" in
	debug) PROFILE_FLAG="" ;;
	release) PROFILE_FLAG="--release" ;;
	*) error "PROFILE is “${PROFILE}”; allowed are “debug” and “release”." ;;
	esac
}

# The version has its only truth in Cargo.toml; the plists carry @VERSION@.
version() {
	sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1
}

# Writes a template with the version substituted to its place in the bundle.
set_plist() {
	local template="$1" target="$2"
	[ -f "$template" ] || error "The template $template is missing."
	sed "s/@VERSION@/$(version)/g" "$template" >"$target"
}

# ── Tasks ────────────────────────────────────────────────────────────────────

# The head of this file from line 3 to the first line that is not a comment — that way the help
# does not slip when the head grows.
task_help() {
	awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${BASH_SOURCE[0]}"
}

task_compile() {
	verify_environment
	report "Compiling elasticdms and the extension ($PROFILE)"
	# Two separate calls, because only the extension's program gets the entry point
	# _NSExtensionMain (crates/fileprovider/build.rs).
	# shellcheck disable=SC2086 # empty means "no switch", not "an empty argument"
	(cd "$ROOT" && cargo build $PROFILE_FLAG -p elasticdms --bin "$APP_BINARY")
	# shellcheck disable=SC2086
	(cd "$ROOT" && cargo build $PROFILE_FLAG -p edms-fileprovider --bin "$APPEX_BINARY")
}

task_bundle() {
	verify_environment
	local from="${BINARY_DIR:-$ROOT/target/$PROFILE}"
	[ -x "$from/$APP_BINARY" ] || error "$from/$APP_BINARY is missing; run “compile” first."
	[ -x "$from/$APPEX_BINARY" ] || error "$from/$APPEX_BINARY is missing; run “compile” first."

	report "Building $APP"
	# Fresh, never on top: an old signature or an old plist in the bundle is worse than none at all
	# — it looks valid and is not.
	rm -rf "$APP"
	mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APPEX/Contents/MacOS"

	cp "$from/$APP_BINARY" "$APP/Contents/MacOS/$APP_BINARY"
	cp "$from/$APPEX_BINARY" "$APPEX/Contents/MacOS/$APPEX_BINARY"
	set_plist "$TEMPLATES/elasticdms-Info.plist" "$APP/Contents/Info.plist"
	set_plist "$TEMPLATES/elasticdms-fileprovider-Info.plist" "$APPEX/Contents/Info.plist"

	build_icon "$from"

	# Before signing: whatever falls into the bundle after signing invalidates the seal.
	[ -f "$TEMPLATES/$UNINSTALL_SCRIPT" ] || error "$TEMPLATES/$UNINSTALL_SCRIPT is missing."
	install -m 755 "$TEMPLATES/$UNINSTALL_SCRIPT" "$APP/Contents/Resources/$UNINSTALL_SCRIPT"
}

# Makes Contents/Resources/elasticdms.icns out of the iconset that lies beside the program.
#
# WHY iconutil AND NOT A FILE WRITTEN BY THE BUILD SCRIPT: the .icns is a container of its own, and
# the only reader whose judgement counts here is macOS. `iconutil` is that reader's own tool — it
# is on every Mac, it refuses a folder whose names or sizes do not fit, and it writes exactly what
# Finder and Installer read. A container assembled in Rust would look right in a hex dump and would
# be judged for the first time at the customer's.
#
# A MISSING ICONSET IS AN ERROR AND NOT A WARNING: a bundle with no icon looks finished. It
# installs, it runs, and only the blank sheet in Finder says that something went wrong — and that
# is seen once the package is out.
build_icon() {
	local from="$1/$ICONSET"
	command -v iconutil >/dev/null || error "iconutil is missing; it comes with macOS and with the Xcode command line tools."
	[ -d "$from" ] || error "$from is missing. crates/app/build.rs draws it next to the program; compile first (“compile”), and if the iconset does not appear, touch crates/app/src/icon.rs so that cargo runs the build script again."
	iconutil --convert icns --output "$APP/Contents/Resources/$ICON_FILE" "$from"
}

task_sign() {
	verify_environment
	[ -d "$APPEX" ] || error "$APPEX is missing; run “bundle” first."
	local flags=(--force --sign "$SIGNING_IDENTITY")
	if [ "$SIGNING_IDENTITY" = "-" ]; then
		report "Signing ad hoc (development; ADR-D05: no paid account is enough for more)"
	else
		# Without the hardened runtime the notarisation refuses; ad hoc, by contrast, would sit
		# badly with the just-in-time parts of the user interface.
		report "Signing with “${SIGNING_IDENTITY}” and the hardened runtime"
		flags+=(--options runtime --timestamp)
	fi

	# From the inside out. If the app is signed first, the extension's signature invalidates it
	# again right away — the app's seal covers its whole content.
	codesign "${flags[@]}" --entitlements "$TEMPLATES/elasticdms-fileprovider.entitlements" "$APPEX"
	# The app gets NO entitlements file: it is not sandboxed and needs no exception (ADR-D05,
	# measurement 2). An empty file would not be "nothing" but a sandbox without any exception —
	# the app could then neither listen nor write.
	codesign "${flags[@]}" "$APP"
}

task_verify() {
	verify_environment
	[ -d "$APPEX" ] || error "$APPEX is missing; run “build” first."

	report "Checking the two Info.plists"
	plutil -lint "$APP/Contents/Info.plist"
	plutil -lint "$APPEX/Contents/Info.plist"
	verify_app_plist
	verify_plist_key

	report "Checking the signatures (every bundle on its own, never --deep)"
	codesign --verify --strict --verbose=2 "$APPEX"
	codesign --verify --strict --verbose=2 "$APP"
	verify_entitlements

	report "Checking the extension's entry point"
	verify_entry_point

	# A bundle without its uninstall script would run, but would leave the domain, the login item
	# and keychain entries behind on every device — no small thing when arguing DSGVO
	# (packaging/macos/README.md, section “Uninstalling”).
	[ -x "$APP/Contents/Resources/$UNINSTALL_SCRIPT" ] ||
		error "Contents/Resources/$UNINSTALL_SCRIPT is missing from the bundle or is not executable."

	report "Bundle in order: $APP"
}

# What the app has to tell the system about itself (ADR-D05, ADR-D07).
verify_app_plist() {
	local plist="$APP/Contents/Info.plist"
	read_app() { /usr/libexec/PlistBuddy -c "Print $1" "$plist" 2>/dev/null || true; }

	[ "$(read_app :CFBundleIdentifier)" = "de.elasticdms.folderclient" ] ||
		error "The app's CFBundleIdentifier is not de.elasticdms.folderclient."
	[ "$(read_app :CFBundlePackageType)" = "APPL" ] ||
		error "The app's CFBundlePackageType is not APPL."
	# Without LSUIElement elasticdms would stand in the Dock and in the app switcher, although it
	# has nothing to show but the usage log — and whoever quits the Dock icon switches the folder
	# off without noticing (ADR-D07).
	[ "$(read_app :LSUIElement)" = "true" ] || error "LSUIElement is missing from the app's Info.plist."
	# contentPolicy only exists from macOS 13; below that the rule "discard on a new version
	# instead of reloading" would silently come to nothing (ADR-D05).
	[ "$(read_app :LSMinimumSystemVersion)" = "13.0" ] ||
		error "The app's LSMinimumSystemVersion is not 13.0."

	# The icon is the one thing here that is only ever seen and never reported: a bundle whose
	# CFBundleIconFile names a file that is not there shows the blank sheet — no error, no log line,
	# nothing but a picture nobody looks at twice. So both halves are measured, the name in the
	# plist and the file in Resources, and they have to be the same one.
	local named
	named="$(read_app :CFBundleIconFile)"
	[ "$named" = "$ICON_FILE" ] ||
		error "CFBundleIconFile is “${named}”, expected was “${ICON_FILE}”."
	[ -s "$APP/Contents/Resources/$named" ] ||
		error "Contents/Resources/$named is missing from the bundle or is empty, although the Info.plist names it."
}


# What the system silently discards if it is not right (ADR-D05).
verify_plist_key() {
	local plist="$APPEX/Contents/Info.plist"
	read() { /usr/libexec/PlistBuddy -c "Print $1" "$plist" 2>/dev/null || true; }

	[ "$(read :CFBundlePackageType)" = "XPC!" ] || error "The extension's CFBundlePackageType is not XPC!."
	# The identifier has to lie below the app's, or the system does not count the extension as part
	# of it. English since 2026-09-13, together with the app's (ADR-D10, correction of 2026-09-13).
	[ "$(read :CFBundleIdentifier)" = "de.elasticdms.folderclient.fileprovider" ] ||
		error "The extension's CFBundleIdentifier does not lie below the app's."
	[ "$(read ':NSExtension:NSExtensionPointIdentifier')" = "com.apple.fileprovider-nonui" ] ||
		error "NSExtensionPointIdentifier is not com.apple.fileprovider-nonui."
	[ "$(read ':NSExtension:NSExtensionFileProviderSupportsEnumeration')" = "true" ] ||
		error "NSExtensionFileProviderSupportsEnumeration is missing; the system would never ask for an enumerator."

	# An app group needs a team ID as a prefix; ad hoc there is none, and an unfitting key makes the
	# system discard the extension without a word (ADR-D05, measurement 3).
	if /usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionFileProviderDocumentGroup' "$plist" >/dev/null 2>&1; then
		error "NSExtensionFileProviderDocumentGroup stands in the Info.plist; without a team ID macOS discards the extension."
	fi

	# The name of the principal class stands twice: in the plist and in the source. Otherwise a typo
	# is only noticed at the empty Finder folder.
	local in_plist from_source
	in_plist="$(read ':NSExtension:NSExtensionPrincipalClass')"
	from_source="$(sed -n 's/^pub const PRINCIPAL_CLASS: &str = "\(.*\)";$/\1/p' "$EXTENSION_SOURCE")"
	[ -n "$from_source" ] || error "PRINCIPAL_CLASS does not stand in $EXTENSION_SOURCE."
	[ "$in_plist" = "$from_source" ] ||
		error "NSExtensionPrincipalClass is “${in_plist}”, the source names “${from_source}”."
}

# Reads the entitlements from the finished signature, not from the template.
#
# A template that never reached codesign looks just as right on the disk; the extension would then
# run without a sandbox (PlugInKit does not accept it) or without the read exception (the rendezvous
# file would stay unreadable, and every request would end in "app not reachable").
verify_entitlements() {
	local entitlements
	entitlements="$(codesign --display --entitlements - --xml "$APPEX" 2>/dev/null)"
	for key in \
		com.apple.security.app-sandbox \
		com.apple.security.network.client \
		com.apple.security.temporary-exception.files.home-relative-path.read-only; do
		case "$entitlements" in
		*"$key"*) ;;
		*) error "The extension's signature does not carry “${key}”." ;;
		esac
	done
	case "$entitlements" in
	*"/Library/Application Support/de.elasticdms.folderclient/"*) ;;
	*) error "The read exception does not name the folder with the rendezvous file." ;;
	esac

	# The app gets none: with an empty sandbox it could neither listen nor write.
	local app_entitlements
	app_entitlements="$(codesign --display --entitlements - --xml "$APP" 2>/dev/null)"
	[ -z "$app_entitlements" ] || error "The app carries entitlements but is meant to carry none: $app_entitlements"
}

# Proves that the extension's program begins at _NSExtensionMain and not at Rust's main.
#
# LC_MAIN names only an offset. It lies in the stub table (__TEXT,__stubs), and `otool -I -v` says
# which imported name stands at which address there — the proof needs no more than that.
#
# EVERY ARCHITECTURE SEPARATELY, and that is no formality: with a universal file
# (scripts/macos-package.sh joins both architectures with lipo) `otool -l` prints the load commands
# of both architectures one after the other. An `awk … exit` then reads only the FIRST — in the
# order lipo produces, x86_64. The arm64 architecture, which runs on every Mac today, would stay
# unchecked: an extension that began at Rust's `main` there would pass green and leave the folder
# empty at the customer's. Hence `otool -arch` per entry from `lipo -archs`; with a single-arch file
# that is exactly one pass.
verify_entry_point() {
	local program="$APPEX/Contents/MacOS/$APPEX_BINARY"
	local arch offset base address name
	# shellcheck disable=SC2086 # `lipo -archs` prints the architectures separated by spaces; the
	# splitting is wanted here.
	for arch in $(lipo -archs "$program"); do
		offset="$(otool -arch "$arch" -l "$program" | awk '/cmd LC_MAIN/{f=1} f&&/entryoff/{print $2; exit}')"
		base="$(otool -arch "$arch" -l "$program" | awk '/segname __TEXT$/{f=1} f&&/vmaddr/{print $2; exit}')"
		[ -n "$offset" ] && [ -n "$base" ] ||
			error "$program has no LC_MAIN in the $arch architecture; that is not an executable."
		address="$(printf '0x%016x' $((base + offset)))"
		name="$(otool -arch "$arch" -I -v "$program" | awk -v a="$address" '$1==a {print $3; exit}')"
		[ "$name" = "_NSExtensionMain" ] ||
			error "The entry point of the $arch architecture lies at $address (${name:-no imported name}), not at _NSExtensionMain."
		printf '    Entry point %-7s %s → %s\n' "$arch" "$address" "$name"
	done
}

task_build() {
	task_compile
	task_bundle
	task_sign
	task_verify
}

# Changes the system: puts the bundle where macOS finds the extension. Afterwards the user has to
# switch it on once in "System Settings → General → Login Items and Extensions"; without that the
# folder stays empty and every access hangs (ADR-D05, measurement 4).
task_install() {
	verify_environment
	[ -d "$APP" ] || error "$APP is missing; run “build” first."
	local target="$HOME/Applications"
	mkdir -p "$target"
	report "Copying to $target/elasticdms.app"
	rm -rf "${target:?}/elasticdms.app"
	cp -R "$APP" "$target/elasticdms.app"
	cat <<-'END'

		    One manual step left that no program can take off you:
		    System Settings → General → Login Items and Extensions →
		    File Providers → switch "elasticdms" on.
	END
}

task_clean() {
	report "Removing $OUTPUT_DIR"
	rm -rf "$OUTPUT_DIR"
}

# ── Dispatcher ───────────────────────────────────────────────────────────────

main() {
	local task="${1:-help}"
	if ! declare -F "task_$task" >/dev/null; then
		printf 'Unknown task “%s”.\n\n' "$task" >&2
		task_help >&2
		exit 2
	fi
	"task_$task"
}

main "$@"
