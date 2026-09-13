#!/usr/bin/env bash
#
# macos-package.sh — builds an installation package elasticdms-<version>.pkg out of the bundle.
#
# THE REASON this script exists, and why it builds a .pkg and not a .dmg: the operator distributes
# to managed devices. Jamf accepts .pkg and nothing else, Intune explicitly accepts unsigned
# packages too under "macOS app (PKG)" — a .dmg is at best the second form, for a direct download.
# But something else is decisive: a bundle put into /Applications by the installer carries no
# com.apple.quarantine (measured against /Applications/OneDrive.app and /Applications/Xcode.app)
# and is therefore never translocated. Apple describes translocation as "Gatekeeper opens apps from
# randomized, read-only locations … designed to prevent the automatic loading of plug-ins
# distributed alongside the app" — exactly the mechanism that destroys the embedded .appex. The
# package sidesteps the question instead of answering it.
#
# Calls:
#   scripts/macos-package.sh build        # the whole way to the .pkg
#   scripts/macos-package.sh universal    # compile both architectures and join them with lipo
#   scripts/macos-package.sh bundle       # elasticdms.app out of the universal programs
#   scripts/macos-package.sh sign         # extension, then app (ad hoc or Developer ID)
#   scripts/macos-package.sh package      # pkgbuild (two components) + productbuild
#   scripts/macos-package.sh notarize     # notarytool + stapler; skipped without access
#   scripts/macos-package.sh verify       # expand the finished .pkg and measure it again
#   scripts/macos-package.sh remove       # calls the uninstall script (CHANGES THE SYSTEM)
#   scripts/macos-package.sh clean        # delete target/pkg and target/universal
#   scripts/macos-package.sh help
#
# Environment variables:
#   SIGNING_IDENTITY=…       "Developer ID Application: … (F2N9G4DJKM)" for the app and the
#                            extension. Default "-": ad hoc.
#   INSTALLER_IDENTITY=…     "Developer ID Installer: …" for the product archive. Those are TWO
#                            different certificates. With an application identity productbuild
#                            refuses: "An installer signing identity (not an application signing
#                            identity) is required for signing flat-style products" (measured).
#                            Empty: an unsigned package.
#   ASC_KEY_P8=…             App Store Connect API key (.p8) for the notarisation,
#   ASC_KEY_ID=…             plus the key ID and the issuer UUID. To be preferred over the
#   ASC_ISSUER=…             app-specific password: no personal account, revocable on its own.
#   APPLE_ACCOUNT / APPLE_PASSWORD / APPLE_TEAM   The fallback path over an app-specific password.
#   EDMS_API_BASE / EDMS_AUTH_BASE / EDMS_APP_BASE
#                            If all three are set, the package writes them into the login item as
#                            EnvironmentVariables. Otherwise the key stays away entirely and the
#                            operator supplies it over MDM; an invented default would mean "wrong
#                            tenant, and everything works".
#
# WITHOUT ANY CERTIFICATE this script runs all the way through and delivers an unsigned,
# un-notarised .pkg. That is no makeshift: it installs into /Applications, without quarantine, and
# can be distributed over Intune "macOS app (PKG)" or a Jamf policy. What is missing is Gatekeeper's
# approval on a double click from the network — and every MDM pre-approval, because that addresses
# apps as "bundle ID (team ID)", and an ad-hoc signature has no team ID.
#
# What this script explicitly does NOT do: install. `build` touches nothing outside target/. Only
# `remove` changes the system, and it says so and asks first.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES="$ROOT/packaging/macos"
BUNDLE_SCRIPT="$ROOT/scripts/macos-bundle.sh"

SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"

# ADR-D05: NSFileProviderItem.contentPolicy exists from macOS 13. The same number stands in both
# Info.plists (LSMinimumSystemVersion) and in the distribution description; here it additionally
# sets LC_BUILD_VERSION in the program. Otherwise rustc takes 11.0 (aarch64) or 10.12 (x86_64) —
# and then the bundle would say "13.0" and the program something else.
export MACOSX_DEPLOYMENT_TARGET=13.0

TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
APP_BINARY="elasticdms"
APPEX_BINARY="elasticdms-fileprovider"

UNIVERSAL="$ROOT/target/universal"
BUNDLE="$ROOT/target/bundle"
APP="$BUNDLE/elasticdms.app"
PACKAGE_DIR="$ROOT/target/pkg"
ROOT_APP="$PACKAGE_DIR/root-app"
ROOT_LOGIN_ITEM="$PACKAGE_DIR/root-loginitem"
PAYLOAD_DIR="$PACKAGE_DIR/payload"

# Three identifiers: one per component and one for the product. The two component identifiers are
# at the same time the receipts that `pkgutil --forget` gets rid of during the uninstall. English
# since 2026-09-13: they become identities on installed machines with the first package that leaves
# this repository, and on 2026-09-13 no such package existed (ADR-D10, correction of 2026-09-13).
ID_PRODUCT="de.elasticdms.folderclient"
ID_APP="de.elasticdms.folderclient.app"
ID_LOGIN_ITEM="de.elasticdms.folderclient.loginitem"

LOGIN_ITEM_PLIST="de.elasticdms.folderclient.plist"

report() { printf '\033[1m==> %s\033[0m\n' "$*"; }
hint() { printf '    %s\n' "$*"; }
error() {
	printf '\033[1;31mError:\033[0m %s\n' "$*" >&2
	exit 1
}

# ── Helpers ──────────────────────────────────────────────────────────────────

verify_environment() {
	[ "$(uname -s)" = "Darwin" ] || error "macos-package.sh only runs on macOS (here: $(uname -s))."
	local tool
	for tool in pkgbuild productbuild pkgutil lipo vtool plutil codesign xattr; do
		command -v "$tool" >/dev/null ||
			error "$tool is missing; please install the Xcode command line tools."
	done
	[ -x "$BUNDLE_SCRIPT" ] || error "$BUNDLE_SCRIPT is missing or not executable."
}

# The version has its only truth in Cargo.toml — as in macos-bundle.sh. The installer decides
# update against downgrade on that number alone.
version() {
	sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1
}

product_file() {
	printf '%s/elasticdms-%s.pkg' "$PACKAGE_DIR" "$(version)"
}

# Free space in MB on the startup volume.
free_mb() { df -m / | awk 'NR==2 {print $4}'; }

# A universal build creates two complete release target directories. On the development machine
# there are roughly 12 GB free; the house rule "stop below 2 GB" is no formality here but the
# difference between an aborted build and a full startup volume.
verify_disk_space() {
	local free
	free="$(free_mb)"
	hint "Free space: ${free} MB"
	[ "$free" -ge 2048 ] ||
		error "Only ${free} MB are left free on /; a universal build needs more. Please make space (scripts/macos-package.sh clean removes target/pkg and target/universal)."
}

# Writes a template with the version substituted to its place.
set_version() {
	local template="$1" target="$2"
	[ -f "$template" ] || error "The template $template is missing."
	sed "s/@VERSION@/$(version)/g" "$template" >"$target"
}

# edms-mock is the server mock — a test rig. What has no business being in a delivered artefact is
# not looked for there but ruled out: a hit is an abort, not a note.
verify_no_mock() {
	local what="$1" hit
	hit="$(printf '%s\n' "$what" | grep -i 'mock' || true)"
	[ -z "$hit" ] ||
		error "The payload holds edms-mock (a test rig, never to be delivered): $hit"
}

# ── Tasks ────────────────────────────────────────────────────────────────────

# The head of this file from line 3 to the first line that is not a comment.
task_help() {
	awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${BASH_SOURCE[0]}"
}

# Compile both architectures and join each program into one universal program.
#
# `lipo` has to run BEFORE `codesign`: it rewrites the file and thereby cuts the ground from under
# a finished signature.
task_universal() {
	verify_environment
	verify_disk_space
	local target
	for target in "${TARGETS[@]}"; do
		report "Compiling for $target (release, macOS $MACOSX_DEPLOYMENT_TARGET)"
		# Two separate calls as in macos-bundle.sh: only the extension's program gets the entry
		# point _NSExtensionMain (crates/fileprovider/build.rs).
		(cd "$ROOT" && cargo build --release --target "$target" -p elasticdms --bin "$APP_BINARY")
		(cd "$ROOT" && cargo build --release --target "$target" -p edms-fileprovider --bin "$APPEX_BINARY")
		verify_disk_space
	done

	report "Joining both architectures (lipo)"
	mkdir -p "$UNIVERSAL"
	local program
	for program in "$APP_BINARY" "$APPEX_BINARY"; do
		lipo -create -output "$UNIVERSAL/$program" \
			"$ROOT/target/${TARGETS[0]}/release/$program" \
			"$ROOT/target/${TARGETS[1]}/release/$program"
	done

	# The icon travels with them, copied and not joined: a picture has no architecture, and the
	# build script writes the same iconset next to each of the two builds. macos-bundle.sh looks
	# for it beside the programs it bundles, and here that is this directory.
	local iconset="$ROOT/target/${TARGETS[0]}/release/elasticdms.iconset"
	[ -d "$iconset" ] ||
		error "$iconset is missing although the build has run; crates/app/build.rs writes it next to the program."
	rm -rf "${UNIVERSAL:?}/elasticdms.iconset"
	cp -R "$iconset" "$UNIVERSAL/elasticdms.iconset"

	verify_universal
}

# Proves what the build claims: both architectures inside, and both built for macOS 13.0.
#
# Without this check a forgotten MACOSX_DEPLOYMENT_TARGET is only noticed on a Mac running
# macOS 13 — that is, never here, but at the customer's.
verify_universal() {
	local program arches minos
	for program in "$APP_BINARY" "$APPEX_BINARY"; do
		arches="$(lipo -archs "$UNIVERSAL/$program")"
		case " $arches " in
		*" arm64 "*) ;;
		*) error "$UNIVERSAL/$program carries no arm64 but “${arches}”." ;;
		esac
		case " $arches " in
		*" x86_64 "*) ;;
		*) error "$UNIVERSAL/$program carries no x86_64 but “${arches}”." ;;
		esac
		# vtool reads LC_BUILD_VERSION per architecture; every line has to name 13.0.
		minos="$(vtool -show-build-version "$UNIVERSAL/$program" | awk '/minos/ {print $2}' | sort -u | tr '\n' ' ')"
		[ "$minos" = "13.0 " ] ||
			error "$UNIVERSAL/$program is built for macOS “${minos}”, not for 13.0 — MACOSX_DEPLOYMENT_TARGET was missing."
		printf '    %-28s %s  minos %s\n' "$program" "$arches" "${minos% }"
	done
}

# Build the bundle — the work is done by macos-bundle.sh, here only the universal programs go in
# instead of target/<profile>/.
task_bundle() {
	verify_environment
	[ -x "$UNIVERSAL/$APP_BINARY" ] ||
		error "$UNIVERSAL/$APP_BINARY is missing; run “universal” first."
	[ -x "$UNIVERSAL/$APPEX_BINARY" ] ||
		error "$UNIVERSAL/$APPEX_BINARY is missing; run “universal” first."

	PROFILE=release BINARY_DIR="$UNIVERSAL" "$BUNDLE_SCRIPT" bundle

	# Quarantine off before anything collects the payload: a packed-in com.apple.quarantine is
	# restored on installation, and the installed app would then be translocatable again — exactly
	# what this package is built against. Mostly without effect on the build machine, not so in CI
	# after an artefact download.
	xattr -cr "$APP"
}

task_sign() {
	verify_environment
	[ -d "$APP" ] || error "$APP is missing; run “bundle” first."
	SIGNING_IDENTITY="$SIGNING_IDENTITY" "$BUNDLE_SCRIPT" sign
	SIGNING_IDENTITY="$SIGNING_IDENTITY" "$BUNDLE_SCRIPT" verify
}

# ── The package ──────────────────────────────────────────────────────────────

task_package() {
	verify_environment
	[ -d "$APP" ] || error "$APP is missing; run “bundle” and “sign” first."
	[ -d "$APP/Contents/_CodeSignature" ] ||
		error "$APP is not signed; run “sign” first (ad hoc is enough)."

	build_roots
	verify_components
	build_component_packages
	verify_payload
	build_product
}

# Two installation roots, because there are two destinations.
#
# The app root contains ONLY elasticdms.app; the place comes from --install-location. That is
# cleaner than a root holding Applications/elasticdms.app, because RootRelativeBundlePath in the
# component list is then simply "elasticdms.app".
build_roots() {
	report "Building the installation roots"
	rm -rf "$ROOT_APP" "$ROOT_LOGIN_ITEM"
	mkdir -p "$ROOT_APP" "$ROOT_LOGIN_ITEM/Library/LaunchAgents"

	cp -R "$APP" "$ROOT_APP/"
	xattr -cr "$ROOT_APP"

	local target="$ROOT_LOGIN_ITEM/Library/LaunchAgents/$LOGIN_ITEM_PLIST"
	cp "$TEMPLATES/$LOGIN_ITEM_PLIST" "$target"
	chmod 644 "$target"
	set_environment_in_login_item "$target"
	plutil -lint "$target" >/dev/null ||
		error "$TEMPLATES/$LOGIN_ITEM_PLIST is not a valid plist."
	hint "elasticdms.app → /Applications"
	hint "$LOGIN_ITEM_PLIST → /Library/LaunchAgents"
}

# Writes the three mandatory variables into the login item when they are set at build time.
#
# All three or none: with two, elasticdms starts just as little as with none, only that the error
# then comes after half the setup. If they are missing, the key stays away entirely — an invented
# base address would mean "wrong tenant, and everything works" (crates/app/src/setup.rs).
set_environment_in_login_item() {
	local plist="$1"
	local api="${EDMS_API_BASE:-}" auth="${EDMS_AUTH_BASE:-}" app="${EDMS_APP_BASE:-}"
	if [ -z "$api" ] && [ -z "$auth" ] && [ -z "$app" ]; then
		hint "Without EDMS_API_BASE/EDMS_AUTH_BASE/EDMS_APP_BASE: the login item carries no environment; the operator supplies it over MDM."
		return 0
	fi
	if [ -z "$api" ] || [ -z "$auth" ] || [ -z "$app" ]; then
		error "EDMS_API_BASE, EDMS_AUTH_BASE and EDMS_APP_BASE belong together; here at least one is set and at least one is empty."
	fi
	/usr/libexec/PlistBuddy \
		-c "Add :EnvironmentVariables dict" \
		-c "Add :EnvironmentVariables:EDMS_API_BASE string $api" \
		-c "Add :EnvironmentVariables:EDMS_AUTH_BASE string $auth" \
		-c "Add :EnvironmentVariables:EDMS_APP_BASE string $app" \
		"$plist" >/dev/null
	hint "The login item carries EDMS_API_BASE=$api"
}

# The component list stands in the repository and is only measured against the bundle here.
#
# THE REASON: `pkgbuild --analyze` sets BundleIsRelocatable to true (measured). The installer would
# then look through the Launch Services database for an existing copy with the same bundle
# identifier and write THERE — a developer copy in ~/Applications would catch the update, and
# /Applications/elasticdms.app would stay old or never arise. That is only noticed at the empty
# Finder folder. Hence the list stands in the repository with `false`, and here it is checked
# whether it still fits the bundle.
verify_components() {
	report "Checking the component list"
	local list="$TEMPLATES/components.plist"
	[ -f "$list" ] || error "$list is missing; it belongs in the repository (produced with pkgbuild --analyze, then BundleIsRelocatable and BundleIsVersionChecked set to false)."

	local value key
	for key in BundleIsRelocatable BundleIsVersionChecked; do
		value="$(/usr/libexec/PlistBuddy -c "Print :0:$key" "$list" 2>/dev/null || true)"
		[ "$value" = "false" ] ||
			error "In $list $key stands as “${value}”; it has to be false, otherwise the installer writes the app where a user once moved it."
	done

	# A cross-check against the real bundle: a newly added child bundle (a second extension, say)
	# would otherwise not stand in the list, and pkgbuild would treat it as mere content.
	local fresh="$PACKAGE_DIR/components-fresh.plist"
	local from_repo="$PACKAGE_DIR/components-repo.plist"
	pkgbuild --analyze --root "$ROOT_APP" "$fresh" >/dev/null
	/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$fresh" >/dev/null
	/usr/libexec/PlistBuddy -c "Set :0:BundleIsVersionChecked false" "$fresh" >/dev/null
	plutil -convert xml1 "$fresh"
	cp "$list" "$from_repo"
	plutil -convert xml1 "$from_repo"
	diff -u "$from_repo" "$fresh" ||
		error "packaging/macos/components.plist no longer fits the bundle (differences above). Produce it anew: pkgbuild --analyze --root target/pkg/root-app packaging/macos/components.plist, then set BundleIsRelocatable and BundleIsVersionChecked to false."
	hint "The list fits the bundle; BundleIsRelocatable=false"
}

build_component_packages() {
	report "Building the two component packages (pkgbuild)"
	# --ownership recommended is the default and stands here spelled out: the files land as
	# root:wheel, not under the identifier of whoever built them. A LaunchAgent owned by the build
	# account does not load on the target machine.
	pkgbuild \
		--identifier "$ID_APP" \
		--version "$(version)" \
		--root "$ROOT_APP" \
		--install-location /Applications \
		--component-plist "$TEMPLATES/components.plist" \
		--scripts "$TEMPLATES/scripts-app" \
		--ownership recommended \
		--min-os-version 13.0 \
		"$PACKAGE_DIR/elasticdms-app.pkg"

	pkgbuild \
		--identifier "$ID_LOGIN_ITEM" \
		--version "$(version)" \
		--root "$ROOT_LOGIN_ITEM" \
		--install-location / \
		--scripts "$TEMPLATES/scripts-loginitem" \
		--ownership recommended \
		--min-os-version 13.0 \
		"$PACKAGE_DIR/elasticdms-loginitem.pkg"
}

# What is in the package is checked on the package and not on the folder it was built from.
verify_payload() {
	report "Checking the payload of the component packages"
	local files
	files="$(pkgutil --payload-files "$PACKAGE_DIR/elasticdms-app.pkg")"
	verify_no_mock "$files"
	local path
	for path in \
		"./elasticdms.app/Contents/MacOS/$APP_BINARY" \
		"./elasticdms.app/Contents/Info.plist" \
		"./elasticdms.app/Contents/PlugIns/$APPEX_BINARY.appex/Contents/MacOS/$APPEX_BINARY" \
		"./elasticdms.app/Contents/PlugIns/$APPEX_BINARY.appex/Contents/Info.plist" \
		"./elasticdms.app/Contents/Resources/elasticdms-uninstall.sh"; do
		printf '%s\n' "$files" | grep -qxF "$path" ||
			error "$path is missing from elasticdms-app.pkg."
	done
	hint "elasticdms.app including the .appex and the uninstall script is inside"

	files="$(pkgutil --payload-files "$PACKAGE_DIR/elasticdms-loginitem.pkg")"
	verify_no_mock "$files"
	printf '%s\n' "$files" | grep -qxF "./Library/LaunchAgents/$LOGIN_ITEM_PLIST" ||
		error "./Library/LaunchAgents/$LOGIN_ITEM_PLIST is missing from elasticdms-loginitem.pkg."
	hint "The login item is inside"

	verify_no_mock_in_binary
}

# The second cross-check: not only no file name, but no trace in the program itself either.
#
# Had edms-mock ever been entered as a dependency of the app by mistake, no file would be named
# after it — the test rig would simply sit inside the program. The crate name then appears in the
# program's symbol names and paths; measured, it is contained zero times in both programs.
verify_no_mock_in_binary() {
	local program hits
	for program in \
		"$ROOT_APP/elasticdms.app/Contents/MacOS/$APP_BINARY" \
		"$ROOT_APP/elasticdms.app/Contents/PlugIns/$APPEX_BINARY.appex/Contents/MacOS/$APPEX_BINARY"; do
		hits="$(LC_ALL=C grep -a -c 'edms_mock\|edms-mock' "$program" || true)"
		[ "$hits" = "0" ] ||
			error "$(basename "$program") names edms-mock ($hits hits); the test rig belongs in no delivered program."
	done
	hint "No edms-mock in the programs"
}

build_product() {
	report "Building the product archive (productbuild)"
	local distribution="$PACKAGE_DIR/distribution.dist"
	set_version "$TEMPLATES/distribution.dist" "$distribution"

	local flags=(
		--distribution "$distribution"
		--package-path "$PACKAGE_DIR"
		--resources "$TEMPLATES/resources"
		--identifier "$ID_PRODUCT"
		--version "$(version)"
	)
	if [ -n "$INSTALLER_IDENTITY" ]; then
		flags+=(--sign "$INSTALLER_IDENTITY")
	fi
	productbuild "${flags[@]}" "$(product_file)"

	if [ -n "$INSTALLER_IDENTITY" ]; then
		report "Done, signed with “${INSTALLER_IDENTITY}”: $(product_file)"
	else
		report "Done: $(product_file)"
		# One sentence, not three: what is missing, what works all the same, what does not.
		hint "This package is unsigned and not notarised — it is good for distribution over MDM (Intune “macOS app (PKG)”, a Jamf policy) and for installing by hand, but a double click on a copy loaded from the network is refused by Gatekeeper; for both, a certificate “Developer ID Installer” in team F2N9G4DJKM is missing."
	fi
}

# ── Notarisation ─────────────────────────────────────────────────────────────

# Per Apple the service accepts only "disk images (UDIF format), signed flat installer packages, and
# ZIP archives" — an unsigned .pkg cannot be notarised. If the signature or the access is missing,
# that is no fault of this run but a missing certificate: the script says so and goes on.
task_notarize() {
	verify_environment
	local package
	package="$(product_file)"
	[ -f "$package" ] || error "$package is missing; run “package” first."

	if ! pkgutil --check-signature "$package" 2>/dev/null | grep -q "Status: signed"; then
		report "Not notarised"
		hint "The package is unsigned, and the notarisation service accepts signed flat packages only. A certificate “Developer ID Installer” (INSTALLER_IDENTITY) is missing for that."
		return 0
	fi

	local access=()
	if [ -n "${ASC_KEY_P8:-}" ] && [ -n "${ASC_KEY_ID:-}" ] && [ -n "${ASC_ISSUER:-}" ]; then
		access=(--key "$ASC_KEY_P8" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER")
		report "Notarising with the App Store Connect API key"
	elif [ -n "${APPLE_ACCOUNT:-}" ] && [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM:-}" ]; then
		access=(--apple-id "$APPLE_ACCOUNT" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM")
		report "Notarising with an app-specific password"
	else
		report "Not notarised"
		hint "The access is missing: either ASC_KEY_P8, ASC_KEY_ID and ASC_ISSUER, or APPLE_ACCOUNT, APPLE_PASSWORD and APPLE_TEAM."
		return 0
	fi

	xcrun notarytool submit "$package" "${access[@]}" --wait --timeout 30m ||
		error "The notarisation failed. Fetch the log with: xcrun notarytool log <submission id> …"

	report "Stapling the ticket (stapler)"
	xcrun stapler staple "$package"
	# The return value, not the output: on a package without a ticket `stapler validate` prints only
	# "Processing: …" and no clear refusal (measured). Whoever reads the output instead of the exit
	# code reports green for a package without a ticket.
	xcrun stapler validate "$package" ||
		error "The ticket is not in place: “xcrun stapler validate” returned an error."
	report "Notarised and stapled: $package"
}

# ── Checking ─────────────────────────────────────────────────────────────────

# Checks the finished .pkg without installing it: expand and measure.
#
# The core of it is that the same rules macos-bundle.sh checks on the freshly built bundle run once
# more here on the expanded package payload — on what arrives at the target machine, not on what the
# build meant. Hence BUNDLE_DIR instead of a second, transcribed list.
task_verify() {
	verify_environment
	local package
	package="$(product_file)"
	[ -f "$package" ] || error "$package is missing; run “package” first."

	report "The package signature"
	pkgutil --check-signature "$package" 2>&1 | sed 's/^/    /' || true
	# spctl is the Gatekeeper test for packages. On an unsigned package it says no — that is the
	# truth about this package and no fault of this run.
	spctl -a -vvv -t install "$package" 2>&1 | sed 's/^/    /' || true

	report "Expanding the package (pkgutil --expand-full)"
	rm -rf "$PAYLOAD_DIR"
	pkgutil --expand-full "$package" "$PAYLOAD_DIR"

	local payload_app="$PAYLOAD_DIR/elasticdms-app.pkg/Payload"
	local payload_loginitem="$PAYLOAD_DIR/elasticdms-loginitem.pkg/Payload"
	[ -d "$payload_app/elasticdms.app" ] ||
		error "elasticdms.app is missing from the expanded package."
	[ -d "$payload_app/elasticdms.app/Contents/PlugIns/$APPEX_BINARY.appex" ] ||
		error "The embedded $APPEX_BINARY.appex is missing from the expanded package."
	verify_no_mock "$(find "$PAYLOAD_DIR" -print)"

	report "Checking the minimum version in the distribution description"
	grep -q '<os-version min="13.0"' "$PAYLOAD_DIR/Distribution" ||
		error "The distribution description names no minimum version 13.0; the package could be installed on macOS 12, where the app does not start."

	# The same checks as on the bundle: both Info.plists, the keys, the signatures, the extension's
	# entitlements and the entry point _NSExtensionMain.
	report "Checking the bundle in the package payload"
	BUNDLE_DIR="$payload_app" PROFILE=release SIGNING_IDENTITY="$SIGNING_IDENTITY" \
		"$BUNDLE_SCRIPT" verify

	report "Checking the programs in the payload for both architectures"
	local program
	for program in \
		"$payload_app/elasticdms.app/Contents/MacOS/$APP_BINARY" \
		"$payload_app/elasticdms.app/Contents/PlugIns/$APPEX_BINARY.appex/Contents/MacOS/$APPEX_BINARY"; do
		local arches
		arches="$(lipo -archs "$program")"
		case " $arches " in
		*" arm64 "* ) ;;
		*) error "$(basename "$program") in the payload carries no arm64 but “${arches}”." ;;
		esac
		case " $arches " in
		*" x86_64 "* ) ;;
		*) error "$(basename "$program") in the payload carries no x86_64 but “${arches}”." ;;
		esac
		printf '    %-28s %s\n' "$(basename "$program")" "$arches"
	done

	report "Checking the login item in the payload"
	local plist="$payload_loginitem/Library/LaunchAgents/$LOGIN_ITEM_PLIST"
	[ -f "$plist" ] || error "$LOGIN_ITEM_PLIST is missing from the expanded package."
	plutil -lint "$plist"
	read_agent() { /usr/libexec/PlistBuddy -c "Print $1" "$plist" 2>/dev/null || true; }
	[ "$(read_agent :Label)" = "$ID_PRODUCT" ] ||
		error "The login item's label is not $ID_PRODUCT."
	[ "$(read_agent :ProgramArguments:0)" = "/Applications/elasticdms.app/Contents/MacOS/elasticdms" ] ||
		error "The login item does not point at /Applications/elasticdms.app/Contents/MacOS/elasticdms."
	[ "$(read_agent :RunAtLoad)" = "true" ] ||
		error "RunAtLoad is missing from the login item; then nothing would start after signing in."
	# KeepAlive would be a fault here and not an ingredient: without the three EDMS_* variables
	# elasticdms aborts the start, and that would turn into a start loop every ten seconds.
	[ -z "$(read_agent :KeepAlive)" ] ||
		error "KeepAlive stands in the login item; without EDMS_API_BASE that would be a start loop."
	hint "Label, program path and RunAtLoad are right"

	report "Package in order: $package"
	ls -lh "$package" | sed 's/^/    /'
}

# ── Uninstalling ─────────────────────────────────────────────────────────────

# Calls the uninstall script that ships with the bundle. CHANGES THE SYSTEM.
#
# It prefers the installed version inside the bundle: that one belongs to what lies on this machine.
# Only when nothing is installed does it take the version from the repository.
task_remove() {
	verify_environment
	local script="/Applications/elasticdms.app/Contents/Resources/elasticdms-uninstall.sh"
	[ -x "$script" ] || script="$TEMPLATES/elasticdms-uninstall.sh"
	[ -x "$script" ] || error "$script is missing or not executable."
	report "Calling $script — this changes this system."
	"$script" remove
}

task_clean() {
	report "Removing $PACKAGE_DIR and $UNIVERSAL"
	rm -rf "$PACKAGE_DIR" "$UNIVERSAL"
}

task_build() {
	task_universal
	task_bundle
	task_sign
	task_package
	task_notarize
	task_verify
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
