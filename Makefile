CC       = gcc
MINGW32  = i686-w64-mingw32-gcc
MINGW64  = x86_64-w64-mingw32-gcc
CFLAGS   = -Wall -O2
BUILD    = build

all: check-deps $(BUILD)/tap_bridge $(BUILD)/rvpnnetmp.sys $(BUILD)/adapter_hook.dll $(BUILD)/rvpn_launcher.exe $(BUILD)/netsh.exe $(BUILD)/netsh64.exe $(BUILD)/rvpn_filter_ui

build: install-deps all

$(BUILD)/tap_bridge: src/tap_bridge.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< -lpthread

$(BUILD)/rvpn_filter_ui: src/rvpn_filter_ui.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(shell pkg-config --cflags --libs gtk4)

$(BUILD)/rvpnnetmp.sys: src/rvpnnetmp.c | $(BUILD)
	$(MINGW64) -shared -o $@ $< \
		-I/usr/x86_64-w64-mingw32/include/ddk \
		-lntoskrnl -lhal -nostdlib \
		-Wl,--subsystem,native -Wl,--entry,DriverEntry

$(BUILD)/adapter_hook.dll: src/adapter_hook.c | $(BUILD)
	$(MINGW32) -shared -o $@ $< \
		-liphlpapi -lws2_32 -Wl,--enable-stdcall-fixup

$(BUILD)/rvpn_launcher.exe: src/rvpn_launcher.c | $(BUILD)
	$(MINGW32) $(CFLAGS) -o $@ $<

$(BUILD)/netsh.exe: src/netsh_wrapper.c | $(BUILD)
	$(MINGW32) $(CFLAGS) -o $@ $< -municode

$(BUILD)/netsh64.exe: src/netsh_wrapper.c | $(BUILD)
	$(MINGW64) $(CFLAGS) -o $@ $< -municode

$(BUILD):
	mkdir -p $(BUILD)

install-deps:
	@echo "[*] Installing dependencies (requires sudo)..."
	@sudo apt update -qq
	@sudo apt install -y --no-install-recommends \
		gcc \
		make \
		mingw-w64 \
		libgtk-4-dev
	@echo "[+] Dependencies installed"

install-datacenter-deps:
	@echo "[*] Installing datacenter dependencies (requires sudo)..."
	@sudo apt update -qq
	@sudo apt install -y --no-install-recommends \
		xvfb \
		x11vnc \
		novnc \
		websockify
	@echo "[+] Datacenter dependencies installed"

check-deps:
	@command -v $(MINGW32) >/dev/null || { echo "Missing: $(MINGW32) (run 'make install-deps')"; exit 1; }
	@command -v $(MINGW64) >/dev/null || { echo "Missing: $(MINGW64) (run 'make install-deps')"; exit 1; }
	@pkg-config --exists gtk4 || { echo "Missing: gtk4 (run 'make install-deps')"; exit 1; }

appimage: check-build-artifacts
	chmod +x packaging/build-appimage.sh
	./packaging/build-appimage.sh

check-build-artifacts:
	@for f in tap_bridge rvpnnetmp.sys adapter_hook.dll rvpn_launcher.exe netsh.exe netsh64.exe; do \
		[ -f "$(BUILD)/$$f" ] || { echo "Missing: $(BUILD)/$$f (run 'make' first)"; exit 1; }; \
	done
	@if [ ! -f "$(BUILD)/rvpn_filter_ui" ]; then echo "[!] rvpn_filter_ui not found — will be skipped"; fi

clean:
	rm -rf $(BUILD)

.PHONY: all check-deps check-build-artifacts clean install-deps install-datacenter-deps build appimage
