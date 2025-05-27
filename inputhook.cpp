#include "inputhook.h"

#include <thread>
#include <sys/stat.h>
#include <fstream>


InputHook::InputHook() {
	gum_init();
	INFO("Frida gum initialized");

	INFO("Starting keybind thread");
	std::thread(&InputHook::watchConfigFile, this).detach();

	m_interceptor = gum_interceptor_obtain();
	if (!m_interceptor) {
		ERR("Failed to obtain interceptor");
		return;
	}
	INFO("Resolving functions");
	resolveFunctions();
	INFO("Applying hooks");
	applyHooks();
}

void InputHook::resolveFunctions() {
	orig_lginput_uinput_send_button = reinterpret_cast<lginput_uinput_send_button_t*>(
		gum_find_function("lginput_uinput_send_button"));
	orig_MICOM_FuncWriteKeyEvent = reinterpret_cast<MICOM_FuncWriteKeyEvent_t*>(
		gum_find_function("MICOM_FuncWriteKeyEvent"));
	if (!orig_MICOM_FuncWriteKeyEvent && !orig_lginput_uinput_send_button) {
	 	orig_write = reinterpret_cast<write_t*>(gum_find_function("write"));
	}
}

void InputHook::applyHooks() {
	if (orig_lginput_uinput_send_button) {
		INFO("Replacing lginput_uinput_send_button");
		gum_interceptor_replace(m_interceptor,
			reinterpret_cast<gpointer>(orig_lginput_uinput_send_button),
			reinterpret_cast<gpointer>(&InputHook::trampoline_lginput),
			this,
			reinterpret_cast<gpointer*>(&orig_lginput_uinput_send_button)
		);
	}
	if (orig_MICOM_FuncWriteKeyEvent) {
		INFO("Replacing MICOM_FuncWriteKeyEvent");
		gum_interceptor_replace(m_interceptor,
			reinterpret_cast<gpointer>(orig_MICOM_FuncWriteKeyEvent),
			reinterpret_cast<gpointer>(&InputHook::trampoline_MICOM_FuncWriteKeyEvent),
			this,
			reinterpret_cast<gpointer*>(&orig_MICOM_FuncWriteKeyEvent)
		);
	}

	if (orig_write) {
		INFO("Replacing write");
		gum_interceptor_replace(m_interceptor,
			reinterpret_cast<gpointer>(orig_write),
			reinterpret_cast<gpointer>(&InputHook::trampoline_write),
			this,
			reinterpret_cast<gpointer*>(&orig_write)
		);
	}
}

bool InputHook::loadKeybinds() {
	std::unique_lock lock(m_mutex);
	std::ifstream file(CONFIG_LOCATION.data());
	if (!file.is_open()) {
		ERR("Failed to open keybinds file: %s", CONFIG_LOCATION.data());
		return false;
	}
	try {
		file >> m_keybinds;
	} catch (const nlohmann::json::parse_error& e) {
		ERR("Failed to parse keybinds file: %s", e.what());
		file.close();
		return false;
	}
	file.close();
	return true;
}

[[noreturn]] void InputHook::watchConfigFile() {
	struct stat file_stat{};
	time_t last_mtime = 0;
	while (true) {
		if (stat(CONFIG_LOCATION.data(), &file_stat) == 0) {
			if (file_stat.st_mtime != last_mtime) {
				last_mtime = file_stat.st_mtime;
				if (!loadKeybinds()) {;
					ERR("Failed to load keybinds");
				}
				INFO("Keybinds reloaded due to config file change");
			}
		}
		using namespace std::chrono_literals;
		std::this_thread::sleep_for(1s);
	}
}

void InputHook::launch(const std::string& cmd) {
	if (cmd.empty()) {
		ERR("Command is empty");
		return;
	}

	INFO("Launching command: %s", cmd.c_str());

	FILE* proc = popen((cmd + " &").c_str(), "w");
	if (!proc)
		ERR("Failed to launch command: %s", cmd.c_str());
	else
		pclose(proc);
}

std::tuple<Action, int> InputHook::handleKey(const int keycode, const int state) {
	std::unique_lock lock(m_mutex);
	try {
		if (!m_keybinds.contains(std::to_string(keycode))) {
			return {Action::PASS, keycode};
		}

		const nlohmann::json keybind = m_keybinds.at(std::to_string(keycode));
		const std::string action = keybind.value("action", "");
		if (action == "replace") {
			const int newKeyCode = keybind.at("keycode");
			INFO("Key %d is replaced with %d", keycode, newKeyCode);
			return {Action::REPLACE, newKeyCode};
		}

		if (action == "pass") {
			INFO("Key %d is passed", keycode);
			return {Action::PASS, keycode};
		}

		if (action == "ignore") {
			INFO("Key %d is ignored", keycode);
			return {Action::IGNORE, keycode};
		}

		if (action == "exec" || action == "launch") {
			if (state == 1) {
				if (action == "exec") {
					INFO("Key %d is exec", keycode);
					launch(keybind.at("command"));
				}
				if (action == "launch") {
					INFO("Key %d is launch", keycode);
					nlohmann::json json;
					json["id"] = keybind.at("id");
					if (keybind.contains("params")) {
						json["params"] = keybind.at("params");
					}
					const std::string command =
							"luna-send -n 1 \"luna://com.webos.applicationManager/launch\" '" + json.dump() + "'";
					launch(command);
				}
			}
			return {Action::IGNORE, keycode};
		}
		return {Action::PASS, keycode};
	} catch (const nlohmann::json::exception& e) {
		ERR("Failed to handle key %d: %s", keycode, e.what());
		return {Action::PASS, keycode};
	}
}

ssize_t InputHook::trampoline_write(const int fd, input_event_t* events, const size_t count) {
	GumInvocationContext* ctx = gum_interceptor_get_current_invocation();
	const gpointer ptr = gum_invocation_context_get_replacement_data(ctx);
	return static_cast<InputHook*>(ptr)->hook_write(fd, events, count);
}

int InputHook::trampoline_lginput(uinput_info_t* info, const int keyid, const int state) {
	GumInvocationContext* ctx = gum_interceptor_get_current_invocation();
	const gpointer ptr = gum_invocation_context_get_replacement_data(ctx);
	return static_cast<InputHook*>(ptr)->hook_lginput(info, keyid, state);
}

int InputHook::trampoline_MICOM_FuncWriteKeyEvent(const int fd, const uint16_t type, const uint16_t code, const int32_t value) {
	GumInvocationContext* ctx = gum_interceptor_get_current_invocation();
	const gpointer ptr = gum_invocation_context_get_replacement_data(ctx);
	return static_cast<InputHook*>(ptr)->hook_MICOM_FuncWriteKeyEvent(fd, type, code, value);
}

int InputHook::hook_lginput(uinput_info_t* info, const int keyid, const int state) {
	const int uinput_code = info->keybinds[keyid].uinput_code;
	INFO("lginput_uinput_send_button called: keyid=%d, state=%d uinput_code=%d", keyid, state, uinput_code);

	auto [action, newKeycode] = handleKey(info->keybinds[keyid].uinput_code, state);

	if (action == Action::REPLACE) {
	 	const int orig = info->keybinds[keyid].uinput_code;
	 	info->keybinds[keyid].uinput_code = newKeycode;
	 	const int ret = orig_lginput_uinput_send_button(info, keyid, state);
	 	info->keybinds[keyid].uinput_code = orig;
	 	return ret;
	}

    if (action == Action::IGNORE) {
	 	return 0;
	}

	return orig_lginput_uinput_send_button(info, keyid, state);
}

int InputHook::hook_MICOM_FuncWriteKeyEvent(const int fd, const uint16_t type, const uint16_t code, const int32_t value) {
	INFO("MICOM_FuncWriteKeyEvent called: fd=%d, type=%d, code=%d, value=%d", fd, type, code, value);

	if (type != 0) {
		auto [action, newKeycode] = handleKey(code, value);

		if (action == Action::REPLACE) {
			return orig_MICOM_FuncWriteKeyEvent(fd, type, newKeycode, value);
		}

		if (action == Action::IGNORE) {
			return 0;
		}
	}

	return orig_MICOM_FuncWriteKeyEvent(fd, type, code, value);
}

ssize_t InputHook::hook_write(const int fd, input_event_t* events, const size_t count) {
	char buf[255];
	const int size = readlink(("/proc/self/fd/$fd" + std::to_string(fd)).c_str(), buf, sizeof(buf));

	if (size > 0 && std::string(buf) == "/dev/uinput" && count >= 16 && events[0].type == 1) {
	 	INFO("write to /dev/uinput: code=%d, value=%d", events[0].code, events[0].value);
	 	auto [action, newKeycode] = handleKey(events[0].code, events[0].value);

	 	if (action == Action::REPLACE) {
	 		events[0].code = newKeycode;
	 	}

	 	if (action == Action::IGNORE) {
	 		return static_cast<ssize_t>(count);
	 	}
	}

	return orig_write(fd, events, count);
}

extern "C" {
	int lib_loginit() {
		const char* tmpfile = "/tmp/inputhook.log";
		log_config_t cfg = {
			.verbosity = V_DBG,
			.log_output = fopen(tmpfile, "w+"),
			.log_leave_open = true,
		};
		setvbuf(cfg.log_output, nullptr, _IONBF, 0);

		log_init(&cfg);
		return 0;
	}

	int lib_preinit(struct injcode_user *user){
		/**
		 * this is needed for hooks pointing to code in this library
		 * if we don't set this, dlclose() will be called and the hooks will segfault when called
		 * (because they will then refer to unmapped memory)
		 * this is *NOT* needed for code allocated elsewhere, e.g. on the heap (sljit)
		 **/
		user->persist = true;
		return 0;
	}

	int lib_main(int argc, char *argv[]){
		INFO("InputHook initialized");
		new InputHook();
		return 0;
	}
}

