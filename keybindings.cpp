#include "keybindings.h"

#include <nlohmann/json.hpp>

#include <charconv>
#include <cstdint>
#include <format>
#include <limits>
#include <stdexcept>

std::expected<KeyBindings, std::string> compileKeybindings(const nlohmann::json& json) {
    if (!json.is_object()) {
        return std::unexpected("Keybinds must be a JSON object");
    }
    KeyBindings bindings;
    for (const auto& [name, value] : json.items()) {
        try {
            int keycode = 0;
            const auto [end, error] = std::from_chars(name.data(), name.data() + name.size(), keycode);
            if (error != std::errc{} || end != name.data() + name.size() || keycode < 0 ||
                keycode > std::numeric_limits<std::uint16_t>::max() || name != std::to_string(keycode)) {
                throw std::invalid_argument("key must be a canonical decimal code between 0 and 65535");
            }
            if (!value.is_object()) {
                throw std::invalid_argument("binding must be an object");
            }
            const auto& action = value.at("action").get_ref<const std::string&>();
            KeyBinding binding;
            if (action == "pass") {
                binding.action = BindingAction::Pass;
            } else if (action == "ignore") {
                binding.action = BindingAction::Ignore;
            } else if (action == "replace") {
                const auto& replacement = value.at("keycode");
                if (!replacement.is_number_integer() || replacement < 0 ||
                    replacement > std::numeric_limits<std::uint16_t>::max()) {
                    throw std::invalid_argument("replacement keycode must be an integer between 0 and 65535");
                }
                binding.action = BindingAction::Replace;
                binding.replacement = replacement.get<int>();
            } else if (action == "exec") {
                binding.action = BindingAction::Exec;
                binding.payload = value.at("command").get<std::string>();
                if (binding.payload.empty() || binding.payload.find('\0') != std::string::npos) {
                    throw std::invalid_argument("command must be nonempty and contain no NUL bytes");
                }
            } else if (action == "launch") {
                binding.action = BindingAction::Launch;
                const auto& id = value.at("id").get_ref<const std::string&>();
                if (id.empty() || id.find('\0') != std::string::npos) {
                    throw std::invalid_argument("app id must be nonempty and contain no NUL bytes");
                }
                nlohmann::json request{{"id", id}};
                if (const auto params = value.find("params"); params != value.end()) {
                    if (!params->is_object()) {
                        throw std::invalid_argument("app params must be an object");
                    }
                    request["params"] = *params;
                }
                binding.payload = request.dump();
            } else {
                throw std::invalid_argument("unknown action");
            }
            bindings.emplace(keycode, std::move(binding));
        } catch (const nlohmann::json::exception& error) {
            return std::unexpected(std::format("Invalid binding '{}': {}", name, error.what()));
        } catch (const std::invalid_argument& error) {
            return std::unexpected(std::format("Invalid binding '{}': {}", name, error.what()));
        }
    }
    return bindings;
}
