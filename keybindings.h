#pragma once

#include <nlohmann/json_fwd.hpp>

#include <expected>
#include <string>
#include <unordered_map>

enum class BindingAction { Pass, Ignore, Replace, Exec, Launch };

struct KeyBinding {
    BindingAction action = BindingAction::Pass;
    int replacement = 0;
    // Shell command for Exec, serialized Luna request for Launch.
    std::string payload;
};

using KeyBindings = std::unordered_map<int, KeyBinding>;

[[nodiscard]] std::expected<KeyBindings, std::string> compileKeybindings(const nlohmann::json& json);
