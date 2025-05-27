#pragma once

#include <cstdint>
#include <string>
#include <nlohmann/json.hpp>
#include <string_view>
#include <mutex>

extern "C" {
#include "ezinject_module.h"
#include <gum/gum.h>
}

typedef struct {
    int unk1[4];
    int uinput_code;
    int unk2[9];
} keybind_info_t;

typedef struct {
    int fd;
    keybind_info_t* keybinds;
} uinput_info_t;

typedef struct {
    uint64_t time;
    uint16_t type;
    uint16_t code;
    int32_t value;
} input_event_t;

enum class Action {
    REPLACE,
    PASS,
    IGNORE,
};

class InputHook {
    using lginput_uinput_send_button_t = int(uinput_info_t*, int, int);
    using MICOM_FuncWriteKeyEvent_t = int(int, uint16_t, uint16_t, int32_t);
    using write_t = ssize_t(int, input_event_t*, size_t);

    static constexpr std::string_view CONFIG_LOCATION = "/home/root/.config/lginputhook/keybinds.json";

public:
    explicit InputHook();

private:
    void resolveFunctions();

    void applyHooks();

    bool loadKeybinds();

    void launch(const std::string& cmd);

    [[noreturn]] void watchConfigFile();

    std::tuple<Action, int> handleKey(int keycode, int state);

    static ssize_t trampoline_write(int fd, input_event_t* events, size_t count);

    static int trampoline_lginput(uinput_info_t* info, int keyid, int state);

    static int trampoline_MICOM_FuncWriteKeyEvent(int fd, uint16_t type, uint16_t code, int32_t value);

    int hook_lginput(uinput_info_t* info, int keyid, int state);

    int hook_MICOM_FuncWriteKeyEvent(int fd, uint16_t type, uint16_t code, int32_t value);

    ssize_t hook_write(int fd, input_event_t* events, size_t count);

    GumInterceptor* m_interceptor{nullptr};
    nlohmann::json m_keybinds{};
    std::mutex m_mutex{};

    lginput_uinput_send_button_t* orig_lginput_uinput_send_button{nullptr};
    MICOM_FuncWriteKeyEvent_t* orig_MICOM_FuncWriteKeyEvent{nullptr};
    write_t* orig_write{nullptr};
};
