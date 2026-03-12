/**
 * RSH Example Plugin
 *
 * Demonstrates how to create an RSH plugin.
 * Build with: cl /LD /DRSH_PLUGIN_EXPORTS example_plugin.c /Fe:example.dll
 *
 * Commands:
 *   - hello: Returns a greeting
 *   - echo: Echoes back the arguments
 *   - time: Returns current time
 */

#define RSH_PLUGIN_EXPORTS
#include "rsh_plugin.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>

// Simple JSON helpers (no external dependencies)
static const char* find_json_string(const char* json, const char* key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char* start = strstr(json, search);
    if (!start) return NULL;
    return start + strlen(search);
}

static int extract_json_string(const char* json, const char* key, char* out, size_t outLen) {
    const char* start = find_json_string(json, key);
    if (!start) return -1;

    size_t i = 0;
    while (start[i] && start[i] != '"' && i < outLen - 1) {
        out[i] = start[i];
        i++;
    }
    out[i] = '\0';
    return 0;
}

// Parse args array from JSON (simplified)
static int parse_args(const char* json, char args[][256], int maxArgs) {
    const char* argsStart = strstr(json, "\"args\":[");
    if (!argsStart) return 0;

    argsStart = strchr(argsStart, '[');
    if (!argsStart) return 0;
    argsStart++;

    int count = 0;
    while (*argsStart && *argsStart != ']' && count < maxArgs) {
        // Skip whitespace
        while (*argsStart == ' ' || *argsStart == ',') argsStart++;
        if (*argsStart == ']') break;

        // Parse string
        if (*argsStart == '"') {
            argsStart++;
            int i = 0;
            while (*argsStart && *argsStart != '"' && i < 255) {
                args[count][i++] = *argsStart++;
            }
            args[count][i] = '\0';
            if (*argsStart == '"') argsStart++;
            count++;
        } else {
            break;
        }
    }
    return count;
}

RSH_API int RSH_GetPluginInfo(char* buffer, uint32_t* bufferLen) {
    const char* info =
        "{"
        "\"name\":\"example\","
        "\"version\":\"1.0.0\","
        "\"description\":\"Example RSH plugin demonstrating the plugin API\","
        "\"commands\":[\"hello\",\"echo\",\"time\",\"sysinfo\"],"
        "\"author\":\"RSH Development Team\""
        "}";

    size_t len = strlen(info);
    if (len >= *bufferLen) {
        *bufferLen = (uint32_t)(len + 1);
        return -1;  // Buffer too small
    }

    strcpy(buffer, info);
    *bufferLen = (uint32_t)len;
    return 0;
}

RSH_API int RSH_Initialize(void) {
    // Initialization code here
    // Return 0 on success
    return 0;
}

RSH_API void RSH_Shutdown(void) {
    // Cleanup code here
}

RSH_API int RSH_Execute(const char* request, uint32_t reqLen,
                        char* response, uint32_t* respLen) {
    char command[64] = {0};
    char args[10][256] = {0};

    // Parse command from request
    if (extract_json_string(request, "command", command, sizeof(command)) != 0) {
        snprintf(response, *respLen,
            "{\"success\":false,\"error\":\"Missing command in request\"}");
        *respLen = (uint32_t)strlen(response);
        return 0;
    }

    int argCount = parse_args(request, args, 10);

    // Handle commands
    if (strcmp(command, "hello") == 0) {
        const char* name = argCount > 0 ? args[0] : "World";
        snprintf(response, *respLen,
            "{\"success\":true,\"output\":\"Hello, %s! This is the example plugin.\"}",
            name);
    }
    else if (strcmp(command, "echo") == 0) {
        char output[4096] = "";
        for (int i = 0; i < argCount; i++) {
            if (i > 0) strcat(output, " ");
            strcat(output, args[i]);
        }
        snprintf(response, *respLen,
            "{\"success\":true,\"output\":\"%s\"}", output);
    }
    else if (strcmp(command, "time") == 0) {
        time_t now = time(NULL);
        struct tm* tm = localtime(&now);
        char timeStr[64];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tm);
        snprintf(response, *respLen,
            "{\"success\":true,\"output\":\"%s\"}", timeStr);
    }
    else if (strcmp(command, "sysinfo") == 0) {
        char computerName[256] = "";
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);

        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        snprintf(response, *respLen,
            "{\"success\":true,\"output\":\"Computer: %s\\nProcessors: %d\\nMemory: %llu MB total, %llu MB free\"}",
            computerName,
            sysInfo.dwNumberOfProcessors,
            memStatus.ullTotalPhys / (1024 * 1024),
            memStatus.ullAvailPhys / (1024 * 1024));
    }
    else {
        snprintf(response, *respLen,
            "{\"success\":false,\"error\":\"Unknown command: %s\"}", command);
    }

    *respLen = (uint32_t)strlen(response);
    return 0;
}
