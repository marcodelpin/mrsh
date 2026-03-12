/**
 * RSH Plugin Interface v1.0
 *
 * This header defines the interface for RSH (Remote Shell) plugins.
 * Plugins are Windows DLLs that export specific functions to extend
 * RSH functionality with custom commands.
 *
 * Required exports:
 *   - RSH_GetPluginInfo: Returns plugin metadata as JSON
 *   - RSH_Execute: Executes plugin commands
 *
 * Optional exports:
 *   - RSH_Initialize: Called when plugin is loaded
 *   - RSH_Shutdown: Called when plugin is unloaded
 *
 * Example plugin implementation:
 * @code
 * #include "rsh_plugin.h"
 * #include <stdio.h>
 * #include <string.h>
 *
 * RSH_API int RSH_GetPluginInfo(char* buffer, uint32_t* bufferLen) {
 *     const char* info = "{"
 *         "\"name\":\"example\","
 *         "\"version\":\"1.0.0\","
 *         "\"description\":\"Example plugin\","
 *         "\"commands\":[\"hello\",\"echo\"],"
 *         "\"author\":\"Your Name\""
 *     "}";
 *     size_t len = strlen(info);
 *     if (len >= *bufferLen) return -1;
 *     strcpy(buffer, info);
 *     *bufferLen = (uint32_t)len;
 *     return 0;
 * }
 *
 * RSH_API int RSH_Execute(const char* request, uint32_t reqLen,
 *                         char* response, uint32_t* respLen) {
 *     // Parse JSON request, execute command, write JSON response
 *     // Return 0 on success, non-zero on error
 *     return 0;
 * }
 * @endcode
 *
 * Build with: cl /LD example_plugin.c /Fe:example.dll
 */

#ifndef RSH_PLUGIN_H
#define RSH_PLUGIN_H

#include <stdint.h>

#ifdef _WIN32
    #ifdef RSH_PLUGIN_EXPORTS
        #define RSH_API __declspec(dllexport)
    #else
        #define RSH_API __declspec(dllimport)
    #endif
#else
    #define RSH_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get plugin information as JSON.
 *
 * The JSON must include these fields:
 *   - name (string): Plugin identifier (used for unload)
 *   - version (string): Plugin version (semver recommended)
 *   - description (string): Brief description
 *   - commands (array of strings): Commands this plugin handles
 *   - author (string, optional): Plugin author
 *
 * @param buffer Output buffer for JSON string (UTF-8, null-terminated)
 * @param bufferLen In: buffer size, Out: actual JSON length (excluding null)
 * @return 0 on success, non-zero on error
 */
RSH_API int RSH_GetPluginInfo(char* buffer, uint32_t* bufferLen);

/**
 * Execute a plugin command.
 *
 * Request JSON format:
 * {
 *   "command": "command_name",
 *   "args": ["arg1", "arg2", ...]
 * }
 *
 * Response JSON format:
 * {
 *   "success": true/false,
 *   "output": "result string",
 *   "error": "error message if success=false",
 *   "data": "optional base64 binary data"
 * }
 *
 * @param request JSON request (UTF-8)
 * @param reqLen Request length in bytes
 * @param response Output buffer for JSON response (UTF-8)
 * @param respLen In: buffer size, Out: actual response length
 * @return 0 on success, non-zero on error
 */
RSH_API int RSH_Execute(const char* request, uint32_t reqLen,
                        char* response, uint32_t* respLen);

/**
 * Initialize the plugin (optional).
 * Called once when the plugin is loaded.
 *
 * @return 0 on success, non-zero on error (plugin will still load)
 */
RSH_API int RSH_Initialize(void);

/**
 * Shutdown the plugin (optional).
 * Called when the plugin is unloaded.
 */
RSH_API void RSH_Shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* RSH_PLUGIN_H */
