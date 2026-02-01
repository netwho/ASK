# Installing JSON Library for Wireshark Lua

The ASK (Analyst's Shark Knife) plugin works with the built-in simple JSON parser, but installing a proper JSON library will significantly improve parsing of complex JSON responses (especially for urlscan.io and other APIs with nested arrays).

## Quick Install (Recommended)

**macOS/Linux:**
```bash
chmod +x install_json_library.sh
./install_json_library.sh
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File install_json_library.ps1
```

## Manual Installation

### Recommended: json.lua (rxi/json.lua)

**json.lua** is a lightweight, pure-Lua JSON library that works perfectly with Wireshark. It's a single file with no dependencies.

- **Author:** rxi
- **Repository:** https://github.com/rxi/json.lua
- **License:** MIT License
- **Description:** A lightweight JSON library for Lua, written in pure Lua with no dependencies

### Installation Steps

#### macOS/Linux

1. **Download json.lua:**
   ```bash
   cd ~/.local/lib/wireshark/plugins
   curl -O https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
   ```

2. **Verify installation:**
   ```bash
   ls -la ~/.local/lib/wireshark/plugins/json.lua
   ```

3. **Restart Wireshark**

#### Windows

1. **Download json.lua:**
   - Open: https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
   - Save the file as `json.lua`

2. **Copy to Wireshark plugins directory:**
   ```cmd
   copy json.lua %APPDATA%\Wireshark\plugins\
   ```

3. **Restart Wireshark**

### Alternative: Manual Installation

If the above doesn't work, you can place `json.lua` in any of these locations:

**macOS/Linux:**
- `~/.local/lib/wireshark/plugins/json.lua` (Personal plugins)
- `~/.config/wireshark/plugins/json.lua` (Alternative personal location)
- `/usr/local/lib/wireshark/plugins/json.lua` (System-wide, requires sudo)

**Windows:**
- `%APPDATA%\Wireshark\plugins\json.lua` (Personal plugins)
- `%PROGRAMFILES%\Wireshark\plugins\json.lua` (System-wide, requires admin)

### Verification

After installing and restarting Wireshark:

1. Open Wireshark
2. Go to `Help → About Wireshark → Plugins`
3. Look for `json.lua` in the list
4. Or check the console for: `[ASK] JSON library loaded successfully`

The plugin will automatically detect and use the JSON library if available. You should see improved parsing for:
- urlscan.io search results (arrays of objects)
- Complex RDAP responses
- VirusTotal responses with nested structures
- Any API with complex JSON structures

### Troubleshooting

**Library not loading?**
- Check file is named exactly `json.lua` (lowercase)
- Verify it's in the correct plugins directory
- Check Wireshark console for error messages
- Ensure file has read permissions

**Still using simple parser?**
- Check Wireshark console logs - it will show if JSON library is available
- The plugin falls back to simple parser if library fails to load
- Try restarting Wireshark after installation

### Other JSON Libraries

If `json.lua` doesn't work for you, other options include:

- **dkjson** - Another pure-Lua JSON library
- **lunajson** - Fast JSON library (may require compilation)

However, `json.lua` (rxi/json.lua) is recommended because:
- Single file, no dependencies
- Pure Lua (no C extensions)
- Works with all Wireshark Lua environments
- Actively maintained
- Small footprint

## Benefits

With a proper JSON library installed:
- ✅ Full parsing of urlscan.io search results
- ✅ Better handling of nested JSON structures
- ✅ More reliable parsing of all API responses
- ✅ Faster parsing performance
- ✅ Better error messages

Without a JSON library:
- ⚠️ Simple parser works for basic JSON
- ⚠️ May struggle with arrays of objects
- ⚠️ Some complex responses may not parse correctly
