/*
 * Browser to Mac Keycode Conversion
 *
 * Converts JavaScript keyCode values to Mac ADB scancodes.
 * This mapping moved from emulator to server per architecture v4.
 */

#ifndef KEYCODE_MAP_H
#define KEYCODE_MAP_H

// Convert browser keycode to Mac ADB keycode
// Returns -1 if keycode is not recognized
int browser_to_mac_keycode(int keycode);

#endif // KEYCODE_MAP_H
