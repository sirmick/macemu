/*
 *  video_headless.cpp - Headless video driver for WebSocket-only streaming
 *
 *  Basilisk II (C) 1997-2008 Christian Bauer
 *  Headless mode (C) 2024
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *  NOTES:
 *    This is a headless video driver that renders to a memory buffer
 *    and streams frames via WebSocket. No display server (X11/Wayland)
 *    or SDL is required.
 *
 *    Input is handled via WebSocket only.
 */

#include "sysdeps.h"

#ifdef ENABLE_HEADLESS

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

#include "cpu_emulation.h"
#include "main.h"
#include "adb.h"
#include "macos_util.h"
#include "prefs.h"
#include "user_strings.h"
#include "video.h"
#include "video_defs.h"
#include "video_blit.h"
#include "vm_alloc.h"

#ifdef ENABLE_WEBSTREAMING
#include "basilisk_integration.h"
#endif

#define DEBUG 0
#include "debug.h"

// Forward declarations
static bool Headless_VideoInit(bool classic);
static void Headless_VideoExit(void);
static void Headless_VideoQuitFullScreen(void);
static void Headless_VideoInterrupt(void);
static void Headless_VideoRefresh(void);

// Supported video modes
using std::vector;
static vector<VIDEO_MODE> VideoModes;

// Mac Screen Width and Height
// When USE_SDL_VIDEO is defined, these are defined in video_sdl2.cpp
#ifdef USE_SDL_VIDEO
extern uint32 MacScreenWidth;
extern uint32 MacScreenHeight;
#else
uint32 MacScreenWidth;
uint32 MacScreenHeight;
#endif

// Global variables
static uint32 frame_skip;
static uint8 *the_buffer = NULL;           // Mac frame buffer (where MacOS draws into)
static uint32 the_buffer_size;             // Size of allocated the_buffer
static bool classic_mode = false;          // Flag: Classic Mac video mode

// Frame buffer properties
static int frame_width = 640;
static int frame_height = 480;
static int frame_depth = 32;               // Bits per pixel
static int frame_bytes_per_row;

// Threading
static std::thread video_thread;
static std::atomic<bool> video_thread_running(false);
static std::mutex frame_mutex;

// RGBA conversion buffer for streaming
static std::vector<uint8_t> rgba_buffer;

// Palette for indexed color modes
static uint8 headless_palette[256 * 3];


/*
 *  Framebuffer allocation routines
 *
 *  CRITICAL: We allocate ONE persistent buffer at startup and NEVER change its address.
 *  This is because Mac OS initializes GDevice structures with the frame buffer address
 *  during boot, and doesn't properly update them on all mode switches. By keeping
 *  the address constant (like real video hardware VRAM), we avoid synchronization issues.
 */

// Persistent buffer - allocated once, never freed until VideoExit
static uint8 *persistent_buffer = NULL;
static uint32 persistent_buffer_size = 0;
static uint32 persistent_mac_addr = 0;

static bool allocate_framebuffer(uint32 width, uint32 height, video_depth depth, uint32 mode_bytes_per_row = 0)
{
	// Use mode's bytes_per_row if provided, otherwise calculate it
	uint32 trivial_bpr = TrivialBytesPerRow(width, depth);
	if (mode_bytes_per_row > 0) {
		frame_bytes_per_row = mode_bytes_per_row;
	} else {
		frame_bytes_per_row = trivial_bpr;
	}

	uint32 needed_size = frame_bytes_per_row * height;

	// If persistent buffer exists and is large enough, reuse it
	if (persistent_buffer != NULL && persistent_buffer_size >= needed_size) {
		the_buffer = persistent_buffer;
		the_buffer_size = needed_size;
	} else {
		// Free old buffer if it exists but is too small
		if (persistent_buffer != NULL) {
			vm_release(persistent_buffer, persistent_buffer_size);
			persistent_buffer = NULL;
		}

		// Calculate max buffer size we might need (1024x768 @ 32bpp is largest mode)
		uint32 max_size = 1024 * 768 * 4;  // 3MB should be enough for any mode
		if (needed_size > max_size) max_size = needed_size;

		// Allocate new persistent buffer
		persistent_buffer = (uint8 *)vm_acquire(max_size, VM_MAP_DEFAULT | VM_MAP_32BIT);
		if (persistent_buffer == VM_MAP_FAILED || persistent_buffer == NULL) {
			fprintf(stderr, "Headless: Failed to allocate frame buffer\n");
			return false;
		}
		persistent_buffer_size = max_size;
		persistent_mac_addr = Host2MacAddr(persistent_buffer);

		the_buffer = persistent_buffer;
		the_buffer_size = needed_size;
	}

	// Clear to gray initially, Mac will draw desktop pattern
	memset(the_buffer, 0x80, the_buffer_size);

	// Allocate/resize RGBA conversion buffer for streaming
	rgba_buffer.resize(width * height * 4);

	frame_width = width;
	frame_height = height;
	// Convert video_depth enum to actual bits per pixel
	switch (depth) {
		case VDEPTH_1BIT:  frame_depth = 1; break;
		case VDEPTH_2BIT:  frame_depth = 2; break;
		case VDEPTH_4BIT:  frame_depth = 4; break;
		case VDEPTH_8BIT:  frame_depth = 8; break;
		case VDEPTH_16BIT: frame_depth = 16; break;
		case VDEPTH_32BIT: frame_depth = 32; break;
		default:           frame_depth = 8; break;
	}

	return true;
}

static void free_framebuffer()
{
	// Don't free persistent buffer - just clear the_buffer pointer
	// The persistent buffer stays allocated until VideoExit
	the_buffer = NULL;
	the_buffer_size = 0;
	rgba_buffer.clear();
}

static void free_persistent_buffer()
{
	if (persistent_buffer && persistent_buffer != VM_MAP_FAILED) {
		vm_release(persistent_buffer, persistent_buffer_size);
		persistent_buffer = NULL;
		persistent_buffer_size = 0;
		persistent_mac_addr = 0;
	}
}


/*
 *  Convert frame buffer to RGBA for streaming
 */

static void convert_to_rgba()
{
	if (!the_buffer || rgba_buffer.empty()) return;

	std::lock_guard<std::mutex> lock(frame_mutex);

	uint8_t *dst = rgba_buffer.data();
	uint8_t *src = the_buffer;

	switch (frame_depth) {
		case 32:
			// Mac stores 32-bit pixels as big-endian ARGB: bytes [A,R,G,B]
			// On x86 (little-endian), we need to read bytes directly
			for (int y = 0; y < frame_height; y++) {
				uint8_t *src_row = src + y * frame_bytes_per_row;
				for (int x = 0; x < frame_width; x++) {
					// Mac big-endian ARGB: byte 0=A, 1=R, 2=G, 3=B
					uint8_t *pixel = src_row + x * 4;
					*dst++ = pixel[1];  // R
					*dst++ = pixel[2];  // G
					*dst++ = pixel[3];  // B
					*dst++ = 0xFF;      // A (ignore Mac's alpha)
				}
			}
			break;

		case 16:
			// Mac stores 16-bit pixels as big-endian RGB555
			for (int y = 0; y < frame_height; y++) {
				uint8_t *src_row = src + y * frame_bytes_per_row;
				for (int x = 0; x < frame_width; x++) {
					// Big-endian: high byte first
					uint8_t *pb = src_row + x * 2;
					uint16_t pixel = (pb[0] << 8) | pb[1];
					// RGB555: bit 15 unused, bits 14-10=R, 9-5=G, 4-0=B
					*dst++ = ((pixel >> 10) & 0x1F) << 3;  // R
					*dst++ = ((pixel >> 5) & 0x1F) << 3;   // G
					*dst++ = (pixel & 0x1F) << 3;          // B
					*dst++ = 0xFF;                          // A
				}
			}
			break;

		case 8:
			// Indexed color -> RGBA via palette
			for (int y = 0; y < frame_height; y++) {
				uint8_t *src_row = src + y * frame_bytes_per_row;
				for (int x = 0; x < frame_width; x++) {
					uint8_t idx = src_row[x];
					*dst++ = headless_palette[idx * 3];      // R
					*dst++ = headless_palette[idx * 3 + 1];  // G
					*dst++ = headless_palette[idx * 3 + 2];  // B
					*dst++ = 0xFF;                            // A
				}
			}
			break;

		case 4:
			// 4-bit indexed color (16 colors) - 2 pixels per byte
			for (int y = 0; y < frame_height; y++) {
				uint8_t *src_row = src + y * frame_bytes_per_row;
				for (int x = 0; x < frame_width; x++) {
					int byte_idx = x / 2;
					int nibble = (x & 1) ? (src_row[byte_idx] & 0x0F) : ((src_row[byte_idx] >> 4) & 0x0F);
					*dst++ = headless_palette[nibble * 3];      // R
					*dst++ = headless_palette[nibble * 3 + 1];  // G
					*dst++ = headless_palette[nibble * 3 + 2];  // B
					*dst++ = 0xFF;                               // A
				}
			}
			break;

		case 2:
			// 2-bit indexed color (4 colors) - 4 pixels per byte
			for (int y = 0; y < frame_height; y++) {
				uint8_t *src_row = src + y * frame_bytes_per_row;
				for (int x = 0; x < frame_width; x++) {
					int byte_idx = x / 4;
					int shift = 6 - (x & 3) * 2;  // 6, 4, 2, 0
					int idx = (src_row[byte_idx] >> shift) & 0x03;
					*dst++ = headless_palette[idx * 3];      // R
					*dst++ = headless_palette[idx * 3 + 1];  // G
					*dst++ = headless_palette[idx * 3 + 2];  // B
					*dst++ = 0xFF;                            // A
				}
			}
			break;

		case 1:
			// 1-bit indexed color (2 colors) - 8 pixels per byte
			for (int y = 0; y < frame_height; y++) {
				uint8_t *src_row = src + y * frame_bytes_per_row;
				for (int x = 0; x < frame_width; x++) {
					int byte_idx = x / 8;
					int bit = 7 - (x & 7);  // MSB first
					int idx = (src_row[byte_idx] >> bit) & 0x01;
					*dst++ = headless_palette[idx * 3];      // R
					*dst++ = headless_palette[idx * 3 + 1];  // G
					*dst++ = headless_palette[idx * 3 + 2];  // B
					*dst++ = 0xFF;                            // A
				}
			}
			break;

		default:
			// Fallback: should not happen, fill with magenta to make it obvious
			for (int i = 0; i < frame_width * frame_height; i++) {
				*dst++ = 0xFF;  // R
				*dst++ = 0x00;  // G
				*dst++ = 0xFF;  // B
				*dst++ = 0xFF;  // A
			}
			break;
	}
}


/*
 *  Video refresh thread - streams frames to WebSocket clients
 */

static void video_refresh_thread()
{
	auto last_frame_time = std::chrono::steady_clock::now();
	int target_fps = 30;  // Target frame rate for streaming

	while (video_thread_running) {
		auto now = std::chrono::steady_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_frame_time);

		// Rate limit to target FPS
		int frame_interval = 1000 / target_fps;
		if (elapsed.count() < frame_interval) {
			std::this_thread::sleep_for(std::chrono::milliseconds(frame_interval - elapsed.count()));
			continue;
		}

		last_frame_time = now;

#ifdef ENABLE_WEBSTREAMING
		// Only convert and send if we have clients
		if (ws_streaming_enabled() && ws_streaming_client_count() > 0) {
			convert_to_rgba();
			ws_streaming_send_frame(rgba_buffer.data(), frame_width, frame_height,
			                        frame_width * 4);
		}
#endif
	}
}


/*
 *  Headless monitor descriptor
 */

class Headless_monitor_desc : public monitor_desc {
public:
	Headless_monitor_desc(const vector<video_mode> &available_modes,
	                      video_depth default_depth, uint32 default_id)
		: monitor_desc(available_modes, default_depth, default_id) {}
	~Headless_monitor_desc() {}

	virtual void switch_to_current_mode(void);
	virtual void set_palette(uint8 *pal, int num);
	virtual void set_gamma(uint8 *gamma, int num);

	void video_close(void);
};

// Global monitor
static Headless_monitor_desc *the_monitor = NULL;


/*
 *  Switch to current video mode
 */

void Headless_monitor_desc::switch_to_current_mode(void)
{
	const video_mode &mode = get_current_mode();

	// Free existing buffer
	free_framebuffer();

	// Allocate new buffer - pass mode.bytes_per_row to ensure consistency
	if (!allocate_framebuffer(mode.x, mode.y, mode.depth, mode.bytes_per_row)) {
		fprintf(stderr, "Headless: Failed to allocate frame buffer for mode %dx%d\n",
		        mode.x, mode.y);
		return;
	}

	// Set Mac frame buffer base
	uint32 mac_addr = (uint32)Host2MacAddr(the_buffer);
	set_mac_frame_base(mac_addr);

	// Update global screen dimensions
	MacScreenWidth = mode.x;
	MacScreenHeight = mode.y;
}


/*
 *  Set color palette
 */

void Headless_monitor_desc::set_palette(uint8 *pal, int num)
{
	std::lock_guard<std::mutex> lock(frame_mutex);

	// Copy palette entries to global palette
	for (int i = 0; i < num; i++) {
		headless_palette[i * 3] = pal[i * 3];
		headless_palette[i * 3 + 1] = pal[i * 3 + 1];
		headless_palette[i * 3 + 2] = pal[i * 3 + 2];
	}
}


/*
 *  Set gamma table (not used in headless mode)
 */

void Headless_monitor_desc::set_gamma(uint8 *gamma, int num)
{
	// Gamma correction not implemented for headless mode
	// Could be applied during RGBA conversion if needed
}


/*
 *  Close video
 */

void Headless_monitor_desc::video_close(void)
{
	// Stop video thread
	video_thread_running = false;
	if (video_thread.joinable()) {
		video_thread.join();
	}

	// Free frame buffer
	free_framebuffer();
}


/*
 *  Initialization
 */

static void add_mode(uint32 width, uint32 height, uint32 resolution_id,
                     uint32 bytes_per_row, video_depth depth)
{
	video_mode mode;
	mode.x = width;
	mode.y = height;
	mode.resolution_id = resolution_id;
	mode.bytes_per_row = bytes_per_row;
	mode.depth = depth;
	VideoModes.push_back(mode);
}

static void add_standard_modes(uint32 width, uint32 height, uint32 resolution_id)
{
	// Add modes at ALL depths - Mac OS may switch to any of these
	// Must match what SDL provides for consistent behavior
	add_mode(width, height, resolution_id,
	         TrivialBytesPerRow(width, VDEPTH_1BIT), VDEPTH_1BIT);
	add_mode(width, height, resolution_id,
	         TrivialBytesPerRow(width, VDEPTH_2BIT), VDEPTH_2BIT);
	add_mode(width, height, resolution_id,
	         TrivialBytesPerRow(width, VDEPTH_4BIT), VDEPTH_4BIT);
	add_mode(width, height, resolution_id,
	         TrivialBytesPerRow(width, VDEPTH_8BIT), VDEPTH_8BIT);
	add_mode(width, height, resolution_id,
	         TrivialBytesPerRow(width, VDEPTH_16BIT), VDEPTH_16BIT);
	add_mode(width, height, resolution_id,
	         TrivialBytesPerRow(width, VDEPTH_32BIT), VDEPTH_32BIT);
}

// Provide VideoInit when building headless (without SDL video)
#ifndef USE_SDL_VIDEO

#ifdef SHEEPSHAVER
bool VideoInit(void)
{
	const bool classic = false;
#else
bool VideoInit(bool classic)
{
#endif
	return Headless_VideoInit(classic);
}

#endif // !USE_SDL_VIDEO

// Headless video initialization - called from VideoInit
static bool Headless_VideoInit(bool classic)
{
	classic_mode = classic;

#ifdef ENABLE_WEBSTREAMING
	// Initialize WebSocket streaming
	int ws_port = PrefsFindInt32("webstreamingport");
	if (ws_port <= 0) ws_port = 8090;

	if (!ws_streaming_init(ws_port)) {
		fprintf(stderr, "Headless: WebSocket streaming failed to initialize\n");
		return false;
	}

	// Set up input callbacks from WebSocket to ADB
	ws_set_input_callbacks(
		// Mouse move callback
		[](int x, int y) {
			ADBMouseMoved(x, y);
		},
		// Mouse button callback
		[](int x, int y, int button, bool pressed) {
			ADBMouseMoved(x, y);
			if (pressed) {
				ADBMouseDown(button);
			} else {
				ADBMouseUp(button);
			}
		},
		// Key callback
		[](int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta) {
			int mac_code = -1;

			// Convert browser keycode to Mac ADB keycode
			if (keycode >= 65 && keycode <= 90) {
				// A-Z
				static const int letter_map[] = {
					0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04,
					0x22, 0x26, 0x28, 0x25, 0x2E, 0x2D, 0x1F, 0x23,
					0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07,
					0x10, 0x06
				};
				mac_code = letter_map[keycode - 65];
			} else if (keycode >= 48 && keycode <= 57) {
				// 0-9
				static const int number_map[] = {
					0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19
				};
				mac_code = number_map[keycode - 48];
			} else {
				switch (keycode) {
					case 8: mac_code = 0x33; break;   // Backspace
					case 9: mac_code = 0x30; break;   // Tab
					case 13: mac_code = 0x24; break;  // Enter
					case 16: mac_code = 0x38; break;  // Shift
					case 17: mac_code = 0x36; break;  // Ctrl -> Command
					case 18: mac_code = 0x3A; break;  // Alt -> Option
					case 27: mac_code = 0x35; break;  // Escape
					case 32: mac_code = 0x31; break;  // Space
					case 37: mac_code = 0x3B; break;  // Left
					case 38: mac_code = 0x3E; break;  // Up
					case 39: mac_code = 0x3C; break;  // Right
					case 40: mac_code = 0x3D; break;  // Down
					case 46: mac_code = 0x75; break;  // Delete
					case 91: mac_code = 0x37; break;  // Meta -> Command
					case 186: mac_code = 0x29; break; // ;
					case 187: mac_code = 0x18; break; // =
					case 188: mac_code = 0x2B; break; // ,
					case 189: mac_code = 0x1B; break; // -
					case 190: mac_code = 0x2F; break; // .
					case 191: mac_code = 0x2C; break; // /
					case 192: mac_code = 0x32; break; // `
					case 219: mac_code = 0x21; break; // [
					case 220: mac_code = 0x2A; break; // backslash
					case 221: mac_code = 0x1E; break; // ]
					case 222: mac_code = 0x27; break; // '
					default: break;
				}
			}

			if (mac_code >= 0) {
				if (pressed) {
					ADBKeyDown(mac_code);
				} else {
					ADBKeyUp(mac_code);
				}
			}
		}
	);
#else
	fprintf(stderr, "Headless: ERROR - Built without WebSocket streaming support!\n");
	fprintf(stderr, "Headless: Rebuild with --enable-webstreaming\n");
	return false;
#endif

	// Read prefs
	frame_skip = PrefsFindInt32("frameskip");

	// Get screen mode from preferences
	int default_width = 640;
	int default_height = 480;
	const char *mode_str = PrefsFindString("screen");

	if (mode_str) {
		// Parse "win/W/H" or just "W/H"
		if (sscanf(mode_str, "win/%d/%d", &default_width, &default_height) != 2) {
			if (sscanf(mode_str, "dga/%d/%d", &default_width, &default_height) != 2) {
				sscanf(mode_str, "%d/%d", &default_width, &default_height);
			}
		}
	}

	// Clamp to reasonable values
	if (default_width < 512) default_width = 512;
	if (default_width > 2560) default_width = 2560;
	if (default_height < 384) default_height = 384;
	if (default_height > 1600) default_height = 1600;

	if (classic) {
		default_width = 512;
		default_height = 342;
	}

	// Initialize default palette - Mac uses inverted grayscale (0=white, 255=black)
	for (int i = 0; i < 256; i++) {
		headless_palette[i * 3] = 255 - i;
		headless_palette[i * 3 + 1] = 255 - i;
		headless_palette[i * 3 + 2] = 255 - i;
	}

	// Build list of video modes
	VideoModes.clear();

	if (classic) {
		// Classic mode: only 1-bit 512x342
		add_mode(512, 342, 0x80, 64, VDEPTH_1BIT);
	} else {
		// Add the default resolution
		add_standard_modes(default_width, default_height, 0x80);

		// Add some standard resolutions
		if (default_width != 640 || default_height != 480)
			add_standard_modes(640, 480, 0x81);
		if (default_width != 800 || default_height != 600)
			add_standard_modes(800, 600, 0x82);
		if (default_width != 1024 || default_height != 768)
			add_standard_modes(1024, 768, 0x83);
	}

	// Create monitor descriptor
	video_depth default_depth = classic ? VDEPTH_1BIT : VDEPTH_32BIT;
	uint32 default_bytes_per_row = TrivialBytesPerRow(default_width, default_depth);

	the_monitor = new Headless_monitor_desc(VideoModes, default_depth, 0x80);
	VideoMonitors.push_back(the_monitor);

	// Allocate initial frame buffer
	if (!allocate_framebuffer(default_width, default_height, default_depth, default_bytes_per_row)) {
		return false;
	}

	// Set Mac frame buffer base
	uint32 mac_frame_base = (uint32)Host2MacAddr(the_buffer);
	the_monitor->set_mac_frame_base(mac_frame_base);

	// Update global screen dimensions
	MacScreenWidth = default_width;
	MacScreenHeight = default_height;

	// Start video refresh thread
	video_thread_running = true;
	video_thread = std::thread(video_refresh_thread);

	return true;
}


/*
 *  Deinitialization
 */

// Provide VideoExit when building headless (without SDL video)
#ifndef USE_SDL_VIDEO
void VideoExit(void)
{
	Headless_VideoExit();
}
#endif

static void Headless_VideoExit(void)
{
#ifdef ENABLE_WEBSTREAMING
	ws_streaming_exit();
#endif

	// Close monitor
	if (the_monitor) {
		the_monitor->video_close();
	}

	// Free persistent buffer
	free_persistent_buffer();

	// Clear video modes
	VideoModes.clear();
}


/*
 *  Close down full-screen mode (if bringing up error alerts is unsafe)
 */

static void Headless_VideoQuitFullScreen(void)
{
	// Nothing to do in headless mode
}

#ifndef USE_SDL_VIDEO
void VideoQuitFullScreen(void)
{
	Headless_VideoQuitFullScreen();
}
#endif


/*
 *  Video interrupt (VBL)
 */

static void Headless_VideoInterrupt(void)
{
	// In headless mode, we don't need to do much here
	// The video refresh thread handles frame streaming
}

#ifndef USE_SDL_VIDEO
void VideoInterrupt(void)
{
	Headless_VideoInterrupt();
}
#endif


/*
 *  Video refresh
 */

static void Headless_VideoRefresh(void)
{
	// Nothing to do - handled by video thread
}

#ifndef USE_SDL_VIDEO
void VideoRefresh(void)
{
	Headless_VideoRefresh();
}
#endif

#endif // ENABLE_HEADLESS
