/*
 *  video_dummy.cpp - Video/graphics emulation, dummy implementation
 *
 *  Basilisk II (C) 1997-2008 Christian Bauer
 *  macemu-next adaptation (C) 2025
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

#include "sysdeps.h"
#include "cpu_emulation.h"
#include "video.h"
#include "video_defs.h"

#define DEBUG 0
#include "debug.h"


// Dummy framebuffer
static uint8 *the_buffer = NULL;
static uint32 the_buffer_size = 0;

// Dummy monitor descriptor
class dummy_monitor_desc : public monitor_desc {
public:
	dummy_monitor_desc(const vector<video_mode> &available_modes, video_depth default_depth, uint32 default_id)
		: monitor_desc(available_modes, default_depth, default_id) {}
	~dummy_monitor_desc() {}

	// Implement pure virtual functions
	void switch_to_current_mode(void) { /* Dummy - nothing to switch */ }
	void set_palette(uint8 *pal, int num) { /* Dummy - ignore palette */ }
	void set_gamma(uint8 *gamma, int num) { /* Dummy - ignore gamma */ }
};


/*
 *  Initialization
 */

bool VideoInit(bool classic)
{
	// Create a dummy 640x480x8 framebuffer
	const int width = 640;
	const int height = 480;
	const video_depth depth = VDEPTH_8BIT;
	const uint32 resolution_id = 0x80;  // Standard resolution ID

	// Allocate framebuffer
	the_buffer_size = width * height;
	the_buffer = (uint8 *)malloc(the_buffer_size);
	if (!the_buffer)
		return false;

	memset(the_buffer, 0, the_buffer_size);

	// Build list of supported video modes
	vector<video_mode> modes;
	video_mode mode;
	mode.x = width;
	mode.y = height;
	mode.resolution_id = resolution_id;
	mode.depth = depth;
	mode.bytes_per_row = width;  // 8-bit depth = 1 byte per pixel
	mode.user_data = 0;
	modes.push_back(mode);

	// Create monitor descriptor
	dummy_monitor_desc *monitor = new dummy_monitor_desc(modes, depth, resolution_id);

	// Set Mac frame buffer address
	monitor->set_mac_frame_base(Host2MacAddr(the_buffer));

	// Add to global monitor list
	VideoMonitors.push_back(monitor);

	D(bug("Video: Dummy 640x480x8 framebuffer initialized\n"));
	return true;
}


/*
 *  Deinitialization
 */

void VideoExit(void)
{
	// Delete monitor descriptors
	vector<monitor_desc *>::iterator i, end = VideoMonitors.end();
	for (i = VideoMonitors.begin(); i != end; ++i)
		delete *i;
	VideoMonitors.clear();

	// Free framebuffer
	if (the_buffer) {
		free(the_buffer);
		the_buffer = NULL;
	}
}


/*
 *  Set palette
 */

void video_set_palette(uint8 *pal, int num)
{
	// Dummy - ignore palette changes
}


/*
 *  Video refresh (called from 60Hz timer)
 */

void VideoRefresh(void)
{
	// Dummy - no actual display update
}


/*
 *  Video VBL interrupt
 */

void VideoVBL(void)
{
	// Dummy - no VBL processing needed
}


/*
 *  Set video mode
 */

void video_set_dirty_area(int x, int y, int w, int h)
{
	// Dummy - ignore dirty regions
}


/*
 *  Close video mode
 */

void video_close(void)
{
	// Dummy - nothing to close
}
