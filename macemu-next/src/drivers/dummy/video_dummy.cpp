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
#include "video.h"
#include "video_defs.h"

#define DEBUG 0
#include "debug.h"


// Dummy framebuffer
static uint8 *the_buffer = NULL;
static uint32 the_buffer_size = 0;


/*
 *  Initialization
 */

bool VideoInit(bool classic)
{
	// Create a dummy 640x480x8 framebuffer
	const int width = 640;
	const int height = 480;
	const int depth = VIDEO_DEPTH_8BIT;

	// Allocate framebuffer
	the_buffer_size = width * height;
	the_buffer = (uint8 *)malloc(the_buffer_size);
	if (!the_buffer)
		return false;

	memset(the_buffer, 0, the_buffer_size);

	// Set up video mode
	VideoMonitor.mode = {
		width,
		height,
		depth,
		VMODE_VALID
	};

	VideoMonitor.mac_frame_base = Host2MacAddr(the_buffer);

	// Add this mode to available modes
	VideoModes.push_back(VideoMonitor.mode);

	D(bug("Video: Dummy 640x480x8 framebuffer initialized\n"));
	return true;
}


/*
 *  Deinitialization
 */

void VideoExit(void)
{
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
