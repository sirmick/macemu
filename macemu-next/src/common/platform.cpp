/*
 *  platform.cpp - Platform initialization
 *
 *  Sets up global platform with null driver defaults.
 */

#include "platform.h"

/*
 *  Global platform instance
 */
extern "C" {
Platform g_platform;
}

/*
 *  Initialize platform with null drivers (safe defaults)
 */
void platform_init(void)
{
	// SCSI - null driver
	g_platform.scsi_init = scsi_null_init;
	g_platform.scsi_exit = scsi_null_exit;
	g_platform.scsi_set_cmd = scsi_null_set_cmd;
	g_platform.scsi_is_target_present = scsi_null_is_target_present;
	g_platform.scsi_set_target = scsi_null_set_target;
	g_platform.scsi_send_cmd = scsi_null_send_cmd;

	// Video - null driver
	g_platform.video_init = video_null_init;
	g_platform.video_exit = video_null_exit;
	g_platform.video_refresh = video_null_refresh;

	// Disk - null driver
	g_platform.disk_init = disk_null_init;
	g_platform.disk_exit = disk_null_exit;

	// Audio - null driver
	g_platform.audio_init = audio_null_init;
	g_platform.audio_exit = audio_null_exit;

	// Serial - null driver
	g_platform.serial_init = serial_null_init;
	g_platform.serial_exit = serial_null_exit;

	// Ether - null driver
	g_platform.ether_init = ether_null_init;
	g_platform.ether_exit = ether_null_exit;
	g_platform.ether_reset = ether_null_reset;
	g_platform.ether_add_multicast = ether_null_add_multicast;
	g_platform.ether_del_multicast = ether_null_del_multicast;
	g_platform.ether_attach_ph = ether_null_attach_ph;
	g_platform.ether_detach_ph = ether_null_detach_ph;
	g_platform.ether_write = ether_null_write;
	g_platform.ether_start_udp_thread = ether_null_start_udp_thread;
	g_platform.ether_stop_udp_thread = ether_null_stop_udp_thread;

	// Memory
	g_platform.ram = nullptr;
	g_platform.rom = nullptr;
	g_platform.ram_size = 0;
	g_platform.rom_size = 0;

	// EmulOp/Trap handlers (NULL by default - set by CPU backend or main)
	g_platform.emulop_handler = nullptr;
	g_platform.trap_handler = nullptr;
}
