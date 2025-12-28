/*
 *  test_boot.cpp - Minimal boot test for macemu-next
 *
 *  Tests the initialization sequence with dummy drivers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "sysdeps.h"
#include "cpu_emulation.h"
#include "uae_wrapper.h"
#include "main.h"
#include "prefs.h"
#include "video.h"
#include "xpram.h"
#include "timer.h"
#include "sony.h"
#include "disk.h"
#include "cdrom.h"
#include "scsi.h"
#include "serial.h"
#include "ether.h"
#include "clip.h"
#include "adb.h"
#include "audio.h"
#include "rom_patches.h"
#include "user_strings.h"

#define DEBUG 1
#include "debug.h"

// Global variables (defined in basilisk_glue.cpp when using dualcpu backend)
extern uint8 *RAMBaseHost;
extern uint8 *ROMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMSize;

#if DIRECT_ADDRESSING
// MEMBaseDiff, RAMBaseMac, ROMBaseMac are defined in uae_wrapper.cpp/basilisk_glue.cpp
extern uintptr MEMBaseDiff;
extern uint32 RAMBaseMac;
extern uint32 ROMBaseMac;
#endif

// CPU and FPU type (CPUType/FPUType defined in uae_wrapper.cpp)
extern int CPUType;
bool CPUIs68060;
extern int FPUType;
bool TwentyFourBitAddressing;

// Error handling (these are defined in main.cpp, but we need const char* versions)
void ErrorAlert(const char *text)
{
	fprintf(stderr, "ERROR: %s\n", text);
}

void WarningAlert(const char *text)
{
	fprintf(stderr, "WARNING: %s\n", text);
}

// Quit emulator
void QuitEmulator(void)
{
	printf("QuitEmulator() called\n");
	ExitAll();
	exit(1);
}

// Interrupt flags (declared in main.h and defined in uae_wrapper.cpp)
extern uint32 InterruptFlags;

// Disable interrupts (stub)
void DisableInterrupt(void)
{
}

// Enable interrupts (stub)
void EnableInterrupt(void)
{
}

// Platform-specific stubs
void MountVolume(const char *path) {}
void FileDiskLayout(loff_t size, loff_t *start, loff_t *length) {}
void FloppyInit() {}
// XPRAMInit and XPRAMExit are in xpram.cpp, we don't need to define them

// System stubs
void SysAddSerialPrefs() {}
void SysAddFloppyPrefs() {}
void SysAddDiskPrefs() {}
void SysAddCDROMPrefs() {}
void *Sys_open(const char *path, bool read_only, bool no_cache) { return NULL; }
void Sys_close(void *fh) {}
size_t Sys_read(void *fh, void *buf, loff_t offset, size_t length) { return 0; }
size_t Sys_write(void *fh, void *buf, loff_t offset, size_t length) { return 0; }
bool SysIsReadOnly(void *fh) { return true; }
bool SysIsDiskInserted(void *fh) { return false; }
bool SysIsFixedDisk(void *fh) { return false; }
loff_t SysGetFileSize(void *fh) { return 0; }
void SysEject(void *fh) {}
void SysAllowRemoval(void *fh) {}
void SysPreventRemoval(void *fh) {}
bool SysCDGetVolume(void *fh, uint8 &left, uint8 &right) { left = 255; right = 255; return true; }
bool SysCDSetVolume(void *fh, uint8 left, uint8 right) { return true; }
void SysCDPause(void *fh) {}
void SysCDResume(void *fh) {}
bool SysCDPlay(void *fh, uint8 m1, uint8 s1, uint8 f1, uint8 m2, uint8 s2, uint8 f2) { return false; }
bool SysCDStop(void *fh, uint8 m, uint8 s, uint8 f) { return true; }
bool SysCDGetPosition(void *fh, uint8 *pos) { return false; }
bool SysCDScan(void *fh, uint8 m, uint8 s, uint8 f, bool reverse) { return false; }
bool SysCDReadTOC(void *fh, uint8 *toc) { return false; }
bool SysFormat(void *fh) { return false; }

// Timer stubs
void timer_current_time(struct timeval &tv) { gettimeofday(&tv, NULL); }
void timer_add_time(struct timeval &res, struct timeval a, struct timeval b) {
	res.tv_sec = a.tv_sec + b.tv_sec;
	res.tv_usec = a.tv_usec + b.tv_usec;
	if (res.tv_usec >= 1000000) { res.tv_sec++; res.tv_usec -= 1000000; }
}
void timer_sub_time(struct timeval &res, struct timeval a, struct timeval b) {
	res.tv_sec = a.tv_sec - b.tv_sec;
	res.tv_usec = a.tv_usec - b.tv_usec;
	if (res.tv_usec < 0) { res.tv_sec--; res.tv_usec += 1000000; }
}
int32 timer_host2mac_time(struct timeval tv) { return tv.tv_sec * 1000000 + tv.tv_usec; }
void timer_mac2host_time(struct timeval &tv, int32 mac_time) {
	tv.tv_sec = mac_time / 1000000;
	tv.tv_usec = mac_time % 1000000;
}
int timer_cmp_time(struct timeval a, struct timeval b) {
	if (a.tv_sec < b.tv_sec) return -1;
	if (a.tv_sec > b.tv_sec) return 1;
	if (a.tv_usec < b.tv_usec) return -1;
	if (a.tv_usec > b.tv_usec) return 1;
	return 0;
}

// Mutex stubs (not used in minimal test)
struct B2_mutex { int dummy; };
B2_mutex *B2_create_mutex() { return new B2_mutex(); }
void B2_delete_mutex(B2_mutex *m) { delete m; }
void B2_lock_mutex(B2_mutex *m) {}
void B2_unlock_mutex(B2_mutex *m) {}

// Interrupt stubs (TriggerInterrupt is in basilisk_glue.cpp)
void SetInterruptFlag(uint32 flag) { InterruptFlags |= flag; }
void ClearInterruptFlag(uint32 flag) { InterruptFlags &= ~flag; }

// CPU emulation stubs - Init680x0, Execute68k, Execute68kTrap are now in basilisk_glue.cpp
// (when using dualcpu backend)
void FlushCodeCache(void *start, uint32 size) {}

// ExtFS stubs
ssize_t extfs_read(int fd, void *buf, size_t len) { return -1; }
ssize_t extfs_write(int fd, void *buf, size_t len) { return -1; }
int extfs_remove(const char *path) { return -1; }
int extfs_rename(const char *old_path, const char *new_path) { return -1; }
void get_finfo(const char *path, uint32 finfo, uint32 fxinfo, bool is_dir) {}
void set_finfo(const char *path, uint32 finfo, uint32 fxinfo, bool is_dir) {}
void close_rfork(const char *path, int fd) {}
int open_rfork(const char *path, int flag) { return -1; }
off_t get_rfork_size(const char *path) { return 0; }
const char *host_encoding_to_macroman(const char *str) { return str; }
const char *macroman_to_host_encoding(const char *str) { return str; }
void add_path_component(char *path, const char *component) {}
void extfs_init() {}
void extfs_exit() {}

// Scratch memory (not used in minimal test)
uint8 *ScratchMem = NULL;

int main(int argc, char **argv)
{
	printf("=== macemu-next Boot Test ===\n\n");

	// Check for ROM file argument
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <rom-file>\n", argv[0]);
		return 1;
	}
	const char *rom_path = argv[1];

	// Initialize random number generator
	srand(time(NULL));

	// Set RAM size before PrefsInit
	RAMSize = 32 * 1024 * 1024;  // 32MB

	// Read preferences (minimal)
	PrefsInit(NULL, argc, argv);
	PrefsAddInt32("ramsize", RAMSize);
	PrefsAddInt32("cpu", 4);  // 68040
	PrefsAddBool("fpu", true);

	printf("Allocating RAM (%d MB)...\n", RAMSize / (1024 * 1024));

	// Allocate RAM (simple mmap for now)
	RAMBaseHost = (uint8 *)mmap(NULL, RAMSize + 0x100000,
	                             PROT_READ | PROT_WRITE,
	                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (RAMBaseHost == MAP_FAILED) {
		fprintf(stderr, "Failed to allocate RAM\n");
		return 1;
	}

	ROMBaseHost = RAMBaseHost + RAMSize;
	memset(RAMBaseHost, 0, RAMSize);

#if DIRECT_ADDRESSING
	// RAMBaseMac shall always be zero
	MEMBaseDiff = (uintptr)RAMBaseHost;
	RAMBaseMac = 0;
	ROMBaseMac = Host2MacAddr(ROMBaseHost);
#endif

	printf("RAM at %p (Mac: 0x%08x)\n", RAMBaseHost, RAMBaseMac);
	printf("ROM at %p (Mac: 0x%08x)\n", ROMBaseHost, ROMBaseMac);

	// Load ROM
	printf("\nLoading ROM from %s...\n", rom_path);
	int rom_fd = open(rom_path, O_RDONLY);
	if (rom_fd < 0) {
		fprintf(stderr, "Failed to open ROM file: %s\n", rom_path);
		return 1;
	}

	ROMSize = lseek(rom_fd, 0, SEEK_END);
	printf("ROM size: %d bytes (%d KB)\n", ROMSize, ROMSize / 1024);

	if (ROMSize != 64*1024 && ROMSize != 128*1024 && ROMSize != 256*1024 &&
	    ROMSize != 512*1024 && ROMSize != 1024*1024) {
		fprintf(stderr, "Invalid ROM size (must be 64/128/256/512/1024 KB)\n");
		close(rom_fd);
		return 1;
	}

	lseek(rom_fd, 0, SEEK_SET);
	if (read(rom_fd, ROMBaseHost, ROMSize) != (ssize_t)ROMSize) {
		fprintf(stderr, "Failed to read ROM file\n");
		close(rom_fd);
		return 1;
	}
	close(rom_fd);
	printf("ROM loaded successfully\n");

	// Initialize everything
	printf("\n=== Initializing Emulator ===\n");
	if (!InitAll(NULL)) {
		fprintf(stderr, "Initialization failed\n");
		return 1;
	}

	printf("\n=== Initialization Complete ===\n");
	printf("ROM Version: 0x%08x\n", ROMVersion);
	printf("CPU Type: 680%02d\n", (CPUType == 0) ? 0 : (CPUType * 10 + 20));
	printf("FPU: %s\n", FPUType ? "Yes" : "No");
	printf("24-bit addressing: %s\n", TwentyFourBitAddressing ? "Yes" : "No");

	// Set initial PC from ROM reset vector
	// M68K reset vector: offset 0 = initial SSP, offset 4 = initial PC
	uint32_t initial_ssp = (ROMBaseHost[0] << 24) | (ROMBaseHost[1] << 16) |
	                       (ROMBaseHost[2] << 8) | ROMBaseHost[3];
	uint32_t initial_pc = (ROMBaseHost[4] << 24) | (ROMBaseHost[5] << 16) |
	                      (ROMBaseHost[6] << 8) | ROMBaseHost[7];

	printf("\nROM Reset Vector:\n");
	printf("  Initial SSP: 0x%08x\n", initial_ssp);
	printf("  Initial PC:  0x%08x\n", initial_pc);

	uae_set_areg(7, initial_ssp);  // A7 = Stack Pointer
	uae_set_pc(initial_pc);
	uae_set_sr(0x2700);  // Supervisor mode, interrupts disabled

	// Execute 5 instructions
	printf("\n=== Executing 5 Instructions ===\n");

	for (int i = 0; i < 5; i++) {
		uint32_t pc_before = uae_get_pc();
		uint16_t sr_before = uae_get_sr();

		printf("Instruction %d: PC=0x%08x SR=0x%04x\n", i + 1, pc_before, sr_before);

		uae_cpu_execute_one();

		uint32_t pc_after = uae_get_pc();
		printf("              -> PC=0x%08x\n", pc_after);
	}

	// Clean up
	printf("\n=== Shutting Down ===\n");
	ExitAll();
	PrefsExit();

	munmap(RAMBaseHost, RAMSize + 0x100000);

	printf("\nBoot test completed successfully!\n");
	return 0;
}
