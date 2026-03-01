/*
 * freedos_data.h — declarations for embedded FreeDOS boot files.
 * Auto-generated from res/freedos/ by scripts/gen_freedos_data.py
 * Do not edit by hand.
 */
#pragma once
#include <stdint.h>

typedef struct {
	int            id;        /* IDR_FD_* resource ID */
	const char    *name;      /* original filename (uppercase) */
	const uint8_t *data;      /* file content */
	uint32_t       size;      /* byte count */
} fd_resource_t;

extern const uint8_t  fd_command_com[];
extern const uint32_t fd_command_com_len;
extern const uint8_t  fd_kernel_sys[];
extern const uint32_t fd_kernel_sys_len;
extern const uint8_t  fd_display_exe[];
extern const uint32_t fd_display_exe_len;
extern const uint8_t  fd_keyb_exe[];
extern const uint32_t fd_keyb_exe_len;
extern const uint8_t  fd_mode_com[];
extern const uint32_t fd_mode_com_len;
extern const uint8_t  fd_keyboard_sys[];
extern const uint32_t fd_keyboard_sys_len;
extern const uint8_t  fd_keybrd2_sys[];
extern const uint32_t fd_keybrd2_sys_len;
extern const uint8_t  fd_keybrd3_sys[];
extern const uint32_t fd_keybrd3_sys_len;
extern const uint8_t  fd_keybrd4_sys[];
extern const uint32_t fd_keybrd4_sys_len;
extern const uint8_t  fd_ega_cpx[];
extern const uint32_t fd_ega_cpx_len;
extern const uint8_t  fd_ega2_cpx[];
extern const uint32_t fd_ega2_cpx_len;
extern const uint8_t  fd_ega3_cpx[];
extern const uint32_t fd_ega3_cpx_len;
extern const uint8_t  fd_ega4_cpx[];
extern const uint32_t fd_ega4_cpx_len;
extern const uint8_t  fd_ega5_cpx[];
extern const uint32_t fd_ega5_cpx_len;
extern const uint8_t  fd_ega6_cpx[];
extern const uint32_t fd_ega6_cpx_len;
extern const uint8_t  fd_ega7_cpx[];
extern const uint32_t fd_ega7_cpx_len;
extern const uint8_t  fd_ega8_cpx[];
extern const uint32_t fd_ega8_cpx_len;
extern const uint8_t  fd_ega9_cpx[];
extern const uint32_t fd_ega9_cpx_len;
extern const uint8_t  fd_ega10_cpx[];
extern const uint32_t fd_ega10_cpx_len;
extern const uint8_t  fd_ega11_cpx[];
extern const uint32_t fd_ega11_cpx_len;
extern const uint8_t  fd_ega12_cpx[];
extern const uint32_t fd_ega12_cpx_len;
extern const uint8_t  fd_ega13_cpx[];
extern const uint32_t fd_ega13_cpx_len;
extern const uint8_t  fd_ega14_cpx[];
extern const uint32_t fd_ega14_cpx_len;
extern const uint8_t  fd_ega15_cpx[];
extern const uint32_t fd_ega15_cpx_len;
extern const uint8_t  fd_ega16_cpx[];
extern const uint32_t fd_ega16_cpx_len;
extern const uint8_t  fd_ega17_cpx[];
extern const uint32_t fd_ega17_cpx_len;
extern const uint8_t  fd_ega18_cpx[];
extern const uint32_t fd_ega18_cpx_len;

extern const fd_resource_t fd_resources[];
#define FD_RESOURCES_COUNT 27
