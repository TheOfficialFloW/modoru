#ifndef __MODORU_H__
#define __MODORU_H__

#include <psp2/ctrl.h>

int k_modoru_release_updater_patches(void);
int k_modoru_patch_updater(void);
int k_modoru_launch_updater(void);
int k_modoru_detect_plugins(void);
int k_modoru_get_factory_firmware(void);
int k_modoru_ctrl_peek_buffer_positive(int port, SceCtrlData *pad_data, int count);

int modoru_release_updater_patches(void);
int modoru_patch_updater(void);
int modoru_launch_updater(void);
int modoru_detect_plugins(void);
int modoru_get_factory_firmware(void);
int modoru_ctrl_peek_buffer_positive(int port, SceCtrlData *pad_data, int count);

#endif
