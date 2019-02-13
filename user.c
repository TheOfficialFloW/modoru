/* user.c -- psp2swu patches
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2/appmgr.h>
#include <psp2/shellutil.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/clib.h>

#include <taihen.h>

#include <stdio.h>
#include <string.h>

#include "modoru.h"

static tai_hook_ref_t sceSblUsGetUpdateModeRef;
static tai_hook_ref_t sceSblUsPowerControlRef;
static tai_hook_ref_t sceIoRemoveRef;
static tai_hook_ref_t vshSblAimgrIsCEXRef;

static SceUID hooks[5];

static char ux0_data_patch[] = "ux0:/data";

static int sceSblUsGetUpdateModePatched(int *mode) {
  int res = TAI_CONTINUE(int, sceSblUsGetUpdateModeRef, mode);
  *mode = 0x10; // GUI with string "System Update"
  return res;
}

static int sceSblUsPowerControlPatched(int cmd, int arg) {
  if (cmd == 0 || cmd == 1) {
    sceShellUtilUnlock(0xfff);
    sceKernelPowerUnlock(0);
  }

  return TAI_CONTINUE(int, sceSblUsPowerControlRef, cmd, arg);
}

static int sceIoRemovePatched(const char *file) {
  TAI_CONTINUE(int, sceIoRemoveRef, file);
  return 0;
}

static int vshSblAimgrIsCEXPatched(void) {
  TAI_CONTINUE(int, vshSblAimgrIsCEXRef);
  return 0; // no sex
}

int modoru_release_psp2swu_patches(void) {
  if (hooks[4] >= 0)
    taiInjectRelease(hooks[4]);
  if (hooks[3] >= 0)
    taiHookRelease(hooks[3], vshSblAimgrIsCEXRef);
  if (hooks[2] >= 0)
    taiHookRelease(hooks[2], sceIoRemoveRef);
  if (hooks[1] >= 0)
    taiHookRelease(hooks[1], sceSblUsPowerControlRef);
  if (hooks[0] >= 0)
    taiHookRelease(hooks[0], sceSblUsGetUpdateModeRef);

  return 0;
}

int modoru_patch_psp2swu(void) {
  tai_module_info_t tai_info;
  SceKernelModuleInfo mod_info;
  int res;

  tai_info.size = sizeof(tai_module_info_t);
  res = taiGetModuleInfo("ScePsp2Swu", &tai_info);
  if (res < 0)
    goto err;

  mod_info.size = sizeof(SceKernelModuleInfo);
  res = sceKernelGetModuleInfo(tai_info.modid, &mod_info);
  if (res < 0)
    goto err;

  sceKernelPowerLock(0);
  sceShellUtilInitEvents(0);
  sceShellUtilLock(0xfff);
  sceAppMgrDestroyOtherApp();

  sceClibMemset(hooks, -1, sizeof(hooks));

  res = hooks[0] = taiHookFunctionImport(&sceSblUsGetUpdateModeRef, "ScePsp2Swu",
                                         TAI_ANY_LIBRARY, 0x8E834565, sceSblUsGetUpdateModePatched);
  if (res < 0)
    goto err;

  res = hooks[1] = taiHookFunctionImport(&sceSblUsPowerControlRef, "ScePsp2Swu",
                                         TAI_ANY_LIBRARY, 0x1825D954, sceSblUsPowerControlPatched);
  if (res < 0)
    goto err;

  res = hooks[2] = taiHookFunctionImport(&sceIoRemoveRef, "ScePsp2Swu",
                                         TAI_ANY_LIBRARY, 0xE20ED0F3, sceIoRemovePatched);
  if (res < 0)
    goto err;

  res = hooks[3] = taiHookFunctionImport(&vshSblAimgrIsCEXRef, "ScePsp2Swu",
                                         TAI_ANY_LIBRARY, 0x27216A82, vshSblAimgrIsCEXPatched);
  if (res < 0)
    goto err;

  int i;
  for (i = 0; i < (uint32_t)mod_info.segments[0].memsz; i += 4) {
    if (sceClibStrncmp((char *)(mod_info.segments[0].vaddr + i), "ud0:/PSP2UPDATE", 16) == 0) {
      res = hooks[4] = taiInjectData(tai_info.modid, 0, i, ux0_data_patch, sizeof(ux0_data_patch));
      if (res < 0)
        goto err;

      break;
    }
  }

  return 0;

err:
  modoru_release_psp2swu_patches();
  return res;
}

int modoru_release_updater_patches(void) {
  return k_modoru_release_updater_patches();
}

int modoru_patch_updater(void) {
  return k_modoru_patch_updater();
}

int modoru_launch_updater(void) {
  return k_modoru_launch_updater();
}

int modoru_detect_plugins(void) {
  return k_modoru_detect_plugins();
}

int modoru_get_factory_firmware(void) {
  return k_modoru_get_factory_firmware();
}

int modoru_ctrl_peek_buffer_positive(int port, SceCtrlData *pad_data, int count) {
  return k_modoru_ctrl_peek_buffer_positive(port, pad_data, count);
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp) {
  modoru_patch_psp2swu();
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  modoru_release_psp2swu_patches();
  return SCE_KERNEL_STOP_SUCCESS;
}
