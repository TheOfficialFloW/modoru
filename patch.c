/* patch.c -- allow kernel module unloading
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2kern/kernel/modulemgr.h>

#include <taihen.h>

static tai_hook_ref_t ksceSblACMgrIsDevelopmentModeRef;
static SceUID hookid = -1;

static int ksceSblACMgrIsDevelopmentModePatched(void) {
  TAI_CONTINUE(int, ksceSblACMgrIsDevelopmentModeRef);
  return 1;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize args, void *argp) {
  hookid = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblACMgrIsDevelopmentModeRef, "SceKernelModulemgr",
                                          TAI_ANY_LIBRARY, 0xBBA13D9C, ksceSblACMgrIsDevelopmentModePatched);
  if (hookid < 0) {
    hookid = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblACMgrIsDevelopmentModeRef, "SceKernelModulemgr",
                                            TAI_ANY_LIBRARY, 0xE87D1777, ksceSblACMgrIsDevelopmentModePatched);
  }

  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  if (hookid >= 0)
    taiHookReleaseForKernel(hookid, ksceSblACMgrIsDevelopmentModeRef);
  return SCE_KERNEL_STOP_SUCCESS;
}
