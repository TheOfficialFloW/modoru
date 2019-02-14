/* kernel.c -- updater patches
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2kern/ctrl.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <taihen.h>

#include <stdio.h>
#include <string.h>

#include "spkg.h"

#define APP_PATH "ux0:app/MODORU000/"

#define MOD_LIST_SIZE 128

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

int ksceAppMgrLaunchAppByPath(const char *name, const char *cmd, int cmdlen, int dynamic, void *opt, void *id);

static tai_hook_ref_t ksceKernelStartPreloadedModulesRef;
static tai_hook_ref_t ksceSblACMgrIsDevelopmentModeRef;
static tai_hook_ref_t SceSysrootForDriver_421EFC96_ref;
static tai_hook_ref_t ksceSysrootUseExternalStorage_ref;
static tai_hook_ref_t ksceSblSsInfraAllocatePARangeVectorRef;
static tai_hook_ref_t ksceKernelAllocHeapMemoryRef;
static tai_hook_ref_t ksceKernelFreeHeapMemoryRef;
static tai_hook_ref_t ksceSblSmCommCallFuncRef;

static SceUID hooks[8];

static int ksceKernelStartPreloadedModulesPatched(SceUID pid) {
  int res = TAI_CONTINUE(int, ksceKernelStartPreloadedModulesRef, pid);

  char titleid[32];
  ksceKernelGetProcessTitleId(pid, titleid, sizeof(titleid));

  if (strcmp(titleid, "NPXS10999") == 0) {
    ksceKernelLoadStartModuleForPid(pid, "vs0:sys/external/libshellsvc.suprx", 0, NULL, 0, NULL, NULL);
    ksceKernelLoadStartModuleForPid(pid, APP_PATH "modoru_user.suprx", 0, NULL, 0, NULL, NULL);
  }

  return res;
}

static int ksceSblACMgrIsDevelopmentModePatched(void) {
  TAI_CONTINUE(int, ksceSblACMgrIsDevelopmentModeRef);
  return 1;
}

static int SceSysrootForDriver_421EFC96_patched(void) {
  TAI_CONTINUE(int, SceSysrootForDriver_421EFC96_ref);
  return 0;
}

static int ksceSysrootUseExternalStorage_patched(void) {
  TAI_CONTINUE(int, ksceSysrootUseExternalStorage_ref);
  return 1;
}

static void *spkg_list = NULL;
static void *spkg_buf = NULL;
static int spkg_size = 0;

static void *ksceKernelAllocHeapMemoryPatched(SceUID uid, SceSize size) {
  void *res = TAI_CONTINUE(void *, ksceKernelAllocHeapMemoryRef, uid, size);
  if (size == sizeof(SceKernelPaddrList))
    spkg_list = res;
  return res;
}

static int ksceKernelFreeHeapMemoryPatched(SceUID uid, void *ptr) {
  if (ptr == spkg_list) {
    spkg_list = NULL;
    spkg_buf = NULL;
    spkg_size = 0;
  }

  return TAI_CONTINUE(int, ksceKernelFreeHeapMemoryRef, uid, ptr);
}

static int ksceSblSsInfraAllocatePARangeVectorPatched(void *buf, int size, SceUID blockid, SceKernelPaddrList *list) {
  if (list == spkg_list) {
    spkg_buf = buf;
    spkg_size = size;
  }

  return TAI_CONTINUE(int, ksceSblSsInfraAllocatePARangeVectorRef, buf, size, blockid, list);
}

static int ksceSblSmCommCallFuncPatched(int id, int service_id, int *f00d_resp, void *data, int size) {
  int res = TAI_CONTINUE(int, ksceSblSmCommCallFuncRef, id, service_id, f00d_resp, data, size);

  if (f00d_resp && service_id == SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG) {
    if (*f00d_resp == SCE_SBL_ERROR_SL_ESYSVER) {
      // The spkg has actually been decrypted successfully, just fake success
      *f00d_resp = 0;
    } else if (*f00d_resp == SCE_SBL_ERROR_SL_EDATA) {
      // Use custom spkg decryptor for < 1.692 spkg
      if (spkg_list && spkg_buf && data && memcmp(data + 0x24, spkg_list, sizeof(SceKernelPaddrList)) == 0) {
        *f00d_resp = decrypt_spkg(spkg_buf, spkg_size);
        if (*f00d_resp >= 0) {
          SceHeader *sce_header = (SceHeader *)spkg_buf;
          SpkgHeader *spkg_header = (SpkgHeader *)(data + 0xf40);
          memcpy(spkg_header, (char *)sce_header + sce_header->header_length, sizeof(SpkgHeader));
          ksceKernelCpuDcacheAndL2WritebackRange(spkg_header, sizeof(SpkgHeader));
        }
      }
    }
  }

  return res;
}

int k_modoru_release_updater_patches(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  if (hooks[7] >= 0)
    taiHookReleaseForKernel(hooks[7], ksceSblSmCommCallFuncRef);
  if (hooks[7] >= 0)
    taiHookReleaseForKernel(hooks[7], ksceKernelFreeHeapMemoryRef);
  if (hooks[5] >= 0)
    taiHookReleaseForKernel(hooks[5], ksceKernelAllocHeapMemoryRef);
  if (hooks[4] >= 0)
    taiHookReleaseForKernel(hooks[4], ksceSblSsInfraAllocatePARangeVectorRef);
  if (hooks[3] >= 0)
    taiHookReleaseForKernel(hooks[3], ksceSysrootUseExternalStorage_ref);
  if (hooks[2] >= 0)
    taiHookReleaseForKernel(hooks[2], SceSysrootForDriver_421EFC96_ref);
  if (hooks[1] >= 0)
    taiHookReleaseForKernel(hooks[1], ksceSblACMgrIsDevelopmentModeRef);
  if (hooks[0] >= 0)
    taiHookReleaseForKernel(hooks[0], ksceKernelStartPreloadedModulesRef);

  EXIT_SYSCALL(state);
  return 0;
}

int k_modoru_patch_updater(void) {
  int res;
  uint32_t state;
  ENTER_SYSCALL(state);

  memset(hooks, -1, sizeof(hooks));

  res = hooks[0] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceKernelStartPreloadedModulesRef, "SceKernelModulemgr",
                                                  TAI_ANY_LIBRARY, 0x432DCC7A, ksceKernelStartPreloadedModulesPatched);
  if (res < 0) {
    res = hooks[0] = taiHookFunctionExportForKernel(KERNEL_PID, &ksceKernelStartPreloadedModulesRef, "SceKernelModulemgr",
                                                    TAI_ANY_LIBRARY, 0x998C7AE9, ksceKernelStartPreloadedModulesPatched);
  }

  if (res < 0)
    goto err;

  res = hooks[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblACMgrIsDevelopmentModeRef, "SceAppMgr",
                                                  TAI_ANY_LIBRARY, 0xBBA13D9C, ksceSblACMgrIsDevelopmentModePatched);
  if (res < 0) {
    res = hooks[1] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblACMgrIsDevelopmentModeRef, "SceAppMgr",
                                                    TAI_ANY_LIBRARY, 0xE87D1777, ksceSblACMgrIsDevelopmentModePatched);
  }

  if (res < 0)
    goto err;

  res = hooks[2] = taiHookFunctionImportForKernel(KERNEL_PID, &SceSysrootForDriver_421EFC96_ref, "SceAppMgr",
                                                  TAI_ANY_LIBRARY, 0x421EFC96, SceSysrootForDriver_421EFC96_patched);
  if (res < 0)
    goto err;

  res = hooks[3] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSysrootUseExternalStorage_ref, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0x55392965, ksceSysrootUseExternalStorage_patched);
  if (res < 0)
    goto err;

  res = hooks[4] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblSsInfraAllocatePARangeVectorRef, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0xE0B13BA7, ksceSblSsInfraAllocatePARangeVectorPatched);
  if (res < 0)
    goto err;

  res = hooks[5] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceKernelAllocHeapMemoryRef, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0x7B4CB60A, ksceKernelAllocHeapMemoryPatched);
  if (res < 0)
    goto err;

  res = hooks[6] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceKernelFreeHeapMemoryRef, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0x3EBCE343, ksceKernelFreeHeapMemoryPatched);
  if (res < 0)
    goto err;

  res = hooks[7] = taiHookFunctionImportForKernel(KERNEL_PID, &ksceSblSmCommCallFuncRef, "SceSblUpdateMgr",
                                                  TAI_ANY_LIBRARY, 0xDB9FC204, ksceSblSmCommCallFuncPatched);
  if (res < 0)
    goto err;

  EXIT_SYSCALL(state);
  return 0;

err:
  k_modoru_release_updater_patches();
  EXIT_SYSCALL(state);
  return res;
}

static int launch_thread(SceSize args, void *argp) {
  int opt[52/4];
  memset(opt, 0, sizeof(opt));
  opt[0] = sizeof(opt);

  ksceAppMgrLaunchAppByPath("ud0:PSP2UPDATE/psp2swu.self", NULL, 0, 0, opt, NULL);

  return ksceKernelExitDeleteThread(0);
}

int k_modoru_launch_updater(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  SceUID thid = ksceKernelCreateThread("launch_thread", (SceKernelThreadEntry)launch_thread, 0x40, 0x1000, 0, 0, NULL);
  if (thid < 0) {
    EXIT_SYSCALL(state);
    return thid;
  }

  ksceKernelStartThread(thid, 0, NULL);

  EXIT_SYSCALL(state);
  return 0;
}

int k_modoru_detect_plugins(void) {
  SceKernelModuleInfo info;
  SceUID modlist[MOD_LIST_SIZE];
  size_t count = MOD_LIST_SIZE;
  int res;

  uint32_t state;
  ENTER_SYSCALL(state);

  int (* _ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
  int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info);

  res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                               0x97CF7B4E, (uintptr_t *)&_ksceKernelGetModuleList);
  if (res < 0)
    res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                                 0xB72C75A4, (uintptr_t *)&_ksceKernelGetModuleList);
  if (res < 0)
    goto err;

  res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                               0xD269F915, (uintptr_t *)&_ksceKernelGetModuleInfo);
  if (res < 0)
    res = module_get_export_func(KERNEL_PID, "SceKernelModulemgr", TAI_ANY_LIBRARY,
                                 0xDAA90093, (uintptr_t *)&_ksceKernelGetModuleInfo);
  if (res < 0)
    goto err;

  res = _ksceKernelGetModuleList(KERNEL_PID, 0x7fffffff, 1, modlist, &count);
  if (res < 0)
    goto err;

  info.size = sizeof(SceKernelModuleInfo);
  res = _ksceKernelGetModuleInfo(KERNEL_PID, modlist[2], &info);
  if (res < 0)
    goto err;

  // Third last kernel module must be either taihen or HENkaku
  if (strcmp(info.module_name, "taihen") != 0 && strcmp(info.module_name, "HENkaku") != 0) {
    res = 1;
    goto err;
  }

  res = _ksceKernelGetModuleList(ksceKernelGetProcessId(), 0x7fffffff, 1, modlist, &count);
  if (res < 0)
    goto err;

  info.size = sizeof(SceKernelModuleInfo);
  res = _ksceKernelGetModuleInfo(ksceKernelGetProcessId(), modlist[1], &info);
  if (res < 0)
    goto err;

  // Second last user module must be SceAppUtil
  if (strcmp(info.module_name, "SceAppUtil") != 0) {
    res = 1;
    goto err;
  }

  res = 0;

err:
  EXIT_SYSCALL(state);
  return res;
}

int k_modoru_get_factory_firmware(void) {
  uint32_t state;
  ENTER_SYSCALL(state);

  unsigned int factory_fw = -1;

  void *sysroot = ksceKernelGetSysrootBuffer();
  if (sysroot)
    factory_fw = *(unsigned int *)(sysroot + 8);

  EXIT_SYSCALL(state);
  return factory_fw;
}

int k_modoru_ctrl_peek_buffer_positive(int port, SceCtrlData *pad_data, int count) {
  SceCtrlData pad;
  uint32_t off;

  uint32_t state;
  ENTER_SYSCALL(state);

  // Set cpu offset to zero
  asm volatile ("mrc p15, 0, %0, c13, c0, 4" : "=r" (off));
  asm volatile ("mcr p15, 0, %0, c13, c0, 4" :: "r" (0));

  int res = ksceCtrlPeekBufferPositive(port, &pad, count);

  // Restore cpu offset
  asm volatile ("mcr p15, 0, %0, c13, c0, 4" :: "r" (off));

  ksceKernelMemcpyKernelToUser((uintptr_t)pad_data, &pad, sizeof(SceCtrlData));

  EXIT_SYSCALL(state);
  return res;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize args, void *argp) {
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  k_modoru_release_updater_patches();
  return SCE_KERNEL_STOP_SUCCESS;
}
