/* main.c -- launcher
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2/appmgr.h>
#include <psp2/ctrl.h>
#include <psp2/power.h>
#include <psp2/shellutil.h>
#include <psp2/vshbridge.h>
#include <psp2/io/devctl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/io/dirent.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <malloc.h>

#include "pspdebug.h"

#include "modoru.h"

#define printf psvDebugScreenPrintf

#define APP_PATH "ux0:app/MODORU000/"
#define PUP_PATH APP_PATH "PSP2UPDAT.PUP"

#define CHUNK_SIZE 64 * 1024

#define WHITE  0x00FFFFFF
#define YELLOW 0x0000FFFF

static SceUID modoru_patch_id = -1, modoru_kernel_id = -1, modoru_user_id = -1;

int unload_modoru_drivers(void);

void ErrorExit(int milisecs, char *fmt, ...) {
  va_list list;
  char msg[256];

  va_start(list, fmt);
  vsprintf(msg, fmt, list);
  va_end(list);

  printf(msg);

  sceKernelDelayThread(milisecs * 1000);

  unload_modoru_drivers();
  sceKernelPowerUnlock(0);
  sceKernelExitProcess(0);
}

int unload_modoru_drivers(void) {
  if (modoru_user_id >= 0)
    sceKernelStopUnloadModule(modoru_user_id, 0, NULL, 0, NULL, NULL);
  if (modoru_kernel_id >= 0)
    taiStopUnloadKernelModule(modoru_kernel_id, 0, NULL, 0, NULL, NULL);
  if (modoru_patch_id >= 0)
    taiStopUnloadKernelModule(modoru_patch_id, 0, NULL, 0, NULL, NULL);

  return 0;
}

int load_modoru_drivers(void) {
  modoru_patch_id = taiLoadStartKernelModule(APP_PATH "modoru_patch.skprx", 0, NULL, 0);
  if (modoru_patch_id < 0)
    return modoru_patch_id;

  modoru_kernel_id = taiLoadStartKernelModule(APP_PATH "modoru_kernel.skprx", 0, NULL, 0);
  if (modoru_kernel_id < 0)
    return modoru_kernel_id;

  modoru_user_id = sceKernelLoadStartModule(APP_PATH "modoru_user.suprx", 0, NULL, 0, NULL, NULL);
  if (modoru_user_id < 0)
    return modoru_user_id;

  return 0;
}

// by yifanlu
int extract(const char *pup, const char *psp2swu) {
  int inf, outf;

  if ((inf = sceIoOpen(pup, SCE_O_RDONLY, 0)) < 0) {
    return -1;
  }

  if ((outf = sceIoOpen(psp2swu, SCE_O_CREAT | SCE_O_WRONLY | SCE_O_TRUNC, 6)) < 0) {
    return -1;
  }

  int ret = -1;
  int count;

  if (sceIoLseek(inf, 0x18, SCE_SEEK_SET) < 0) {
    goto end;
  }

  if (sceIoRead(inf, &count, 4) < 4) {
    goto end;
  }

  if (sceIoLseek(inf, 0x80, SCE_SEEK_SET) < 0) {
    goto end;
  }

  struct {
    uint64_t id;
    uint64_t off;
    uint64_t len;
    uint64_t field_18;
  } __attribute__((packed)) file_entry;

  for (int i = 0; i < count; i++) {
    if (sceIoRead(inf, &file_entry, sizeof(file_entry)) != sizeof(file_entry)) {
      goto end;
    }

    if (file_entry.id == 0x200) {
      break;
    }
  }

  if (file_entry.id == 0x200) {
    char buffer[1024];
    size_t rd;

    if (sceIoLseek(inf, file_entry.off, SCE_SEEK_SET) < 0) {
      goto end;
    }

    while (file_entry.len && (rd = sceIoRead(inf, buffer, sizeof(buffer))) > 0) {
      if (rd > file_entry.len) {
        rd = file_entry.len;
      }
      sceIoWrite(outf, buffer, rd);
      file_entry.len -= rd;
    }

    if (file_entry.len == 0) {
      ret = 0;
    }
  }

end:
  sceIoClose(inf);
  sceIoClose(outf);
  return ret;
}

int copy(const char *src, const char *dst) {
  int res;
  SceUID fdsrc = -1, fddst = -1;
  void *buf = NULL;

  res = fdsrc = sceIoOpen(src, SCE_O_RDONLY, 0);
  if (res < 0)
    goto err;

  res = fddst = sceIoOpen(dst, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
  if (res < 0)
    goto err;

  buf = memalign(4096, CHUNK_SIZE);
  if (!buf) {
    res = -1;
    goto err;
  }

  do {
    res = sceIoRead(fdsrc, buf, CHUNK_SIZE);
    if (res > 0)
      res = sceIoWrite(fddst, buf, res);
  } while (res > 0);

err:
  if (buf)
    free(buf);
  if (fddst >= 0)
    sceIoClose(fddst);
  if (fdsrc >= 0)
    sceIoClose(fdsrc);

  return res;
}

int remove_dir(const char *path) {
  SceUID dfd = sceIoDopen(path);
  if (dfd >= 0) {
    int res = 0;

    do {
      SceIoDirent dir;
      memset(&dir, 0, sizeof(SceIoDirent));

      res = sceIoDread(dfd, &dir);
      if (res > 0) {
        char *new_path = malloc(strlen(path) + strlen(dir.d_name) + 2);
        snprintf(new_path, 1024, "%s/%s", path, dir.d_name);
        remove_dir(new_path);
        free(new_path);
      }
    } while (res > 0);

    sceIoDclose(dfd);

    return sceIoRmdir(path);
  } else {
    return sceIoRemove(path);
  }
}

void firmware_string(char string[8], unsigned int version) {
  char a = (version >> 24) & 0xf;
  char b = (version >> 20) & 0xf;
  char c = (version >> 16) & 0xf;
  char d = (version >> 12) & 0xf;

  memset(string, 0, 8);
  string[0] = '0' + a;
  string[1] = '.';
  string[2] = '0' + b;
  string[3] = '0' + c;
  string[4] = '\0';

  if (d) {
    string[4] = '0' + d;
    string[5] = '\0';
  }
}

void wait_confirm(const char *msg) {
  printf(msg);

  while (1) {
    SceCtrlData pad;
    sceCtrlPeekBufferPositive(0, &pad, 1);

    if (pad.buttons & SCE_CTRL_CROSS) {
      break;
    } else if (pad.buttons & (SCE_CTRL_RTRIGGER | SCE_CTRL_R1)) {
      ErrorExit(5000, "Exiting in 5 seconds.\n");
    }

    sceKernelDelayThread(10000);
  }

  sceKernelDelayThread(500 * 1000);
}

int main(int argc, char *argv[]) {
  int res;
  int bypass = 0;

  psvDebugScreenInit();
  sceKernelPowerLock(0);

  printf("-- modoru v1.0\n");
  printf("   by TheFloW\n\n");

  if (sceIoDevctl("ux0:", 0x3001, NULL, 0, NULL, 0) == 0x80010030)
    ErrorExit(10000, "Enable unsafe homebrew first before using this software.\n");

  res = load_modoru_drivers();
  if (res < 0)
    ErrorExit(10000, "Error 0x%08X loading drivers.\n", res);

  SceKernelFwInfo fwinfo;
  fwinfo.size = sizeof(SceKernelFwInfo);
  _vshSblGetSystemSwVersion(&fwinfo);

  unsigned int current_version = (unsigned int)fwinfo.version;
  unsigned int factory_version = modoru_get_factory_firmware();

  char current_fw[8], factory_fw[8];
  firmware_string(current_fw, current_version);
  firmware_string(factory_fw, factory_version);

  printf("Firmware information:\n");
  printf(" - Current firmware: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", current_fw);
  psvDebugScreenSetTextColor(WHITE);
  printf("\n");
  printf(" - Factory firmware: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", factory_fw);
  psvDebugScreenSetTextColor(WHITE);
  printf("\n\n");

  SceCtrlData pad;
  modoru_ctrl_peek_buffer_positive(0, &pad, 1);
  if (pad.buttons & (SCE_CTRL_LTRIGGER | SCE_CTRL_R1)) {
    bypass = 1;
  }

  if (!bypass) {
    if (scePowerGetBatteryLifePercent() < 50)
      ErrorExit(10000, "Battery has to be at least at 50%%.\n");

    res = modoru_detect_plugins();
    if (res < 0) {
      ErrorExit(10000, "Error 0x%08X detecting plugins.\n", res);
    } else if (res != 0) {
      ErrorExit(20000, "Disable all your plugins first before using this software.\n"
                       "If you have already disabled them, but still get this message,\n"
                       "reboot your device and launch this software again without\n"
                       "launching any other applications before (e.g. VitaShell\n"
                       "or Adrenaline).\n");
    }
  }

  char header[0x80];

  SceUID fd = sceIoOpen(PUP_PATH, SCE_O_RDONLY, 0);
  if (fd < 0)
    ErrorExit(10000, "Error 0x%08X opening %s.\n", fd, PUP_PATH);
  sceIoRead(fd, header, sizeof(header));
  sceIoClose(fd);

  if (strncmp(header, "SCEUF", 5) != 0)
    ErrorExit(10000, "Error invalid updater file.\n");

  unsigned int target_version  = *(unsigned int *)(header + 0x10);

  char target_fw[8];
  firmware_string(target_fw,  target_version);

  printf("Target firmware: ");
  psvDebugScreenSetTextColor(YELLOW);
  printf("%s", target_fw);
  psvDebugScreenSetTextColor(WHITE);
  printf("\n\n");

  if (target_version < factory_version)
    ErrorExit(10000, "Error you cannot go lower than your factory firmware.");

  if (target_version == current_version) {
    printf("Do you want to reinstall firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", current_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf("?\n");
  } else if (target_version < current_version) {
    printf("Do you want to downgrade from firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", current_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf(" to firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", target_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf("?\n");
  } else if (target_version > current_version) {
    printf("Do you want to update from firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", current_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf(" to firmware ");
    psvDebugScreenSetTextColor(YELLOW);
    printf("%s", target_fw);
    psvDebugScreenSetTextColor(WHITE);
    printf("?\n");
  }

  wait_confirm("Press X to confirm, R to exit.\n\n");

  printf("This software will make PERMANENT modifications to your Vita.\n"
         "If anything goes wrong, there is NO RECOVERY (not even with a\n"
         "hardware flasher). The creators provide this tool \"as is\", without\n"
         "warranty of any kind, express or implied and cannot be held liable\n"
         "for any damage done.\n\n");

  if (!bypass) {
    printf("Continues in 20 seconds.\n\n");
    sceKernelDelayThread(20 * 1000 * 1000);
  }

  wait_confirm("Press X to accept these terms and start the installation,\n"
               "      R to not accept and exit.\n\n");

  printf("Cleaning ud0:...");
  remove_dir("ud0:");
  sceIoMkdir("ud0:PSP2UPDATE", 0777);
  printf("OK\n");

  printf("Copying PSP2UPDAT.PUP to ud0:...");
  res = copy(PUP_PATH, "ud0:PSP2UPDATE/PSP2UPDAT.PUP");
  if (res < 0)
    ErrorExit(10000, "Error 0x%08X copying PSP2UPDAT.PUP.\n", res);
  printf("OK\n");
  sceKernelDelayThread(500 * 1000);

  printf("Extracting psp2swu.self...");
  res = extract("ud0:PSP2UPDATE/PSP2UPDAT.PUP", "ud0:PSP2UPDATE/psp2swu.self");
  if (res < 0)
    ErrorExit(10000, "Error 0x%08X extracting psp2swu.self.\n", res);
  printf("OK\n");
  sceKernelDelayThread(500 * 1000);

  printf("Removing ux0:id.dat...");
  res = sceIoRemove("ux0:id.dat");
  if (res < 0 && res != 0x80010002)
    ErrorExit(10000, "Error 0x%08X deleting ux0:id.dat.\n", res);
  printf("OK\n");
  sceKernelDelayThread(500 * 1000);

  printf("Starting SCE updater...\n");
  sceKernelDelayThread(1 * 1000 * 1000);

  sceKernelPowerUnlock(0);

  res = modoru_patch_updater();
  if (res < 0)
    ErrorExit(10000, "Error 0x%08X patching updater.\n", res);

  res = modoru_launch_updater();
  if (res < 0)
    goto err;

  sceKernelDelayThread(10 * 1000 * 1000);

err:
  modoru_release_updater_patches();
  ErrorExit(10000, "Error 0x%08X starting SCE updater.\n", res);

  return 0;
}
