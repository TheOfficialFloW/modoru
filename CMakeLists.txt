cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(modoru)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(VITA_APP_NAME "modoru 戻る")
set(VITA_TITLEID  "MODORU000")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

link_directories(
  ${CMAKE_BINARY_DIR}/modoru_kernel_stubs
  ${CMAKE_BINARY_DIR}/modoru_user_stubs
)

add_executable(modoru
  main.c
  scr_printf.c
  font.c
)

add_dependencies(modoru modoru_kernel.skprx)

target_link_libraries(modoru
  SceAppMgr_stub
  SceCtrl_stub
  SceDisplay_stub
  ScePower_stub
  SceVshBridge_stub
  taihen_stub
  modoru_user_stub_weak
)

vita_create_self(eboot.bin modoru UNSAFE)

add_executable(modoru_patch
  patch.c
)
set_target_properties(modoru_patch
  PROPERTIES LINK_FLAGS
  -nostdlib
)
target_link_libraries(modoru_patch
  taihenForKernel_stub
)
vita_create_self(modoru_patch.skprx modoru_patch
  CONFIG ${CMAKE_SOURCE_DIR}/patch_exports.yml
  UNSAFE
)

add_executable(modoru_kernel
  kernel.c
  spkg.c
)
set_target_properties(modoru_kernel
  PROPERTIES LINK_FLAGS
  -nostdlib
)
target_link_libraries(modoru_kernel
  SceAppMgrForDriver_stub
  SceCtrlForDriver_stub
  SceCpuForDriver_stub
  SceKernelUtilsForDriver_stub
  SceModulemgrForDriver_stub
  SceSblAIMgrForDriver_stub
  SceSblSsMgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceSysrootForKernel_stub
  SceThreadmgrForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
)
vita_create_self(modoru_kernel.skprx modoru_kernel
  CONFIG ${CMAKE_SOURCE_DIR}/kernel_exports.yml
  UNSAFE
)
vita_create_stubs(modoru_kernel_stubs modoru_kernel ${CMAKE_SOURCE_DIR}/kernel_exports.yml KERNEL)

add_executable(modoru_user
  user.c
)
set_target_properties(modoru_user
  PROPERTIES LINK_FLAGS
  -nostartfiles
)
target_link_libraries(modoru_user
  SceAppMgr_stub
  SceShellSvc_stub
  ScePower_stub
  taihen_stub
  modoru_kernel_stub
)
vita_create_self(modoru_user.suprx modoru_user
  CONFIG ${CMAKE_SOURCE_DIR}/user_exports.yml
  UNSAFE
)
vita_create_stubs(modoru_user_stubs modoru_user ${CMAKE_SOURCE_DIR}/user_exports.yml)

add_dependencies(modoru_user modoru_kernel_stubs)
add_dependencies(modoru modoru_patch.skprx)
add_dependencies(modoru modoru_kernel.skprx)
add_dependencies(modoru modoru_user_stubs)
add_dependencies(modoru modoru_user.suprx)

vita_create_vpk(modoru.vpk ${VITA_TITLEID} eboot.bin
  VERSION ${VITA_VERSION}
  NAME ${VITA_APP_NAME}
  FILE ${CMAKE_BINARY_DIR}/modoru_patch.skprx modoru_patch.skprx
  FILE ${CMAKE_BINARY_DIR}/modoru_kernel.skprx modoru_kernel.skprx
  FILE ${CMAKE_BINARY_DIR}/modoru_user.suprx modoru_user.suprx
  FILE ${CMAKE_SOURCE_DIR}/pkg/icon0.png sce_sys/icon0.png
  FILE ${CMAKE_SOURCE_DIR}/pkg/template.xml sce_sys/livearea/contents/template.xml
  FILE ${CMAKE_SOURCE_DIR}/pkg/bg0.png sce_sys/livearea/contents/bg0.png
  FILE ${CMAKE_SOURCE_DIR}/pkg/startup.png sce_sys/livearea/contents/startup.png
)
