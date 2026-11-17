cmake_minimum_required(VERSION 3.16)
project(pmpro VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2)

find_package(Threads REQUIRED)
find_package(LibLZMA REQUIRED)

option(PMPRO_GUI "Build the GTK4/libadwaita GUI (pmpro)" ON)
if(PMPRO_GUI)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ADW REQUIRED libadwaita-1 gtk4)
endif()

# Platform HID transport
if(APPLE)
    set(PMPRO_HIDRAW src/hidraw_macos.c src/hidraw_common.c)
    set(PMPRO_HID_LIBS "-framework IOKit" "-framework CoreFoundation")
else()
    set(PMPRO_HIDRAW src/hidraw_linux.c src/hidraw_common.c)
    set(PMPRO_HID_LIBS "")
endif()

# ---- vendored mfoc-hardnested Crypto-1 hardnested solver (GPLv3) ----
set(HN ${CMAKE_SOURCE_DIR}/src/hardnested)
set(HN_COMMON
    ${HN}/cmdhfmfhard.c ${HN}/crapto1.c ${HN}/crypto1.c ${HN}/parity.c
    ${HN}/ui.c ${HN}/util.c ${HN}/util_posix.c
    ${HN}/hardnested/hardnested_bruteforce.c
    ${HN}/hardnested/hardnested_cpu_dispatch.c
    ${HN}/hardnested/tables.c)
# NOTE: HN_ARCH is the target architecture. It defaults to CMAKE_SYSTEM_PROCESSOR (the
# build host CPU); on macOS, CMAKE_OSX_ARCHITECTURES overrides it when it names exactly one
# arch (cross-builds such as x86_64 on arm64 hosts). Universal (multi-arch) macOS builds are
# rejected: build one arch at a time.
# The SIMD cores are x86-only; other architectures use the portable NOSIMD cores.
set(HN_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    list(LENGTH CMAKE_OSX_ARCHITECTURES HN_OSX_ARCH_COUNT)
    if(HN_OSX_ARCH_COUNT GREATER 1)
        message(FATAL_ERROR "universal builds are not supported; build one arch at a time")
    endif()
    set(HN_ARCH "${CMAKE_OSX_ARCHITECTURES}")
endif()
if(HN_ARCH MATCHES "^(x86_64|AMD64|x86|i[3-6]86)$")
    set(HN_X86 TRUE)
    add_library(hardnested STATIC ${HN_COMMON}
        ${HN}/hardnested/hardnested_bf_core_SSE2.c
        ${HN}/hardnested/hardnested_bf_core_AVX.c
        ${HN}/hardnested/hardnested_bf_core_AVX2.c
        ${HN}/hardnested/hardnested_bf_core_AVX512.c
        ${HN}/hardnested/hardnested_bitarray_core_SSE2.c
        ${HN}/hardnested/hardnested_bitarray_core_AVX.c
        ${HN}/hardnested/hardnested_bitarray_core_AVX2.c
        ${HN}/hardnested/hardnested_bitarray_core_AVX512.c)
    target_compile_definitions(hardnested PRIVATE X86_SIMD)
else()
    add_library(hardnested STATIC ${HN_COMMON}
        ${HN}/hardnested/hardnested_bf_core_NOSIMD.c
        ${HN}/hardnested/hardnested_bitarray_core_NOSIMD.c)
    # hardnested_bf_core_NOSIMD.c calls printf() without including <stdio.h>
    # (an error on modern clang); force-include it instead of editing the vendored file.
    set_source_files_properties(${HN}/hardnested/hardnested_bf_core_NOSIMD.c
        PROPERTIES COMPILE_OPTIONS "-include;stdio.h")
endif()
target_include_directories(hardnested PUBLIC ${HN} ${HN}/hardnested)
target_compile_options(hardnested PRIVATE -w -O2)
target_link_libraries(hardnested PUBLIC Threads::Threads m LibLZMA::LibLZMA)
if(HN_X86)
set_source_files_properties(
    ${HN}/hardnested/hardnested_bf_core_SSE2.c ${HN}/hardnested/hardnested_bitarray_core_SSE2.c
    PROPERTIES COMPILE_OPTIONS "-mmmx;-msse2")
set_source_files_properties(
    ${HN}/hardnested/hardnested_bf_core_AVX.c ${HN}/hardnested/hardnested_bitarray_core_AVX.c
    PROPERTIES COMPILE_OPTIONS "-mmmx;-msse2;-mavx")
set_source_files_properties(
    ${HN}/hardnested/hardnested_bf_core_AVX2.c ${HN}/hardnested/hardnested_bitarray_core_AVX2.c
    PROPERTIES COMPILE_OPTIONS "-mmmx;-msse2;-mavx;-mavx2")
set_source_files_properties(
    ${HN}/hardnested/hardnested_bf_core_AVX512.c ${HN}/hardnested/hardnested_bitarray_core_AVX512.c
    PROPERTIES COMPILE_OPTIONS "-mmmx;-msse2;-mavx;-mavx2;-mavx512f")
endif()

if(PMPRO_GUI)
# ---- embed the app icon as a GResource (so it shows when run uninstalled) ----
find_program(GLIB_COMPILE_RESOURCES glib-compile-resources REQUIRED)
set(ICON_GRESOURCE ${CMAKE_BINARY_DIR}/icon_resources.c)
add_custom_command(
    OUTPUT ${ICON_GRESOURCE}
    COMMAND ${GLIB_COMPILE_RESOURCES}
            --target=${ICON_GRESOURCE} --generate-source
            --sourcedir=${CMAKE_SOURCE_DIR}/data
            ${CMAKE_SOURCE_DIR}/data/icons.gresource.xml
    DEPENDS ${CMAKE_SOURCE_DIR}/data/icons.gresource.xml
            ${CMAKE_SOURCE_DIR}/data/com.furui.pmpro.svg
    COMMENT "Compiling icon GResource")

add_executable(pmpro
    src/app.c
    ${PMPRO_HIDRAW}
    src/protocol.c
    src/furui.c
    src/session.c
    src/crypto1.c
    src/crack.c
    src/hardnested_glue.c
    src/nested.c
    src/dump.c
    src/ndef.c
    src/macbundle.c
    ${ICON_GRESOURCE})

target_include_directories(pmpro PRIVATE ${ADW_INCLUDE_DIRS} src)
target_link_directories(pmpro PRIVATE ${ADW_LIBRARY_DIRS})
target_link_libraries(pmpro PRIVATE ${ADW_LIBRARIES} hardnested ${PMPRO_HID_LIBS})
target_compile_options(pmpro PRIVATE ${ADW_CFLAGS_OTHER})
if(APPLE)
    # Leave room for install_name_tool when the .app bundle relocates dylibs.
    target_link_options(pmpro PRIVATE -Wl,-headerpad_max_install_names)

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(MAKE_APP ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/macos/make_app.py
        --build ${CMAKE_BINARY_DIR} --version ${PROJECT_VERSION})
    if(PMPRO_BREW_PREFIX)   # optional; default is `brew --prefix`
        list(APPEND MAKE_APP --prefix ${PMPRO_BREW_PREFIX})
    endif()
    add_custom_target(macos-app COMMAND ${MAKE_APP} DEPENDS pmpro pmctl
        COMMENT "Packaging NFC PM-Pro.app" VERBATIM)
    add_custom_target(macos-dmg COMMAND ${MAKE_APP} --dmg DEPENDS pmpro pmctl
        COMMENT "Packaging NFC PM-Pro.app + DMG" VERBATIM)
    add_test(NAME make_app_py COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_SOURCE_DIR}/tools/macos/test_make_app.py)
endif()
endif()

# CLI tools (no GTK) — protocol control + RE probe
add_executable(pmctl src/pmctl.c ${PMPRO_HIDRAW} src/furui.c src/session.c src/protocol.c src/crypto1.c src/crack.c src/hardnested_glue.c src/nested.c src/dump.c src/ndef.c)
target_link_libraries(pmctl PRIVATE hardnested ${PMPRO_HID_LIBS})
if(APPLE)
    target_link_options(pmctl PRIVATE -Wl,-headerpad_max_install_names)
endif()
add_executable(pmprobe src/probe.c ${PMPRO_HIDRAW} src/protocol.c)
target_link_libraries(pmprobe PRIVATE ${PMPRO_HID_LIBS})
target_include_directories(pmprobe PRIVATE src)

# Crypto-1 self-tests (cipher round-trip + key recovery from synthetic keystream)
add_executable(test_cipher   tests/test_cipher.c   src/crypto1.c)
add_executable(test_recovery tests/test_recovery.c src/crypto1.c)
add_executable(test_dump     tests/test_dump.c     src/dump.c src/protocol.c)
add_executable(test_ndef     tests/test_ndef.c     src/ndef.c)
add_executable(test_hidraw_common tests/test_hidraw_common.c src/hidraw_common.c)
target_include_directories(test_hidraw_common PRIVATE src)
add_executable(test_macbundle tests/test_macbundle.c src/macbundle.c)
target_include_directories(test_macbundle PRIVATE src)
target_include_directories(test_cipher   PRIVATE src)
target_include_directories(test_recovery PRIVATE src)
target_include_directories(test_dump     PRIVATE src)
target_include_directories(test_ndef     PRIVATE src)
enable_testing()
add_test(NAME cipher   COMMAND test_cipher)
add_test(NAME recovery COMMAND test_recovery)
add_test(NAME dump     COMMAND test_dump)
add_test(NAME ndef     COMMAND test_ndef)
add_test(NAME hidraw_common COMMAND test_hidraw_common)
add_test(NAME macbundle COMMAND test_macbundle)

install(TARGETS pmctl RUNTIME DESTINATION bin)
if(PMPRO_GUI)
install(TARGETS pmpro RUNTIME DESTINATION bin)
install(FILES data/com.furui.pmpro.desktop DESTINATION share/applications)
install(FILES data/com.furui.pmpro.svg
        DESTINATION share/icons/hicolor/scalable/apps)

# Refresh the desktop + icon caches after a system install (best-effort).
install(CODE "
  execute_process(COMMAND update-desktop-database \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/applications\" ERROR_QUIET)
  execute_process(COMMAND gtk-update-icon-cache -f -t \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/icons/hicolor\" ERROR_QUIET)
")
endif()
