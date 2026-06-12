cmake_minimum_required(VERSION 3.16)
project(pmpro C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ADW REQUIRED libadwaita-1 gtk4)
find_package(Threads REQUIRED)

# ---- vendored mfoc-hardnested Crypto-1 hardnested solver (GPLv3) ----
set(HN ${CMAKE_SOURCE_DIR}/src/hardnested)
add_library(hardnested STATIC
    ${HN}/cmdhfmfhard.c ${HN}/crapto1.c ${HN}/crypto1.c ${HN}/parity.c
    ${HN}/ui.c ${HN}/util.c ${HN}/util_posix.c
    ${HN}/hardnested/hardnested_bruteforce.c
    ${HN}/hardnested/hardnested_cpu_dispatch.c
    ${HN}/hardnested/tables.c
    ${HN}/hardnested/hardnested_bf_core_SSE2.c
    ${HN}/hardnested/hardnested_bf_core_AVX.c
    ${HN}/hardnested/hardnested_bf_core_AVX2.c
    ${HN}/hardnested/hardnested_bf_core_AVX512.c
    ${HN}/hardnested/hardnested_bitarray_core_SSE2.c
    ${HN}/hardnested/hardnested_bitarray_core_AVX.c
    ${HN}/hardnested/hardnested_bitarray_core_AVX2.c
    ${HN}/hardnested/hardnested_bitarray_core_AVX512.c)
target_include_directories(hardnested PUBLIC ${HN} ${HN}/hardnested)
target_compile_definitions(hardnested PRIVATE X86_SIMD)
target_compile_options(hardnested PRIVATE -w -O2)
pkg_check_modules(LZMA REQUIRED liblzma)
target_include_directories(hardnested PRIVATE ${LZMA_INCLUDE_DIRS})
target_link_libraries(hardnested PUBLIC Threads::Threads m ${LZMA_LIBRARIES})
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
    src/hidraw.c
    src/protocol.c
    src/furui.c
    src/session.c
    src/crypto1.c
    src/crack.c
    src/hardnested_glue.c
    src/nested.c
    src/dump.c
    src/ndef.c
    ${ICON_GRESOURCE})

target_include_directories(pmpro PRIVATE ${ADW_INCLUDE_DIRS} src)
target_link_directories(pmpro PRIVATE ${ADW_LIBRARY_DIRS})
target_link_libraries(pmpro PRIVATE ${ADW_LIBRARIES} hardnested)
target_compile_options(pmpro PRIVATE ${ADW_CFLAGS_OTHER})

# CLI tools (no GTK) — protocol control + RE probe
add_executable(pmctl src/pmctl.c src/hidraw.c src/furui.c src/session.c src/protocol.c src/crypto1.c src/crack.c src/hardnested_glue.c src/nested.c src/dump.c src/ndef.c)
target_link_libraries(pmctl PRIVATE hardnested)
add_executable(pmprobe src/probe.c src/hidraw.c src/protocol.c)

# Crypto-1 self-tests (cipher round-trip + key recovery from synthetic keystream)
add_executable(test_cipher   tests/test_cipher.c   src/crypto1.c)
add_executable(test_recovery tests/test_recovery.c src/crypto1.c)
add_executable(test_dump     tests/test_dump.c     src/dump.c src/protocol.c)
add_executable(test_ndef     tests/test_ndef.c     src/ndef.c)
target_include_directories(test_cipher   PRIVATE src)
target_include_directories(test_recovery PRIVATE src)
target_include_directories(test_dump     PRIVATE src)
target_include_directories(test_ndef     PRIVATE src)
enable_testing()
add_test(NAME cipher   COMMAND test_cipher)
add_test(NAME recovery COMMAND test_recovery)
add_test(NAME dump     COMMAND test_dump)
add_test(NAME ndef     COMMAND test_ndef)

install(TARGETS pmpro pmctl RUNTIME DESTINATION bin)
install(FILES data/com.furui.pmpro.desktop DESTINATION share/applications)
install(FILES data/com.furui.pmpro.svg
        DESTINATION share/icons/hicolor/scalable/apps)

# Refresh the desktop + icon caches after a system install (best-effort).
install(CODE "
  execute_process(COMMAND update-desktop-database \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/applications\" ERROR_QUIET)
  execute_process(COMMAND gtk-update-icon-cache -f -t \"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/icons/hicolor\" ERROR_QUIET)
")
