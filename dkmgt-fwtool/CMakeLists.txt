
add_executable(fwtool
   cJSON.c
   cJSON.h
   dkmgt-firmware.c
   dkmgt-firmware.h
   main.c
)
set_target_properties(fwtool PROPERTIES OUTPUT_NAME dkmgt-fwtool)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMD REQUIRED IMPORTED_TARGET libmd)
target_link_libraries(fwtool PRIVATE PkgConfig::LIBMD)
