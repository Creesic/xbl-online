# Link the Xbox Live profile library into a game without editing xboxrecomp.
#
# In the game's CMakeLists.txt, after the executable is declared:
#
#   include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/XblOnline.cmake)
#   xbl_online_link(your_game_target)
#
# XBL_ONLINE_DIR defaults to the online/ directory next to this file's parent.
# Override it if this repo is not a sibling of the game.

if(NOT XBL_ONLINE_DIR)
    get_filename_component(XBL_ONLINE_DIR "${CMAKE_CURRENT_LIST_DIR}/../online" ABSOLUTE)
endif()

function(xbl_online_link target)
    if(NOT TARGET xbl_online)
        add_subdirectory(${XBL_ONLINE_DIR} ${CMAKE_BINARY_DIR}/xbl_online EXCLUDE_FROM_ALL)
    endif()
    target_link_libraries(${target} PRIVATE xbl_online)
    if(MSVC)
        target_link_options(${target} PRIVATE "/INCLUDE:xbl_online_attach_anchor")
    elseif(APPLE)
        target_link_options(${target} PRIVATE "-Wl,-u,_xbl_online_attach_anchor")
    else()
        target_link_options(${target} PRIVATE "-Wl,--undefined=xbl_online_attach_anchor")
    endif()
endfunction()
