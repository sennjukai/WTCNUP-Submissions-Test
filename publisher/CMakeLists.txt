cmake_minimum_required(VERSION 3.20)
project(CommunityPublisher LANGUAGES CXX)

add_executable(community-publisher
    common.cpp
    zip.cpp
    community_submission_v2.cpp
    community_package_v2.cpp
    community_git_v2.cpp
    community_pipeline_v2.cpp
    community_publisher.cpp
    community_publisher_cli.cpp
)
target_include_directories(community-publisher PRIVATE .)
target_compile_features(community-publisher PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(community-publisher PRIVATE /utf-8 /W4)
endif()
target_compile_definitions(community-publisher PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 WINVER=0x0A00)
if(WIN32)
    target_link_libraries(community-publisher PRIVATE
        shell32 ole32 bcrypt normaliz advapi32 user32 uuid)
endif()
