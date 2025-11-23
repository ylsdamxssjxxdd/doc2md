set(DOC2MD_SOURCES
    doc2md/document_converter.cpp
)

add_library(doc2md_lib ${DOC2MD_SOURCES})
target_include_directories(doc2md_lib
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/miniz
            ${CMAKE_SOURCE_DIR}/thirdparty/tinyxml2)
target_link_libraries(doc2md_lib PUBLIC miniz tinyxml2)

add_executable(doc2md main.cpp)
target_link_libraries(doc2md PRIVATE doc2md_lib)
