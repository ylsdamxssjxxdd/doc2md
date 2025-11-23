set(DOC2MD_SOURCES
    doc2md/document_converter.cpp
)

add_library(doc2md_lib ${DOC2MD_SOURCES})
target_include_directories(doc2md_lib
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/miniz
            ${CMAKE_SOURCE_DIR}/thirdparty/tinyxml2
            ${CMAKE_SOURCE_DIR}/thirdparty/libxls/include)
target_link_libraries(doc2md_lib PUBLIC miniz tinyxml2 libxls)
