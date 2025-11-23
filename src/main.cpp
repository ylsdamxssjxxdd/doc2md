#include "doc2md/document_converter.h"

#include <iostream>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: doc2md <file>\n";
        return 1;
    }
    doc2md::ConversionResult result = doc2md::convertFile(argv[1]);
    if (!result.success)
    {
        std::cerr << "Failed to convert file: " << argv[1] << "\n";
        return 2;
    }
    std::cout << result.markdown;
    return 0;
}
