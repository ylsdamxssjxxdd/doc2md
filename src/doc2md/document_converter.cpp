#include "doc2md/document_converter.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <codecvt>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern "C"
{
#include "miniz.h"
}

#include "tinyxml2.h"

namespace doc2md
{
namespace detail
{
using ByteBuffer = std::vector<uint8_t>;

static std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

static std::string trim(const std::string &value)
{
    const auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    auto begin = std::find_if_not(value.begin(), value.end(), isSpace);
    auto end = std::find_if_not(value.rbegin(), value.rend(), isSpace).base();
    if (begin >= end) return {};
    return std::string(begin, end);
}

static void replaceAll(std::string &text, const std::string &from, const std::string &to)
{
    if (from.empty()) return;
    std::string::size_type pos = 0;
    while ((pos = text.find(from, pos)) != std::string::npos)
    {
        text.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static std::vector<std::string> splitLines(const std::string &text)
{
    std::vector<std::string> lines;
    std::string current;
    for (char ch : text)
    {
        if (ch == '\r') continue;
        if (ch == '\n')
        {
            lines.push_back(current);
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }
    lines.push_back(current);
    return lines;
}

static std::string join(const std::vector<std::string> &items, const std::string &separator)
{
    if (items.empty()) return {};
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i)
    {
        if (i) oss << separator;
        oss << items[i];
    }
    return oss.str();
}

static std::string escapeMarkdownCell(std::string text)
{
    replaceAll(text, "|", "\\|");
    replaceAll(text, "\r", "");
    replaceAll(text, "\n", "<br>");
    return trim(text);
}

static std::string makeMarkdownTable(const std::vector<std::vector<std::string>> &rows)
{
    if (rows.empty()) return {};
    size_t maxColumns = 0;
    for (const auto &row : rows)
        maxColumns = std::max(maxColumns, row.size());
    if (maxColumns == 0) return {};

    std::ostringstream oss;
    auto writeRow = [&](const std::vector<std::string> &row) {
        oss << "| ";
        for (size_t i = 0; i < maxColumns; ++i)
        {
            if (i) oss << " | ";
            if (i < row.size())
                oss << escapeMarkdownCell(row[i]);
            else
                oss << "";
        }
        oss << " |\n";
    };

    writeRow(rows.front());
    oss << "| ";
    for (size_t i = 0; i < maxColumns; ++i)
    {
        if (i) oss << " | ";
        oss << "---";
    }
    oss << " |\n";
    for (size_t i = 1; i < rows.size(); ++i)
        writeRow(rows[i]);
    std::string table = oss.str();
    if (!table.empty() && table.back() == '\n') table.pop_back();
    return table;
}

static std::string readBinaryFile(const std::string &path)
{
    std::ifstream stream(path.c_str(), std::ios::binary);
    if (!stream) return {};
    return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

static std::string readTextFile(const std::string &path)
{
    std::ifstream stream(path.c_str(), std::ios::binary);
    if (!stream) return {};
    std::ostringstream oss;
    oss << stream.rdbuf();
    return oss.str();
}

static std::string utf16ToUtf8(const char16_t *data, size_t length)
{
    static std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    return converter.to_bytes(data, data + length);
}

static std::string utf16ToUtf8(const std::u16string &str)
{
    return utf16ToUtf8(str.data(), str.size());
}

static std::string latin1ToUtf8(const std::string &text)
{
    std::string out;
    out.reserve(text.size() * 2);
    for (unsigned char ch : text)
    {
        if (ch < 0x80)
            out.push_back(static_cast<char>(ch));
        else
        {
            out.push_back(static_cast<char>(0xC0 | (ch >> 6)));
            out.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        }
    }
    return out;
}

class ZipArchive
{
public:
    ZipArchive() { std::memset(&m_archive, 0, sizeof(m_archive)); }
    ~ZipArchive() { close(); }

    bool open(const std::string &path)
    {
        close();
        const std::string bytes = readBinaryFile(path);
        if (bytes.empty()) return false;
        m_storage.assign(bytes.begin(), bytes.end());
        if (!mz_zip_reader_init_mem(&m_archive, m_storage.data(), m_storage.size(), 0))
        {
            close();
            return false;
        }
        m_open = true;
        return true;
    }

    std::string fileContent(const std::string &name) const
    {
        if (!m_open) return {};
        const int index = mz_zip_reader_locate_file(const_cast<mz_zip_archive *>(&m_archive), name.c_str(), nullptr, 0);
        if (index < 0) return {};
        size_t outSize = 0;
        void *ptr = mz_zip_reader_extract_to_heap(const_cast<mz_zip_archive *>(&m_archive), index, &outSize, 0);
        if (!ptr || outSize == 0)
        {
            if (ptr) mz_free(ptr);
            return {};
        }
        std::string data(static_cast<const char *>(ptr), static_cast<size_t>(outSize));
        mz_free(ptr);
        return data;
    }

    std::vector<std::string> filesWithPrefix(const std::string &prefix) const
    {
        std::vector<std::string> names;
        if (!m_open) return names;
        const int count = static_cast<int>(mz_zip_reader_get_num_files(&m_archive));
        for (int i = 0; i < count; ++i)
        {
            mz_zip_archive_file_stat statRecord;
            if (!mz_zip_reader_file_stat(const_cast<mz_zip_archive *>(&m_archive), i, &statRecord))
                continue;
            std::string name = statRecord.m_filename ? statRecord.m_filename : "";
            if (name.compare(0, prefix.size(), prefix) == 0) names.push_back(name);
        }
        std::sort(names.begin(), names.end());
        return names;
    }

private:
    void close()
    {
        if (m_open)
        {
            mz_zip_reader_end(&m_archive);
            m_open = false;
        }
        m_storage.clear();
    }

    mutable mz_zip_archive m_archive;
    ByteBuffer m_storage;
    bool m_open = false;
};

constexpr uint32_t OleFreeSector = 0xFFFFFFFFu;
constexpr uint32_t OleEndOfChain = 0xFFFFFFFEu;

struct OleDirectoryEntry
{
    std::string name;
    uint8_t type = 0;
    uint32_t startSector = OleEndOfChain;
    uint64_t size = 0;
};

class CompoundFileReader
{
public:
    bool load(const std::string &path);
    std::string streamByName(const std::string &name) const;

private:
    int sectorSize() const { return 1 << m_sectorShift; }
    int miniSectorSize() const { return 1 << m_miniSectorShift; }
    int64_t sectorOffset(uint32_t sector) const;
    std::string sectorData(uint32_t sector) const;
    bool appendDifatSector(uint32_t sector, std::vector<uint32_t> &difat);
    bool buildFat(const std::vector<uint32_t> &difat);
    bool buildMiniFat(uint32_t startSector, uint32_t sectorCount);
    bool buildDirectory();
    bool buildMiniStream();
    std::string readStream(uint32_t startSector, uint64_t size, bool useMini) const;
    uint32_t nextSector(uint32_t current) const;

    ByteBuffer m_data;
    std::vector<uint32_t> m_fat;
    std::vector<uint32_t> m_miniFat;
    std::vector<OleDirectoryEntry> m_entries;
    ByteBuffer m_miniStream;
    uint16_t m_sectorShift = 9;
    uint16_t m_miniSectorShift = 6;
    uint32_t m_miniStreamCutoff = 4096;
    uint32_t m_firstDirSector = 0;
    uint32_t m_firstMiniFatSector = OleEndOfChain;
    uint32_t m_numMiniFatSectors = 0;
    uint16_t m_majorVersion = 3;
    bool m_valid = false;
};

template <typename T>
static T readLe(const uint8_t *ptr)
{
    T value = 0;
    std::memcpy(&value, ptr, sizeof(T));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t *raw = reinterpret_cast<uint8_t *>(&value);
    std::reverse(raw, raw + sizeof(T));
#endif
    return value;
}

bool CompoundFileReader::load(const std::string &path)
{
    m_valid = false;
    const std::string bytes = readBinaryFile(path);
    if (bytes.size() < 512) return false;
    m_data.assign(bytes.begin(), bytes.end());

    const uint8_t *header = m_data.data();
    const uint64_t signature = readLe<uint64_t>(header);
    if (signature != 0xE11AB1A1E011CFD0ULL) return false;

    m_majorVersion = readLe<uint16_t>(header + 0x1A);
    const uint16_t byteOrder = readLe<uint16_t>(header + 0x1C);
    if (byteOrder != 0xFFFE) return false;
    m_sectorShift = readLe<uint16_t>(header + 0x1E);
    m_miniSectorShift = readLe<uint16_t>(header + 0x20);
    m_miniStreamCutoff = readLe<uint32_t>(header + 0x38);
    m_firstDirSector = readLe<uint32_t>(header + 0x30);
    m_firstMiniFatSector = readLe<uint32_t>(header + 0x3C);
    m_numMiniFatSectors = readLe<uint32_t>(header + 0x40);
    uint32_t firstDifatSector = readLe<uint32_t>(header + 0x44);
    uint32_t numDifatSectors = readLe<uint32_t>(header + 0x48);

    std::vector<uint32_t> difat;
    difat.reserve(128);
    const uint8_t *difatHead = header + 0x4C;
    for (int i = 0; i < 109; ++i)
    {
        uint32_t entry = readLe<uint32_t>(difatHead + i * 4);
        if (entry != OleFreeSector) difat.push_back(entry);
    }
    uint32_t difatSector = firstDifatSector;
    while (numDifatSectors > 0 && difatSector != OleEndOfChain)
    {
        if (!appendDifatSector(difatSector, difat)) return false;
        const std::string block = sectorData(difatSector);
        if (block.size() != static_cast<size_t>(sectorSize())) return false;
        difatSector = readLe<uint32_t>(reinterpret_cast<const uint8_t *>(block.data()) + sectorSize() - 4);
        --numDifatSectors;
    }
    if (!buildFat(difat)) return false;
    if (!buildMiniFat(m_firstMiniFatSector, m_numMiniFatSectors)) return false;
    if (!buildDirectory()) return false;
    if (!buildMiniStream()) return false;
    m_valid = true;
    return true;
}

std::string CompoundFileReader::streamByName(const std::string &name) const
{
    if (!m_valid) return {};
    std::string lower = toLower(name);
    for (const auto &entry : m_entries)
    {
        if (entry.type != 2) continue;
        if (toLower(entry.name) != lower) continue;
        const bool useMini = entry.size < m_miniStreamCutoff && !m_miniStream.empty();
        return readStream(entry.startSector, entry.size, useMini);
    }
    return {};
}

int64_t CompoundFileReader::sectorOffset(uint32_t sector) const
{
    if (sector == OleEndOfChain) return -1;
    const int64_t offset = 512 + static_cast<int64_t>(sector) * sectorSize();
    if (offset < 0 || offset + sectorSize() > static_cast<int64_t>(m_data.size())) return -1;
    return offset;
}

std::string CompoundFileReader::sectorData(uint32_t sector) const
{
    const int64_t offset = sectorOffset(sector);
    if (offset < 0) return {};
    return std::string(reinterpret_cast<const char *>(m_data.data()) + offset, sectorSize());
}

bool CompoundFileReader::appendDifatSector(uint32_t sector, std::vector<uint32_t> &difat)
{
    const std::string block = sectorData(sector);
    if (block.size() != static_cast<size_t>(sectorSize())) return false;
    const int intsPerSector = sectorSize() / 4;
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(block.data());
    for (int i = 0; i < intsPerSector - 1; ++i)
    {
        uint32_t value = readLe<uint32_t>(ptr + i * 4);
        if (value != OleFreeSector) difat.push_back(value);
    }
    return true;
}

bool CompoundFileReader::buildFat(const std::vector<uint32_t> &difat)
{
    if (difat.empty()) return false;
    m_fat.clear();
    const int intsPerSector = sectorSize() / 4;
    for (uint32_t sector : difat)
    {
        const std::string block = sectorData(sector);
        if (block.size() != static_cast<size_t>(sectorSize())) return false;
        const uint8_t *ptr = reinterpret_cast<const uint8_t *>(block.data());
        for (int i = 0; i < intsPerSector; ++i)
            m_fat.push_back(readLe<uint32_t>(ptr + i * 4));
    }
    return !m_fat.empty();
}

bool CompoundFileReader::buildMiniFat(uint32_t startSector, uint32_t sectorCount)
{
    m_miniFat.clear();
    if (startSector == OleEndOfChain || sectorCount == 0) return true;
    uint32_t sector = startSector;
    const int intsPerSector = sectorSize() / 4;
    for (uint32_t i = 0; i < sectorCount && sector != OleEndOfChain; ++i)
    {
        const std::string block = sectorData(sector);
        if (block.size() != static_cast<size_t>(sectorSize())) return false;
        const uint8_t *ptr = reinterpret_cast<const uint8_t *>(block.data());
        for (int j = 0; j < intsPerSector; ++j)
            m_miniFat.push_back(readLe<uint32_t>(ptr + j * 4));
        sector = nextSector(sector);
    }
    return true;
}

bool CompoundFileReader::buildDirectory()
{
    const std::string dirStream = readStream(m_firstDirSector, 0, false);
    if (dirStream.empty()) return false;
    m_entries.clear();
    const int entrySize = 128;
    const int count = static_cast<int>(dirStream.size()) / entrySize;
    for (int i = 0; i < count; ++i)
    {
        const uint8_t *base = reinterpret_cast<const uint8_t *>(dirStream.data()) + i * entrySize;
        const uint16_t nameLen = readLe<uint16_t>(base + 64);
        if (nameLen < 2) continue;
        const int charCount = std::max(0, std::min<int>(32, nameLen / 2 - 1));
        std::u16string name;
        name.resize(charCount);
        std::memcpy(&name[0], base, charCount * sizeof(char16_t));
        OleDirectoryEntry entry;
        entry.name = utf16ToUtf8(name);
        entry.type = static_cast<uint8_t>(base[66]);
        entry.startSector = readLe<uint32_t>(base + 116);
        if (m_majorVersion >= 4)
            entry.size = readLe<uint64_t>(base + 120);
        else
            entry.size = readLe<uint32_t>(base + 120);
        m_entries.push_back(entry);
    }
    return !m_entries.empty();
}

bool CompoundFileReader::buildMiniStream()
{
    auto it = std::find_if(m_entries.begin(), m_entries.end(), [](const OleDirectoryEntry &entry) { return entry.type == 5; });
    if (it == m_entries.end()) return false;
    const std::string root = readStream(it->startSector, it->size, false);
    m_miniStream.assign(root.begin(), root.end());
    return true;
}

std::string CompoundFileReader::readStream(uint32_t startSector, uint64_t size, bool useMini) const
{
    if (startSector == OleEndOfChain) return {};
    std::string buffer;
    if (useMini)
    {
        uint32_t sector = startSector;
        uint64_t remaining = size;
        const int miniSz = miniSectorSize();
        while (sector != OleEndOfChain && remaining > 0)
        {
            const int64_t offset = static_cast<int64_t>(sector) * miniSz;
            if (offset < 0 || offset + miniSz > static_cast<int64_t>(m_miniStream.size())) break;
            const int chunk = static_cast<int>(std::min<uint64_t>(remaining, miniSz));
            buffer.append(reinterpret_cast<const char *>(m_miniStream.data()) + offset, chunk);
            remaining -= chunk;
            if (sector >= m_miniFat.size()) break;
            sector = m_miniFat[sector];
        }
        if (size && buffer.size() > size) buffer.resize(static_cast<size_t>(size));
        return buffer;
    }

    uint32_t sector = startSector;
    uint64_t remaining = size;
    const int sectorSz = sectorSize();
    while (sector != OleEndOfChain && (remaining > 0 || size == 0))
    {
        const int64_t offset = sectorOffset(sector);
        if (offset < 0) break;
        const int chunk = static_cast<int>((size == 0) ? sectorSz : std::min<uint64_t>(remaining, sectorSz));
        buffer.append(reinterpret_cast<const char *>(m_data.data()) + offset, chunk);
        if (size)
        {
            remaining -= chunk;
            if (remaining == 0) break;
        }
        sector = nextSector(sector);
    }
    if (size && buffer.size() > size) buffer.resize(static_cast<size_t>(size));
    return buffer;
}

uint32_t CompoundFileReader::nextSector(uint32_t current) const
{
    if (current >= m_fat.size()) return OleEndOfChain;
    return m_fat[current];
}

static std::string markdownToText(std::string md)
{
    std::regex fenced("```[\\s\\S]*?```", std::regex::optimize);
    md = std::regex_replace(md, fenced, "");
    md = std::regex_replace(md, std::regex("`([^`]*)`"), "$1");
    md = std::regex_replace(md, std::regex("!\\[([^\\]]*)\\]\\([^\\)]*\\)"), "$1");
    md = std::regex_replace(md, std::regex("\\[([^\\]]*)\\]\\([^\\)]*\\)"), "$1");
    md = std::regex_replace(md, std::regex("(?m)^\\s*#+\\s*"), "");
    md = std::regex_replace(md, std::regex("(?m)^>\\s*"), "");
    md = std::regex_replace(md, std::regex("(?m)^\\|.*\\|$"), "");
    md = std::regex_replace(md, std::regex("(?m)^\\s*\\|?\\s*:-*:?\\s*(\\|\\s*:-*:?\\s*)*$"), "");
    md = std::regex_replace(md, std::regex("<[^>]+>"), "");
    replaceAll(md, "**", "");
    replaceAll(md, "*", "");
    return md;
}

static std::string htmlToText(std::string html)
{
    html = std::regex_replace(html, std::regex("<style[\\s\\S]*?</style>", std::regex::icase), "");
    html = std::regex_replace(html, std::regex("<script[\\s\\S]*?</script>", std::regex::icase), "");
    html = std::regex_replace(html, std::regex("<br\\s*/?>", std::regex::icase), "\n");
    html = std::regex_replace(html, std::regex("</p>", std::regex::icase), "\n\n");
    html = std::regex_replace(html, std::regex("<[^>]+>"), "");
    replaceAll(html, "&nbsp;", " ");
    replaceAll(html, "&lt;", "<");
    replaceAll(html, "&gt;", ">");
    replaceAll(html, "&amp;", "&");
    return trim(html);
}

struct TextPiece
{
    uint32_t cpStart = 0;
    uint32_t cpEnd = 0;
    uint32_t fileOffset = 0;
    bool unicode = false;
};

struct FibInfo
{
    bool useTable1 = false;
    bool complex = false;
    uint32_t fcMin = 0;
    uint32_t fcMac = 0;
    uint32_t fcClx = 0;
    uint32_t lcbClx = 0;
};

static bool parseFib(const std::string &wordStream, FibInfo &info)
{
    if (wordStream.size() < 256) return false;
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(wordStream.data());
    if (readLe<uint16_t>(ptr) != 0xA5EC) return false;
    const uint16_t flags = readLe<uint16_t>(ptr + 0x0A);
    info.useTable1 = (flags & 0x0200) != 0;
    info.complex = (flags & 0x0004) != 0;
    info.fcMin = readLe<uint32_t>(ptr + 0x18);
    info.fcMac = readLe<uint32_t>(ptr + 0x1C);

    int pos = 32;
    if (wordStream.size() < pos + 2) return false;
    const uint16_t csw = readLe<uint16_t>(ptr + pos);
    pos += 2 + csw * 2;
    if (wordStream.size() < pos + 2) return false;
    const uint16_t cslw = readLe<uint16_t>(ptr + pos);
    pos += 2 + cslw * 4;
    if (wordStream.size() < pos + 2) return false;
    const uint16_t cbRgFcLcb = readLe<uint16_t>(ptr + pos);
    pos += 2;
    if (wordStream.size() < pos + cbRgFcLcb * 8) return false;
    const int idx = 33;
    if (cbRgFcLcb > idx)
    {
        const int offset = pos + idx * 8;
        info.fcClx = readLe<uint32_t>(ptr + offset);
        info.lcbClx = readLe<uint32_t>(ptr + offset + 4);
    }
    return true;
}

static std::vector<TextPiece> parseTextPieces(const std::string &tableStream, uint32_t fcClx, uint32_t lcbClx)
{
    std::vector<TextPiece> pieces;
    if (fcClx == 0 || lcbClx == 0) return pieces;
    if (fcClx + lcbClx > tableStream.size()) return pieces;
    const uint8_t *clx = reinterpret_cast<const uint8_t *>(tableStream.data() + fcClx);
    int pos = 0;
    while (pos < static_cast<int>(lcbClx))
    {
        const uint8_t clxt = clx[pos++];
        if (clxt == 0x01)
        {
            if (pos + 4 > static_cast<int>(lcbClx)) break;
            const uint32_t lcb = readLe<uint32_t>(clx + pos);
            pos += 4;
            if (lcb == 0 || pos + static_cast<int>(lcb) > static_cast<int>(lcbClx)) break;
            const uint8_t *plc = clx + pos;
            pos += static_cast<int>(lcb);
            const int pieceCount = (static_cast<int>(lcb) - 4) / (8 + 4);
            if (pieceCount <= 0) break;
            std::vector<uint32_t> cps(pieceCount + 1);
            for (size_t i = 0; i < cps.size(); ++i)
                cps[i] = readLe<uint32_t>(plc + i * 4);
            const uint8_t *pcd = plc + (pieceCount + 1) * 4;
            for (int i = 0; i < pieceCount; ++i)
            {
                const uint32_t fc = readLe<uint32_t>(pcd + i * 8 + 2);
                const bool unicode = (fc & 0x40000000u) == 0;
                const uint32_t fileOffset = unicode ? fc : (fc & 0x3FFFFFFFu) / 2;
                TextPiece piece;
                piece.cpStart = cps[i];
                piece.cpEnd = cps[i + 1];
                piece.fileOffset = fileOffset;
                piece.unicode = unicode;
                pieces.push_back(piece);
            }
            break;
        }
        else if (clxt == 0x02)
        {
            if (pos + 2 > static_cast<int>(lcbClx)) break;
            const uint16_t cb = readLe<uint16_t>(clx + pos);
            pos += 2 + cb;
        }
        else
        {
            break;
        }
    }
    return pieces;
}

static std::string decodePieces(const std::string &wordStream, const std::vector<TextPiece> &pieces)
{
    if (pieces.empty()) return {};
    std::string out;
    for (const TextPiece &piece : pieces)
    {
        if (piece.cpEnd <= piece.cpStart) continue;
        const uint32_t charCount = piece.cpEnd - piece.cpStart;
        const uint32_t byteCount = piece.unicode ? charCount * 2 : charCount;
        if (piece.fileOffset + byteCount > wordStream.size()) continue;
        if (piece.unicode)
        {
            const char16_t *src = reinterpret_cast<const char16_t *>(wordStream.data() + piece.fileOffset);
            out += utf16ToUtf8(src, charCount);
        }
        else
        {
            const std::string bytes(wordStream.data() + piece.fileOffset, byteCount);
            out += latin1ToUtf8(bytes);
        }
    }
    return out;
}

static std::string decodeSimpleRange(const std::string &wordStream, uint32_t fcMin, uint32_t fcMac)
{
    if (fcMac <= fcMin || fcMin >= wordStream.size()) return {};
    uint32_t limit = std::min<uint32_t>(fcMac, wordStream.size());
    uint32_t span = limit - fcMin;
    if (span < 4) return {};
    if (span % 2 != 0) --span;
    const char16_t *src = reinterpret_cast<const char16_t *>(wordStream.data() + fcMin);
    return utf16ToUtf8(src, span / 2);
}

static std::string normalizeWordText(const std::string &raw)
{
    if (raw.empty()) return {};
    std::string cleaned;
    cleaned.reserve(raw.size());
    for (unsigned char byte : raw)
    {
        if (byte == 0x00) continue;
        if (byte == 0x0D || byte == 0x07 || byte == 0x0B || byte == 0x0C || byte == 0x1E || byte == 0x1F)
            cleaned.push_back('\n');
        else
            cleaned.push_back(static_cast<char>(byte));
    }
    std::vector<std::string> lines = splitLines(cleaned);
    std::vector<std::string> filtered;
    for (const std::string &line : lines)
    {
        const std::string trimmedLine = trim(line);
        if (!trimmedLine.empty()) filtered.push_back(trimmedLine);
    }
    return join(filtered, "\n");
}

static bool looksLikeDocumentText(const std::string &chunk)
{
    const std::string trimmedText = trim(chunk);
    if (trimmedText.size() < 2 || trimmedText.size() > 1024) return false;
    static const std::unordered_set<std::string> noise = {
        "Root Entry", "SummaryInformation", "DocumentSummaryInformation", "WordDocument",
        "0Table", "1Table", "Normal.dotm", "WpsCustomData", "KSOProductBuildVer",
        "KSOTemplateDocerSaveRecord"};
    if (noise.count(trimmedText)) return false;
    return true;
}

static int chunkScore(const std::string &chunk)
{
    int cjk = 0;
    int digits = 0;
    int asciiAlpha = 0;
    for (unsigned char ch : chunk)
    {
        if (ch >= 0x4E && ch <= 0x9F) ++cjk;
        if (std::isdigit(ch)) ++digits;
        if (std::isalpha(ch) && ch < 0x80) ++asciiAlpha;
    }
    int score = cjk * 5 + digits * 3 - asciiAlpha;
    if (digits >= 6 && digits >= cjk && digits > asciiAlpha) score += digits * 10;
    return score;
}

static std::string extractUtf16Text(const std::string &data)
{
    if (data.empty()) return {};
    std::vector<std::string> chunks;
    std::u16string current;
    bool reading = false;
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(data.data());
    for (size_t offset = 0; offset + 1 < data.size(); offset += 2)
    {
        uint16_t value = readLe<uint16_t>(ptr + offset);
        if (value >= 0x20 && value != 0xFFFF && value != 0xFFFE)
        {
            reading = true;
            if (value == 0x000D || value == 0x000A)
                current.push_back(u'\n');
            else
                current.push_back(static_cast<char16_t>(value));
        }
        else if (reading)
        {
            if (current.size() >= 3) chunks.push_back(utf16ToUtf8(current));
            current.clear();
            reading = false;
        }
    }
    if (reading && current.size() >= 3) chunks.push_back(utf16ToUtf8(current));

    std::unordered_set<std::string> seen;
    std::vector<std::string> filtered;
    for (const std::string &chunk : chunks)
    {
        const std::string trimmedChunk = trim(chunk);
        if (trimmedChunk.empty() || !looksLikeDocumentText(trimmedChunk)) continue;
        if (seen.insert(trimmedChunk).second) filtered.push_back(trimmedChunk);
    }

    if (filtered.size() > 1)
    {
        std::vector<int> scores;
        scores.reserve(filtered.size());
        int bestScore = std::numeric_limits<int>::min();
        for (const std::string &chunk : filtered)
        {
            const int score = chunkScore(chunk);
            scores.push_back(score);
            bestScore = std::max(bestScore, score);
        }
        const int cutoff = bestScore > 0 ? bestScore - 4 : bestScore;
        std::vector<std::string> prioritized;
        for (size_t i = 0; i < filtered.size(); ++i)
        {
            if (scores[i] >= cutoff && scores[i] > 0) prioritized.push_back(filtered[i]);
        }
        if (!prioritized.empty()) filtered = prioritized;
    }
    return join(filtered, "\n");
}

static std::string readWpsViaWordBinary(const std::string &path)
{
    CompoundFileReader reader;
    if (!reader.load(path)) return {};
    const std::string wordStream = reader.streamByName("WordDocument");
    if (wordStream.empty()) return {};
    FibInfo fib;
    if (!parseFib(wordStream, fib)) return {};
    const std::string tableStream = reader.streamByName(fib.useTable1 ? "1Table" : "0Table");
    std::string raw;
    if (!tableStream.empty() && fib.fcClx && fib.lcbClx)
    {
        const std::vector<TextPiece> pieces = parseTextPieces(tableStream, fib.fcClx, fib.lcbClx);
        raw = decodePieces(wordStream, pieces);
    }
    if (raw.empty()) raw = decodeSimpleRange(wordStream, fib.fcMin, fib.fcMac);
    return normalizeWordText(raw);
}

static std::string readWpsHeuristic(const std::string &path)
{
    return extractUtf16Text(readBinaryFile(path));
}

static std::string readWpsText(const std::string &path)
{
    std::string parsed = readWpsViaWordBinary(path);
    if (!parsed.empty()) return parsed;
    return readWpsHeuristic(path);
}

static std::string readCompoundUtf16Stream(const std::string &path, const std::vector<std::string> &streamNames)
{
    CompoundFileReader reader;
    if (!reader.load(path)) return {};
    for (const std::string &name : streamNames)
    {
        const std::string data = reader.streamByName(name);
        if (data.empty()) continue;
        const std::string text = extractUtf16Text(data);
        if (!text.empty()) return text;
    }
    return {};
}

static std::string formatMarkdownList(const std::string &text)
{
    const std::vector<std::string> lines = splitLines(text);
    std::vector<std::string> formatted;
    formatted.reserve(lines.size());
    for (const std::string &line : lines)
    {
        const std::string trimmedLine = trim(line);
        if (!trimmedLine.empty()) formatted.push_back("- " + trimmedLine);
    }
    return join(formatted, "\n");
}

static std::string readEtText(const std::string &path)
{
    std::string text = readCompoundUtf16Stream(path, {"Workbook"});
    if (text.empty()) text = readWpsHeuristic(path);
    if (text.empty()) return {};
    return "## ET Workbook\n\n" + text;
}

static std::string readDpsText(const std::string &path)
{
    std::string text = readCompoundUtf16Stream(path, {"PowerPoint Document"});
    if (text.empty()) text = readWpsHeuristic(path);
    if (text.empty()) return {};
    const std::string list = formatMarkdownList(text);
    if (list.empty()) return text;
    return "## DPS Slides\n\n" + list;
}

static const tinyxml2::XMLElement *findChildElement(const tinyxml2::XMLElement *root, const char *name)
{
    for (auto element = root ? root->FirstChildElement() : nullptr; element; element = element->NextSiblingElement())
    {
        if (std::strcmp(element->Name(), name) == 0) return element;
    }
    return nullptr;
}

static void collectWordText(const tinyxml2::XMLElement *node, std::string &out)
{
    if (!node) return;
    const char *name = node->Name();
    if (std::strcmp(name, "w:t") == 0)
    {
        if (const char *text = node->GetText()) out += text;
        return;
    }
    if (std::strcmp(name, "w:br") == 0 || std::strcmp(name, "w:cr") == 0)
    {
        out.push_back('\n');
        return;
    }
    if (std::strcmp(name, "w:tab") == 0)
    {
        out.push_back(' ');
        return;
    }
    for (auto child = node->FirstChildElement(); child; child = child->NextSiblingElement())
        collectWordText(child, out);
}

static std::string docxParagraphStyle(const tinyxml2::XMLElement *paragraph)
{
    const auto *pPr = findChildElement(paragraph, "w:pPr");
    if (!pPr) return {};
    const auto *style = findChildElement(pPr, "w:pStyle");
    if (!style) return {};
    if (const char *val = style->Attribute("w:val")) return val;
    if (const char *legacy = style->Attribute("val")) return legacy;
    return {};
}

static std::string formatDocxParagraph(const tinyxml2::XMLElement *paragraph)
{
    std::string text;
    collectWordText(paragraph, text);
    const std::string trimmedText = trim(text);
    if (trimmedText.empty()) return {};
    const std::string style = docxParagraphStyle(paragraph);
    if (!style.empty() && style.size() > 7 && style.substr(0, 7) == "Heading")
    {
        try
        {
            int level = std::stoi(style.substr(7));
            level = std::max(1, std::min(6, level));
            return std::string(static_cast<size_t>(level), '#') + " " + trimmedText;
        }
        catch (...)
        {
            // fall back to plain text
        }
    }
    return trimmedText;
}

static std::string parseDocxTable(const tinyxml2::XMLElement *tbl);

static std::string readDocxTableCell(const tinyxml2::XMLElement *cell)
{
    std::vector<std::string> fragments;
    for (auto child = cell->FirstChildElement(); child; child = child->NextSiblingElement())
    {
        const char *name = child->Name();
        if (std::strcmp(name, "w:p") == 0)
        {
            const std::string paragraph = formatDocxParagraph(child);
            if (!paragraph.empty()) fragments.push_back(paragraph);
        }
        else if (std::strcmp(name, "w:tbl") == 0)
        {
            const std::string nested = parseDocxTable(child);
            if (!nested.empty()) fragments.push_back(nested);
        }
    }
    return join(fragments, "\n");
}

static std::string parseDocxTable(const tinyxml2::XMLElement *tbl)
{
    std::vector<std::vector<std::string>> rows;
    for (auto row = tbl->FirstChildElement("w:tr"); row; row = row->NextSiblingElement("w:tr"))
    {
        std::vector<std::string> cells;
        for (auto cell = row->FirstChildElement("w:tc"); cell; cell = cell->NextSiblingElement("w:tc"))
            cells.push_back(readDocxTableCell(cell));
        if (!cells.empty()) rows.push_back(cells);
    }
    return makeMarkdownTable(rows);
}

static std::string parseDocxDocumentXml(const std::string &xml)
{
    tinyxml2::XMLDocument doc;
    if (doc.Parse(xml.c_str(), xml.size()) != tinyxml2::XML_SUCCESS) return {};
    const auto *root = doc.RootElement();
    if (!root) return {};
    const auto *body = findChildElement(root, "w:body");
    if (!body) return {};
    std::vector<std::string> blocks;
    for (auto node = body->FirstChildElement(); node; node = node->NextSiblingElement())
    {
        const char *name = node->Name();
        if (std::strcmp(name, "w:p") == 0)
        {
            const std::string block = formatDocxParagraph(node);
            if (!block.empty()) blocks.push_back(block);
        }
        else if (std::strcmp(name, "w:tbl") == 0)
        {
            const std::string table = parseDocxTable(node);
            if (!table.empty()) blocks.push_back(table);
        }
    }
    return join(blocks, "\n\n");
}

static std::string readDocxText(const std::string &path)
{
    ZipArchive zip;
    if (!zip.open(path)) return {};
    const std::string xml = zip.fileContent("word/document.xml");
    if (xml.empty()) return {};
    return parseDocxDocumentXml(xml);
}

static std::string collectInlineString(const tinyxml2::XMLElement *element)
{
    std::string text;
    for (auto child = element->FirstChildElement(); child; child = child->NextSiblingElement())
    {
        if (std::strcmp(child->Name(), "t") == 0)
        {
            if (const char *value = child->GetText()) text += value;
        }
        else
        {
            text += collectInlineString(child);
        }
    }
    return trim(text);
}

static std::vector<std::string> parseSharedStringsXml(const std::string &xml)
{
    std::vector<std::string> values;
    if (xml.empty()) return values;
    tinyxml2::XMLDocument doc;
    if (doc.Parse(xml.c_str(), xml.size()) != tinyxml2::XML_SUCCESS) return values;
    for (auto entry = doc.RootElement() ? doc.RootElement()->FirstChildElement("si") : nullptr; entry; entry = entry->NextSiblingElement("si"))
    {
        std::string text;
        for (auto child = entry->FirstChildElement(); child; child = child->NextSiblingElement())
        {
            if (std::strcmp(child->Name(), "t") == 0)
            {
                if (const char *value = child->GetText()) text += value;
            }
            else
            {
                text += collectInlineString(child);
            }
        }
        values.push_back(trim(text));
    }
    return values;
}

static std::string readWorksheetCell(const tinyxml2::XMLElement *cell, const std::vector<std::string> &sharedStrings)
{
    const char *type = cell->Attribute("t");
    if (type && std::strcmp(type, "inlineStr") == 0)
    {
        if (const auto *inlineStr = cell->FirstChildElement("is")) return collectInlineString(inlineStr);
        return {};
    }
    if (type && std::strcmp(type, "s") == 0)
    {
        const auto *valueElement = cell->FirstChildElement("v");
        if (!valueElement) return {};
        const int idx = valueElement->IntText(-1);
        if (idx >= 0 && idx < static_cast<int>(sharedStrings.size())) return sharedStrings[idx];
        return valueElement->GetText() ? valueElement->GetText() : "";
    }
    const auto *valueElement = cell->FirstChildElement("v");
    if (!valueElement) return {};
    const char *value = valueElement->GetText();
    return value ? trim(value) : "";
}

static std::vector<std::vector<std::string>> parseWorksheet(const std::string &xml, const std::vector<std::string> &sharedStrings)
{
    std::vector<std::vector<std::string>> rows;
    tinyxml2::XMLDocument doc;
    if (doc.Parse(xml.c_str(), xml.size()) != tinyxml2::XML_SUCCESS) return rows;
    const auto *sheetData = doc.RootElement() ? doc.RootElement()->FirstChildElement("sheetData") : nullptr;
    if (!sheetData) return rows;
    for (auto row = sheetData->FirstChildElement("row"); row; row = row->NextSiblingElement("row"))
    {
        std::vector<std::string> cells;
        for (auto cell = row->FirstChildElement("c"); cell; cell = cell->NextSiblingElement("c"))
            cells.push_back(readWorksheetCell(cell, sharedStrings));
        if (!cells.empty()) rows.push_back(cells);
    }
    return rows;
}

static int extractTrailingNumber(const std::string &name)
{
    int i = static_cast<int>(name.size()) - 1;
    while (i >= 0 && !std::isdigit(static_cast<unsigned char>(name[i]))) --i;
    if (i < 0) return 0;
    const int end = i;
    while (i >= 0 && std::isdigit(static_cast<unsigned char>(name[i]))) --i;
    return std::stoi(name.substr(i + 1, end - i));
}

static std::string readXlsxText(const std::string &path)
{
    ZipArchive zip;
    if (!zip.open(path)) return {};
    const std::vector<std::string> sharedStrings = parseSharedStringsXml(zip.fileContent("xl/sharedStrings.xml"));
    std::vector<std::string> sheetFiles = zip.filesWithPrefix("xl/worksheets/sheet");
    if (sheetFiles.empty()) return {};
    std::sort(sheetFiles.begin(), sheetFiles.end(), [](const std::string &a, const std::string &b) {
        const int na = extractTrailingNumber(a);
        const int nb = extractTrailingNumber(b);
        if (na == nb) return a < b;
        return na < nb;
    });

    std::vector<std::string> sheets;
    int index = 1;
    for (const std::string &sheetFile : sheetFiles)
    {
        const std::string xml = zip.fileContent(sheetFile);
        if (xml.empty()) continue;
        const auto rows = parseWorksheet(xml, sharedStrings);
        if (rows.empty()) continue;
        const std::string table = makeMarkdownTable(rows);
        if (table.empty()) continue;
        sheets.push_back("## Sheet " + std::to_string(index++) + "\n\n" + table);
    }
    return join(sheets, "\n\n");
}

static void collectSlideParagraphs(const tinyxml2::XMLElement *node, std::vector<std::string> &paragraphs)
{
    if (!node) return;
    if (std::strcmp(node->Name(), "a:p") == 0)
    {
        std::string text;
        for (auto child = node->FirstChildElement(); child; child = child->NextSiblingElement())
        {
            if (std::strcmp(child->Name(), "a:t") == 0)
            {
                if (const char *value = child->GetText()) text += value;
            }
            else if (std::strcmp(child->Name(), "a:br") == 0)
            {
                text.push_back('\n');
            }
            else
            {
                collectSlideParagraphs(child, paragraphs);
            }
        }
        const std::string trimmedText = trim(text);
        if (!trimmedText.empty()) paragraphs.push_back("- " + trimmedText);
        return;
    }
    for (auto child = node->FirstChildElement(); child; child = child->NextSiblingElement())
        collectSlideParagraphs(child, paragraphs);
}

static std::string parseSlideXml(const std::string &xml)
{
    tinyxml2::XMLDocument doc;
    if (doc.Parse(xml.c_str(), xml.size()) != tinyxml2::XML_SUCCESS) return {};
    std::vector<std::string> paragraphs;
    collectSlideParagraphs(doc.RootElement(), paragraphs);
    return join(paragraphs, "\n");
}

static std::string readPptxText(const std::string &path)
{
    ZipArchive zip;
    if (!zip.open(path)) return {};
    std::vector<std::string> slideFiles = zip.filesWithPrefix("ppt/slides/slide");
    if (slideFiles.empty()) return {};
    std::sort(slideFiles.begin(), slideFiles.end(), [](const std::string &a, const std::string &b) {
        const int na = extractTrailingNumber(a);
        const int nb = extractTrailingNumber(b);
        if (na == nb) return a < b;
        return na < nb;
    });
    std::vector<std::string> slides;
    int index = 1;
    for (const std::string &slideFile : slideFiles)
    {
        const std::string slideXml = zip.fileContent(slideFile);
        if (slideXml.empty()) continue;
        const std::string text = parseSlideXml(slideXml);
        if (text.empty()) continue;
        slides.push_back("## Slide " + std::to_string(index++) + "\n\n" + text);
    }
    return join(slides, "\n\n");
}

} // namespace detail

ConversionResult convertFile(const std::string &path, const ConversionOptions &options)
{
    (void)options;
    ConversionResult result;
    const std::string lowerPath = detail::toLower(path);
    const auto dot = lowerPath.find_last_of('.');
    const std::string extension = dot == std::string::npos ? "" : lowerPath.substr(dot);

    const std::unordered_set<std::string> plainExtensions = {
        ".txt", ".log", ".json", ".ini", ".cfg"};
    const std::unordered_set<std::string> markdownExtensions = {
        ".md", ".markdown"};
    const std::unordered_set<std::string> codeExtensions = {
        ".cpp", ".cc", ".c", ".h", ".hpp", ".py", ".js", ".ts", ".css", ".html", ".htm"};

    if (extension == ".docx")
        result.markdown = detail::readDocxText(path);
    else if (extension == ".pptx")
        result.markdown = detail::readPptxText(path);
    else if (extension == ".xlsx")
        result.markdown = detail::readXlsxText(path);
    else if (extension == ".doc" || extension == ".wps")
        result.markdown = detail::readWpsText(path);
    else if (extension == ".et")
        result.markdown = detail::readEtText(path);
    else if (extension == ".dps")
        result.markdown = detail::readDpsText(path);
    else if (plainExtensions.count(extension))
        result.markdown = detail::trim(detail::readTextFile(path));
    else if (codeExtensions.count(extension))
    {
        const std::string text = detail::readTextFile(path);
        if (!text.empty())
            result.markdown = "```" + (extension.size() > 1 ? extension.substr(1) : std::string()) + "\n" + text + "\n```";
    }
    else
    {
        result.markdown = detail::trim(detail::readTextFile(path));
    }

    if (markdownExtensions.count(extension))
        result.markdown = detail::markdownToText(result.markdown);
    else if (extension == ".html" || extension == ".htm")
        result.markdown = detail::htmlToText(result.markdown);

    result.success = !result.markdown.empty();
    if (!result.success)
        result.warnings.push_back("No parser produced output for file: " + path);
    return result;
}

} // namespace doc2md
