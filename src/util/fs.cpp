// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/check.h>
#include <util/fs.h>
#include <util/syserror.h>
#include <sync.h>

#ifndef WIN32
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <unistd.h>
#else
#include <codecvt>
#include <limits>
#include <windows.h>
#endif

#include <cassert>
#include <cerrno>
#include <string>
#include <map>

namespace fsbridge {

namespace {

class MemoryFile {
private:
    static constexpr uint8_t AllocationSizeLog2 = 18; // 256 Kb
    static constexpr size_t AllocationSize = 1 << AllocationSizeLog2;
    static constexpr size_t AllocationMask = AllocationSize - 1;

    static constexpr size_t getOffset(size_t pos) {
        return pos & AllocationMask;
    }
    static constexpr size_t getBufferNum(size_t pos) {
        return pos >> AllocationSizeLog2;
    }
    static constexpr size_t getBufferBegin(size_t pos) {
        return pos & ~AllocationMask;
    }
    static constexpr size_t getBufferNext(size_t pos) {
        return getBufferBegin(pos) + AllocationSize;
    }

    static ssize_t read_static_cookie(void *cookie, char *buf, size_t size) EXCLUSIVE_LOCKS_REQUIRED(!static_cast<MemoryFile*>(cookie)->mut) {
        Assert(cookie != nullptr);
        return static_cast<MemoryFile*>(cookie)->read_cookie(buf, size);
    }

    static ssize_t write_static_cookie(void *cookie, const char *buf, size_t size) EXCLUSIVE_LOCKS_REQUIRED(!static_cast<MemoryFile*>(cookie)->mut) {
        Assert(cookie != nullptr);
        return static_cast<MemoryFile*>(cookie)->write_cookie(buf, size);
    }

    static int seek_static_cookie(void *cookie, off_t *offset, int whence) EXCLUSIVE_LOCKS_REQUIRED(!static_cast<MemoryFile*>(cookie)->mut) {
        Assert(cookie != nullptr);
        return static_cast<MemoryFile*>(cookie)->seek_cookie(offset, whence);
    }

    static int close_static_cookie(void *cookie);

    static constexpr cookie_io_functions_t cookieFn = {
        .read = read_static_cookie,
        .write = write_static_cookie,
        .seek = seek_static_cookie,
        .close = close_static_cookie,
    };
public:

    enum OpenFlags {
      INVALID = 0,
      READ = 1 << 0,
      WRITE = 1 << 1,
      CREAT = 1 << 2,
      EXCL = 1 << 3,
      TRUNC = 1 << 4,
      BINARY = 1 << 5,
      APPEND = 1 << 6,
    };

    static int getOpenFlags(const char* mode) {
      if (mode == nullptr || *mode == '\0') return 0;
      int res = 0;
      switch (*mode) {
        case 'r':
          res |= OpenFlags::READ;
          break;
        case 'w':
          res |= OpenFlags::WRITE | OpenFlags::CREAT | OpenFlags::TRUNC;
          break;
        case 'a':
          res |= OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREAT | OpenFlags::APPEND;
          break;
        default:
          return OpenFlags::INVALID;
      }
      const char* target = &mode[1];
      while (true) {
        switch (*target) {
          case '+':
            res |= OpenFlags::READ | OpenFlags::WRITE;
            break;
          case 'b':
            res |= OpenFlags::BINARY;
            break;
          case 'x':
            res |= OpenFlags::EXCL;
            break;
          case '\0':
            return res;
          default:
            std::cerr <<  "Fail to parse mode " << mode << std::endl;
            return OpenFlags::INVALID;
        }
        target++;
      }
    }

    MemoryFile() : pos(0), endPos(0), openMode(0), currentFile(nullptr) {}
    MemoryFile(const MemoryFile&) = delete;
    MemoryFile(MemoryFile&&) = delete;
    MemoryFile &operator=(const MemoryFile&) = delete;
    MemoryFile &operator=(MemoryFile&&) = delete;

    ~MemoryFile() {
        if (currentFile != nullptr) {
            close_static_cookie(this);
        }
        Assert(currentFile == nullptr);
    }

    FILE* open_cookie(const char* mode, bool isNewFile) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        if (currentFile != nullptr) {
            std::cerr <<  "Try to open twice the same file without closing it first." << std::endl;
            Assert(false);
            return nullptr;
        }
        Assert(openMode == OpenFlags::INVALID);

        openMode = getOpenFlags(mode);
        if (openMode == OpenFlags::INVALID) {
            std::cerr <<  "Fail to parse mode " << mode << std::endl;
            errno = EINVAL;
            return nullptr;
        }
        if ((openMode & (OpenFlags::CREAT | OpenFlags::EXCL)) == (OpenFlags::CREAT | OpenFlags::EXCL) &&
            !isNewFile) {
            errno = EEXIST;
            openMode = OpenFlags::INVALID;
            return nullptr;
        }
        if ((openMode & OpenFlags::CREAT) == 0) {
            if (isNewFile) {
                errno = ENOENT;
                openMode = OpenFlags::INVALID;
                return nullptr;
            }
            Assert((openMode & OpenFlags::TRUNC) == 0);
        }
        if ((openMode & OpenFlags::TRUNC) != 0) {
            data.clear();
            endPos = 0;
        }
        Assert(endPos >= 0 && endPos <= data.size() * AllocationSize);
        if ((openMode & OpenFlags::APPEND) != 0) {
            pos = endPos;
        } else {
            pos = 0;
        }
        currentFile = fopencookie(this, mode, cookieFn);
        if (currentFile == nullptr) {
            std::cerr <<  "Fail to fopencookie with mode " << mode << std::endl;
            Assert(false);
            openMode = OpenFlags::INVALID;
            return nullptr;
        }
        return currentFile;
    }

    FILE* getCurrentFile() const EXCLUSIVE_LOCKS_REQUIRED(!mut) { LOCK(mut); return currentFile; }

    bool truncate(const size_t target) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        return doTruncate(target);
    }

    bool copyContentTo(MemoryFile& dest) const EXCLUSIVE_LOCKS_REQUIRED(!mut, !dest.mut){
        LOCK2(mut, dest.mut);
        Assert(currentFile == nullptr);
        Assert(dest.currentFile == nullptr);

        dest.data.resize(data.size());

        for (size_t i = 0; i < data.size(); i++) {
            if (dest.data[i]) {
                *dest.data[i] = *data[i];
            } else {
              dest.data[i] = std::make_unique<std::array<char, AllocationSize>>(*data[i]);
            }
        }
        dest.pos = pos;
        dest.endPos = endPos;
        return true;
    }

private:
    // Note: pos may be greater than endPos, in case of seek
    mutable Mutex mut;

    size_t pos GUARDED_BY(mut) = 0;
    size_t endPos GUARDED_BY(mut) = 0;
    std::vector<std::unique_ptr<std::array<char, AllocationSize>>> data GUARDED_BY(mut);
    int openMode GUARDED_BY(mut) = OpenFlags::INVALID;
    FILE* currentFile GUARDED_BY(mut) = nullptr;

    ssize_t read_cookie(char *buf, size_t size) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        if ((openMode & OpenFlags::READ) == 0) {
            errno = EBADF;
            return -1;
        }
        if (pos >= endPos) {
            return 0;
        }
        size_t offset = 0;
        while (offset < size) {
            if (pos == endPos) break;
            Assert(pos < endPos);

            size_t nextPos = std::min<size_t>(getBufferNext(pos), endPos);
            size_t readSize = std::min<size_t>(nextPos - pos, size - offset);
            Assert(readSize > 0);
            Assert(readSize <= AllocationSize);

            size_t bufferOffset = getOffset(pos);
            size_t bufferNum = getBufferNum(pos);
            Assert(bufferOffset + readSize <= AllocationSize);
            Assert(bufferNum < data.size());
            Assert(data[bufferNum]);
            memcpy(&buf[offset], &(data[bufferNum]->at(bufferOffset)), readSize);
            offset += readSize;
            pos += readSize;
        }
        Assert(pos <= endPos);
        Assert(offset <= size);
        return offset;
    }

    ssize_t write_cookie(const char *buf, size_t size) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        if ((openMode & OpenFlags::WRITE) == 0) {
            return 0;
        }
        if (pos > endPos) {
            if (!doTruncate(pos)) {
                return 0;
            }
        }
        size_t offset = 0;
        while (offset < size) {
            size_t nextPos = getBufferNext(pos);
            size_t writeSize = std::min<size_t>(nextPos - pos, size - offset);
            size_t bufferOffset = getOffset(pos);
            size_t bufferNum = getBufferNum(pos);
            if (bufferNum == data.size()) {
                data.emplace_back(std::make_unique<std::array<char, AllocationSize>>());
            }
            Assert(bufferNum < data.size());
            Assert(bufferOffset + writeSize <= AllocationSize);
            Assert(data[bufferNum]);
            memcpy(&(data[bufferNum]->at(bufferOffset)), &buf[offset], writeSize);
            pos += writeSize;
            offset += writeSize;
            if (pos > endPos) {
                endPos = pos;
            }
        }
        return offset;
    }

    int seek_cookie(off_t *offset, int whence) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        size_t target = 0;
        switch (whence) {
            case SEEK_SET:
              target = 0;
              break;
            case SEEK_CUR:
              target = pos;
              break;
            case SEEK_END:
              target = endPos;
              break;
            default:
              errno = EINVAL;
              return -1;
        }
        if (*offset < 0 && target < ((size_t)-*offset)) {
            pos = 0;
        } else {
            pos = target + *offset;
        }
        *offset = pos;
        return 0;
    }

    int close_cookie() EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        Assert(currentFile != nullptr);
        currentFile = nullptr;
        openMode = OpenFlags::INVALID;
        return 0;
    }

    bool doTruncate(const size_t target) EXCLUSIVE_LOCKS_REQUIRED(mut) {
        if ((openMode & OpenFlags::WRITE) == 0) {
            return false;
        }
        if (target < endPos) {
            while (target > endPos) {
                size_t nextPos = std::min<size_t>(getBufferNext(endPos), target);
                size_t memsetSize = nextPos - endPos;
                size_t bufferOffset = getOffset(endPos);
                size_t bufferNum = getBufferNum(endPos);
                if (bufferNum == data.size()) {
                    data.emplace_back(std::make_unique<std::array<char, AllocationSize>>());
                }
                Assert(bufferNum < data.size());
                Assert(bufferOffset + memsetSize <= AllocationSize);
                Assert(data[bufferNum]);
                memset(&(data[bufferNum]->at(bufferOffset)), 0, memsetSize);
                endPos += memsetSize;
            }
        } else if (target > endPos) {
            size_t bufferNum = getBufferNum(target);
            Assert(bufferNum < data.size());
            if (getOffset(target) == 0) {
                data.resize(bufferNum);
            } else {
                data.resize(bufferNum + 1);
            }
            endPos = target;
        }
        Assert(endPos == target);
        return true;
    }
};

class MemoryFS {
    // TODO:
    //    remove file ??
    //    rename file ??
    //    copy file ??
    //    handle ifstream.open
    //    handle ofstream.open
private:
    mutable Mutex mut;

    struct FileInfo {
        std::unique_ptr<MemoryFile> backendFile;
    };

    std::atomic<bool> enable = false;
    bool hasDatadir GUARDED_BY(mut) = false;
    fs::path datadir GUARDED_BY(mut);

    std::map<FILE*, fs::path> openFile GUARDED_BY(mut);
    std::map<fs::path, FileInfo> fileInfos GUARDED_BY(mut);

    std::map<fs::path, FileInfo> snapshot GUARDED_BY(mut);

    static bool is_subpath(const fs::path& path, const fs::path& base) {
        const auto mismatch_pair = std::mismatch(path.begin(), path.end(), base.begin(), base.end());
        return mismatch_pair.second == base.end();
    }

public:
    MemoryFS() {}

    bool isMemoryFile(FILE* f) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        if (!enable) return false;
        LOCK(mut);
        return openFile.contains(f);
    }

    FILE *fopen(const fs::path& p, const char *mode) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        if (!enable) {
            return ::fopen(p.c_str(), mode);
        }
        LOCK(mut);
        fs::path absPath = std::filesystem::absolute(p);
        if ((!is_subpath(absPath, datadir)) ||
             absPath.filename() == ".lock" ||
             absPath.filename() == "debug.log") {
            std::cout << "native open " << absPath << std::endl;
            return ::fopen(p.c_str(), mode);
        }
        std::cout << "open " << absPath << " with mode " << mode << std::endl;

        auto inserted = fileInfos.try_emplace(absPath, FileInfo{});
        FileInfo& fileInfo = inserted.first->second;

        if (!fileInfo.backendFile) {
            Assert(inserted.second);
            fileInfo.backendFile = std::make_unique<MemoryFile>();
        } else {
            Assert(!inserted.second);
        }
        if (fileInfo.backendFile->getCurrentFile() != nullptr) {
            std::cerr <<  "Try to open twice " << absPath << " without closing it first." << std::endl;
            Assert(false);
            return nullptr;
        }
        FILE* res = fileInfo.backendFile->open_cookie(mode, inserted.second);

        if (res == nullptr) {
            if (inserted.second) {
                fileInfos.erase(inserted.first);
                std::cout << "Fail to open " << absPath << std::endl;
            }
            return nullptr;
        }
        Assert(res == fileInfo.backendFile->getCurrentFile());

        openFile[res] = absPath;
        return res;
    }

    int close(MemoryFile& f, std::function<int(MemoryFile& f)> closeFoo) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        Assert(f.getCurrentFile() != nullptr);
        auto it = openFile.find(f.getCurrentFile());
        if (it != openFile.end()) {
            fs::path p = it->second;
            std::cout << "Close " << p << std::endl;
            openFile.erase(it);
        } else {
            std::cerr << "Call close on unknonw openFile." << std::endl;
        }
        return closeFoo(f);
    }

    bool truncateMemoryFile(FILE* f, unsigned int length) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        Assert(enable);
        LOCK(mut);
        auto it = openFile.find(f);
        Assert(it != openFile.end());
        auto it2 = fileInfos.find(it->second);
        Assert(it2 != fileInfos.end());
        FileInfo& fileInfo = it2->second;
        Assert(f == fileInfo.backendFile->getCurrentFile());

        return fileInfo.backendFile->truncate(length);
    }

    void setDatadir(const fs::path& p) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        fs::path absPath = std::filesystem::absolute(p);

        LOCK(mut);
        if (absPath != datadir && hasDatadir && enable) {
          Assert(openFile.size() == 0);
        }
        hasDatadir = true;
        datadir = absPath;
        //std::cout << "Datadir " << absPath << std::endl;
    }

    void setEnable(bool v) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        LOCK(mut);
        enable = v;
    }

    bool isPathInMemFS(const fs::path& p) EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        if (!enable) return false;
        LOCK(mut);
        return fileInfos.contains(p);
    }

    bool createSnapshot() EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        if (!enable) return false;
        LOCK(mut);
        if (openFile.size() != 0) return false;

        for (const auto& el: fileInfos) {
            Assert(el.second.backendFile->getCurrentFile() == nullptr);
        }

        snapshot.clear();

        for (const auto& el: fileInfos) {
            auto inserted = snapshot.try_emplace(el.first, FileInfo{});
            Assert(inserted.second);
            FileInfo& backupFile = inserted.first->second;
            backupFile.backendFile = std::make_unique<MemoryFile>();
            Assert(el.second.backendFile->copyContentTo(*backupFile.backendFile));
        }
        return true;
    }

    bool restoreSnapshot() EXCLUSIVE_LOCKS_REQUIRED(!mut) {
        if (!enable) return false;
        LOCK(mut);
        if (openFile.size() != 0) return false;

        for (const auto& el: fileInfos) {
            Assert(el.second.backendFile->getCurrentFile() == nullptr);
        }

        fileInfos.clear();

        for (const auto& el: snapshot) {
            auto inserted = fileInfos.try_emplace(el.first, FileInfo{});
            Assert(inserted.second);
            FileInfo& restoredFile = inserted.first->second;
            restoredFile.backendFile = std::make_unique<MemoryFile>();
            Assert(el.second.backendFile->copyContentTo(*restoredFile.backendFile));
        }
        return true;
    }
};

static MemoryFS memfs;

int MemoryFile::close_static_cookie(void *cookie) {
    Assert(cookie != nullptr);
    MemoryFile* obj = static_cast<MemoryFile*>(cookie);
    return memfs.close(*obj, [](MemoryFile& o) { return o.close_cookie(); } );
}

} // anonymous namespace

void setMemFSDatadir(const fs::path& p) {
    memfs.setDatadir(p);
}

void setEnableMemFS(bool v) {
    memfs.setEnable(v);
}

FILE *fopen(const fs::path& p, const char *mode)
{
#ifndef WIN32
    return memfs.fopen(p, mode);
#else
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t> utf8_cvt;
    return ::_wfopen(p.wstring().c_str(), utf8_cvt.from_bytes(mode).c_str());
#endif
}

bool isMemoryFile(FILE* f) {
    return memfs.isMemoryFile(f);
}

bool isPathInMemFS(const fs::path& p) {
    return memfs.isPathInMemFS(p);
}

bool truncateMemoryFile(FILE* f, unsigned int length) {
    return memfs.truncateMemoryFile(f, length);
}

bool createSnapshotMemFS() {
    return memfs.createSnapshot();
}

bool restoreSnapshotMemFS() {
    return memfs.restoreSnapshot();
}

fs::path AbsPathJoin(const fs::path& base, const fs::path& path)
{
    assert(base.is_absolute());
    return path.empty() ? base : fs::path(base / path);
}

#ifndef WIN32

static std::string GetErrorReason()
{
    return SysErrorString(errno);
}

FileLock::FileLock(const fs::path& file)
{
    fd = open(file.c_str(), O_RDWR);
    if (fd == -1) {
        reason = GetErrorReason();
    }
}

FileLock::~FileLock()
{
    if (fd != -1) {
        close(fd);
    }
}

bool FileLock::TryLock()
{
    if (fd == -1) {
        return false;
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if (fcntl(fd, F_SETLK, &lock) == -1) {
        reason = GetErrorReason();
        return false;
    }

    return true;
}
#else

static std::string GetErrorReason() {
    return Win32ErrorString(GetLastError());
}

FileLock::FileLock(const fs::path& file)
{
    hFile = CreateFileW(file.wstring().c_str(),  GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        reason = GetErrorReason();
    }
}

FileLock::~FileLock()
{
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
}

bool FileLock::TryLock()
{
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    _OVERLAPPED overlapped = {};
    if (!LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(), &overlapped)) {
        reason = GetErrorReason();
        return false;
    }
    return true;
}
#endif

} // namespace fsbridge
