#ifndef FS_FILE_H
#define FS_FILE_H

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

namespace fs {
  class file {
    public:
      // Constructor.
      file() = default;

      // Destructor.
      ~file();

      // Open file for writing.
      bool open(const char* filename);

      // Is the file open?
      bool open() const;

      // Close file.
      void close();

      // Reposition read/write file offset.
      enum class whence : int {
        set = SEEK_SET,
        current = SEEK_CUR,
        end = SEEK_END
      };

      off_t seek(off_t offset, whence whence);

      // Get the current value of the file position indicator.
      off_t tell() const;

      // Write to file.
      bool write(const void* buf, size_t count);

      // Write to file at a given offset.
      bool pwrite(const void* buf, size_t count, off_t offset);

      // Get file descriptor.
      int fd() const;

    private:
      // File descriptor.
      int _M_fd = -1;

      // Disable copy constructor and assignment operator.
      file(const file&) = delete;
      file& operator=(const file&) = delete;
  };

  inline file::~file()
  {
    close();
  }

  inline bool file::open(const char* filename)
  {
    return ((_M_fd = ::open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644)) !=
            -1);
  }

  inline bool file::open() const
  {
    return (_M_fd != -1);
  }

  inline void file::close()
  {
    if (_M_fd != -1) {
      ::close(_M_fd);
      _M_fd = -1;
    }
  }

  inline off_t file::seek(off_t offset, whence whence)
  {
    return ::lseek(_M_fd, offset, static_cast<int>(whence));
  }

  inline off_t file::tell() const
  {
    return ::lseek(_M_fd, 0, SEEK_CUR);
  }

  inline int file::fd() const
  {
    return _M_fd;
  }
}

#endif // FS_FILE_H
