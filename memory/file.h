#ifndef MEMORY_FILE_H
#define MEMORY_FILE_H

#include "string/buffer.h"
#include "fs/file.h"

namespace memory {
  class file {
    public:
      // Constructor.
      file() = default;

      // Destructor.
      ~file() = default;

      // Clear file.
      void clear();

      // Reposition read/write file offset.
      off_t seek(off_t offset, fs::file::whence whence);

      // Get the current value of the file position indicator.
      size_t tell() const;

      // Write to file.
      bool write(const void* buf, size_t count);

      // Write to file at a given offset.
      bool pwrite(const void* buf, size_t count, size_t offset);

      // Get data.
      const void* data() const;

      // Get length.
      size_t length() const;

    private:
      // Buffer.
      string::buffer _M_buf;

      // Position in the buffer.
      size_t _M_pos = 0;

      // Disable copy constructor and assignment operator.
      file(const file&) = delete;
      file& operator=(const file&) = delete;
  };

  inline void file::clear()
  {
    _M_buf.clear();
    _M_pos = 0;
  }

  inline size_t file::tell() const
  {
    return _M_pos;
  }

  inline bool file::write(const void* buf, size_t count)
  {
    if (_M_buf.replace(_M_pos, count, buf, count)) {
      _M_pos += count;
      return true;
    }

    return false;
  }

  inline bool file::pwrite(const void* buf, size_t count, size_t offset)
  {
    // If the offset is not beyond the end of the buffer...
    if (offset <= _M_buf.length()) {
      return _M_buf.replace(offset, count, buf, count);
    } else {
      return ((_M_buf.append(offset - _M_buf.length(), 0)) &&
              (_M_buf.append(buf, count)));
    }
  }

  inline const void* file::data() const
  {
    return _M_buf.data();
  }

  inline size_t file::length() const
  {
    return _M_buf.length();
  }
}

#endif // MEMORY_FILE_H
