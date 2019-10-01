#include <errno.h>
#include "memory/file.h"

off_t memory::file::seek(off_t offset, fs::file::whence whence)
{
  switch (whence) {
    case fs::file::whence::set:
      break;
    case fs::file::whence::current:
      offset += _M_pos;
      break;
    case fs::file::whence::end:
      offset += _M_buf.length();
      break;
    default:
      errno = EINVAL;
      return -1;
  }

  // If the offset is not negative...
  if (offset >= 0) {
    // If the offset is beyond the end of the buffer...
    if (static_cast<size_t>(offset) > _M_buf.length()) {
      // Create hole.
      if (!_M_buf.append(offset - _M_buf.length(), 0)) {
        errno = ENOMEM;
        return -1;
      }
    }

    _M_pos = offset;

    return _M_pos;
  } else {
    errno = EINVAL;
    return -1;
  }
}
