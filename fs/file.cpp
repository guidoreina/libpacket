#include <stdint.h>
#include <errno.h>
#include "fs/file.h"

bool fs::file::write(const void* buf, size_t count)
{
  const uint8_t* b = static_cast<const uint8_t*>(buf);

  while (count > 0) {
    const ssize_t ret = ::write(_M_fd, b, count);
    if (ret > 0) {
      if ((count -= ret) == 0) {
        return true;
      }

      b += ret;
    } else if (ret < 0) {
      if (errno != EINTR) {
        return false;
      }
    }
  }

  return true;
}

bool fs::file::pwrite(const void* buf, size_t count, off_t offset)
{
  const uint8_t* b = static_cast<const uint8_t*>(buf);

  while (count > 0) {
    const ssize_t ret = ::pwrite(_M_fd, b, count, offset);
    if (ret > 0) {
      if ((count -= ret) == 0) {
        return true;
      }

      b += ret;
      offset += ret;
    } else if (ret < 0) {
      if (errno != EINTR) {
        return false;
      }
    }
  }

  return true;
}
