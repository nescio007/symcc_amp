// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/epoll.h>
#include <systemd/sd-daemon.h>
#include <semaphore.h>

#include "Config.h"
#include "Shadow.h"
#include <Runtime.h>

#define SYM(x) x##_symbolized

#define IS_LITTLE_ENDIAN (*reinterpret_cast<const uint16_t*>("\0\xff") > 0x0100)

namespace {

/// semaphore (if we have any)
sem_t *listen_semaphore = nullptr;

/// did we receive a symbolic input packet?
bool packet_received = false;

/// The current position in the (symbolic) input.
uint64_t inputOffset = 0;

/// Tell the solver to try an alternative value than the given one.
template<typename V, typename F>
void tryAlternative(V value, SymExpr valueExpr, F caller) {
  if (valueExpr) {
    _sym_push_path_constraint(
        _sym_build_equal(valueExpr,
                         _sym_build_integer(value, sizeof(value) * 8)),
        true, reinterpret_cast<uintptr_t>(caller));
  }
}

// A partial specialization for pointer types for convenience.
template<typename E, typename F>
void tryAlternative(E *value, SymExpr valueExpr, F caller) {
  tryAlternative(reinterpret_cast<intptr_t>(value), valueExpr, caller);
}
} // namespace

void initLibcWrappers() {
  auto *sem_name = getenv("SYMCC_LISTEN_SEM");
  if (sem_name != nullptr) {
    listen_semaphore = sem_open(sem_name, 0);
  }
  if (g_config.fullyConcrete)
    return;
}

void listen_ready() {
  if (listen_semaphore != nullptr) {
    sem_post(listen_semaphore);
  }
}

bool is_input_fd(int sockfd) {
  return sd_is_socket_inet(sockfd, AF_INET, SOCK_DGRAM, -1, g_config.inputPort);
}

std::string hexdump(const void *data, size_t length) {
  std::ostringstream out("");
  for (size_t i = 0; i < length; i++) {
    out << std::hex << std::setw(2) << std::setfill('0') << unsigned(reinterpret_cast<const uint8_t *>(data)[i]);
  }
  return out.str();
}

extern "C" {

void *SYM(malloc)(size_t size) {
  auto *result = malloc(size);

  tryAlternative(size, _sym_get_parameter_expression(0), SYM(malloc));

  _sym_set_return_expression(nullptr);
  return result;
}

void *SYM(calloc)(size_t nmemb, size_t size) {
  auto *result = calloc(nmemb, size);

  tryAlternative(nmemb, _sym_get_parameter_expression(0), SYM(calloc));
  tryAlternative(size, _sym_get_parameter_expression(1), SYM(calloc));

  _sym_set_return_expression(nullptr);
  return result;
}

// See comment on lseek and lseek64 below; the same applies to the "off"
// parameter of mmap.

void *SYM(mmap64)(void *addr, size_t len, int prot, int flags, int fildes,
                  uint64_t off) {
  auto *result = mmap64(addr, len, prot, flags, fildes, off);

  tryAlternative(len, _sym_get_parameter_expression(1), SYM(mmap64));

  _sym_set_return_expression(nullptr);
  return result;
}

void *SYM(mmap)(void *addr, size_t len, int prot, int flags, int fildes,
                uint32_t off) {
  return SYM(mmap64)(addr, len, prot, flags, fildes, off);
}

ssize_t SYM(read)(int fildes, void *buf, size_t nbyte) {
  tryAlternative(buf, _sym_get_parameter_expression(1), SYM(read));
  tryAlternative(nbyte, _sym_get_parameter_expression(2), SYM(read));

  auto result = read(fildes, buf, nbyte);
  _sym_set_return_expression(nullptr);

  if (result < 0)
    return result;

  if (is_input_fd(fildes)) {
    // Reading symbolic input.
    ReadWriteShadow shadow(buf, result);
    std::generate(shadow.begin(), shadow.end(),
                  []() { return _sym_get_input_byte(inputOffset++); });
  } else if (!isConcrete(buf, result)) {
    ReadWriteShadow shadow(buf, result);
    std::fill(shadow.begin(), shadow.end(), nullptr);
  }

  return result;
}

// lseek is a bit tricky because, depending on preprocessor macros, glibc
// defines it to be a function operating on 32-bit values or aliases it to
// lseek64. Therefore, we cannot know in general whether calling lseek in our
// code takes a 32 or a 64-bit offset and whether it returns a 32 or a 64-bit
// result. In fact, since we compile this library against LLVM which requires us
// to compile with "-D_FILE_OFFSET_BITS=64", we happen to know that, for us,
// lseek is an alias to lseek64, but this may change any time. More importantly,
// client code may call one or the other, depending on its preprocessor
// definitions.
//
// Therefore, we define symbolic versions of both lseek and lseek64, but
// internally we only use lseek64 because it's the only one on whose
// availability we can rely.

uint64_t SYM(lseek64)(int fd, uint64_t offset, int whence) {
  auto result = lseek64(fd, offset, whence);
  _sym_set_return_expression(nullptr);
  if (result == (off_t) - 1)
    return result;

  if (whence == SEEK_SET)
    _sym_set_return_expression(_sym_get_parameter_expression(1));

  if (is_input_fd(fd))
    inputOffset = result;

  return result;
}

uint32_t SYM(lseek)(int fd, uint32_t offset, int whence) {
  uint64_t result = SYM(lseek64)(fd, offset, whence);

  // Perform the same overflow check as glibc in the 32-bit version of lseek.

  auto result32 = (uint32_t) result;
  if (result == result32)
    return result32;

  errno = EOVERFLOW;
  return (uint32_t) - 1;
}

size_t SYM(fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  tryAlternative(ptr, _sym_get_parameter_expression(0), SYM(fread));
  tryAlternative(size, _sym_get_parameter_expression(1), SYM(fread));
  tryAlternative(nmemb, _sym_get_parameter_expression(2), SYM(fread));

  auto result = fread(ptr, size, nmemb, stream);
  _sym_set_return_expression(nullptr);

  if (is_input_fd(fileno(stream))) {
    // Reading symbolic input.
    ReadWriteShadow shadow(ptr, result * size);
    std::generate(shadow.begin(), shadow.end(),
                  []() { return _sym_get_input_byte(inputOffset++); });
  } else if (!isConcrete(ptr, result * size)) {
    ReadWriteShadow shadow(ptr, result * size);
    std::fill(shadow.begin(), shadow.end(), nullptr);
  }

  return result;
}

char *SYM(fgets)(char *str, int n, FILE *stream) {
  tryAlternative(str, _sym_get_parameter_expression(0), SYM(fgets));
  tryAlternative(n, _sym_get_parameter_expression(1), SYM(fgets));

  auto result = fgets(str, n, stream);
  _sym_set_return_expression(_sym_get_parameter_expression(0));

  if (is_input_fd(fileno(stream))) {
    // Reading symbolic input.
    ReadWriteShadow shadow(str, sizeof(char) * strlen(str));
    std::generate(shadow.begin(), shadow.end(),
                  []() { return _sym_get_input_byte(inputOffset++); });
  } else if (!isConcrete(str, sizeof(char) * strlen(str))) {
    ReadWriteShadow shadow(str, sizeof(char) * strlen(str));
    std::fill(shadow.begin(), shadow.end(), nullptr);
  }

  return result;
}

void SYM(rewind)(FILE *stream) {
  rewind(stream);
  _sym_set_return_expression(nullptr);

  if (is_input_fd(fileno(stream))) {
    inputOffset = 0;
  }
}

int SYM(fseek)(FILE *stream, long offset, int whence) {
  tryAlternative(offset, _sym_get_parameter_expression(1), SYM(fseek));

  auto result = fseek(stream, offset, whence);
  _sym_set_return_expression(nullptr);
  if (result == -1)
    return result;

  if (is_input_fd(fileno(stream))) {
    auto pos = ftell(stream);
    if (pos == -1)
      return -1;
    inputOffset = pos;
  }

  return result;
}

int SYM(fseeko)(FILE *stream, off_t offset, int whence) {
  tryAlternative(offset, _sym_get_parameter_expression(1), SYM(fseeko));

  auto result = fseeko(stream, offset, whence);
  _sym_set_return_expression(nullptr);
  if (result == -1)
    return result;

  if (is_input_fd(fileno(stream))) {
    auto pos = ftello(stream);
    if (pos == -1)
      return -1;
    inputOffset = pos;
  }

  return result;
}

int SYM(fseeko64)(FILE *stream, uint64_t offset, int whence) {
  tryAlternative(offset, _sym_get_parameter_expression(1), SYM(fseeko64));

  auto result = fseeko64(stream, offset, whence);
  _sym_set_return_expression(nullptr);
  if (result == -1)
    return result;

  if (is_input_fd(fileno(stream))) {
    auto pos = ftello64(stream);
    if (pos == -1)
      return -1;
    inputOffset = pos;
  }

  return result;
}

int SYM(getc)(FILE *stream) {
  auto result = getc(stream);
  if (result == EOF) {
    _sym_set_return_expression(nullptr);
    return result;
  }

  if (is_input_fd(fileno(stream)))
    _sym_set_return_expression(_sym_build_zext(
        _sym_get_input_byte(inputOffset++), sizeof(int) * 8 - 8));
  else
    _sym_set_return_expression(nullptr);

  return result;
}

int SYM(fgetc)(FILE *stream) {
  auto result = fgetc(stream);
  if (result == EOF) {
    _sym_set_return_expression(nullptr);
    return result;
  }

  if (is_input_fd(fileno(stream)))
    _sym_set_return_expression(_sym_build_zext(
        _sym_get_input_byte(inputOffset++), sizeof(int) * 8 - 8));
  else
    _sym_set_return_expression(nullptr);

  return result;
}

int SYM(getchar)(void) {
  return SYM(getc)(stdin);
}

int SYM(ungetc)(int c, FILE *stream) {
  auto result = ungetc(c, stream);
  _sym_set_return_expression(_sym_get_parameter_expression(0));

  if (is_input_fd(fileno(stream)) && result != EOF)
    inputOffset--;

  return result;
}

void *SYM(memcpy)(void *dest, const void *src, size_t n) {
  auto *result = memcpy(dest, src, n);

  tryAlternative(dest, _sym_get_parameter_expression(0), SYM(memcpy));
  tryAlternative(src, _sym_get_parameter_expression(1), SYM(memcpy));
  tryAlternative(n, _sym_get_parameter_expression(2), SYM(memcpy));

  _sym_memcpy(static_cast<uint8_t *>(dest), static_cast<const uint8_t *>(src),
              n);
  _sym_set_return_expression(_sym_get_parameter_expression(0));
  return result;
}

void *SYM(memset)(void *s, int c, size_t n) {
  auto *result = memset(s, c, n);

  tryAlternative(s, _sym_get_parameter_expression(0), SYM(memset));
  tryAlternative(n, _sym_get_parameter_expression(2), SYM(memset));

  _sym_memset(static_cast<uint8_t *>(s), _sym_get_parameter_expression(1), n);
  _sym_set_return_expression(_sym_get_parameter_expression(0));
  return result;
}

void *SYM(memmove)(void *dest, const void *src, size_t n) {
  tryAlternative(dest, _sym_get_parameter_expression(0), SYM(memmove));
  tryAlternative(src, _sym_get_parameter_expression(1), SYM(memmove));
  tryAlternative(n, _sym_get_parameter_expression(2), SYM(memmove));

  auto *result = memmove(dest, src, n);
  _sym_memmove(static_cast<uint8_t *>(dest), static_cast<const uint8_t *>(src),
               n);

  _sym_set_return_expression(_sym_get_parameter_expression(0));
  return result;
}

char *SYM(strncpy)(char *dest, const char *src, size_t n) {
  tryAlternative(dest, _sym_get_parameter_expression(0), SYM(strncpy));
  tryAlternative(src, _sym_get_parameter_expression(1), SYM(strncpy));
  tryAlternative(n, _sym_get_parameter_expression(2), SYM(strncpy));

  auto *result = strncpy(dest, src, n);
  _sym_set_return_expression(nullptr);

  size_t srcLen = strnlen(src, n);
  size_t copied = std::min(n, srcLen);
  if (isConcrete(src, copied) && isConcrete(dest, n))
    return result;

  auto srcShadow = ReadOnlyShadow(src, copied);
  auto destShadow = ReadWriteShadow(dest, n);

  std::copy(srcShadow.begin(), srcShadow.end(), destShadow.begin());
  if (copied < n) {
    ReadWriteShadow destRestShadow(dest + copied, n - copied);
    std::fill(destRestShadow.begin(), destRestShadow.end(), nullptr);
  }

  return result;
}

const char *SYM(strchr)(const char *s, int c) {
  tryAlternative(s, _sym_get_parameter_expression(0), SYM(strchr));
  tryAlternative(c, _sym_get_parameter_expression(1), SYM(strchr));

  auto *result = strchr(s, c);
  _sym_set_return_expression(nullptr);

  auto *cExpr = _sym_get_parameter_expression(1);
  if (isConcrete(s, result != nullptr ? (result - s) : strlen(s)) &&
      cExpr == nullptr)
    return result;

  if (cExpr == nullptr)
    cExpr = _sym_build_integer(c, 8);
  else
    cExpr = _sym_build_trunc(cExpr, 8);

  size_t length = result != nullptr ? (result - s) : strlen(s);
  auto shadow = ReadOnlyShadow(s, length);
  auto shadowIt = shadow.begin();
  for (size_t i = 0; i < length; i++) {
    _sym_push_path_constraint(
        _sym_build_not_equal(
            (*shadowIt != nullptr) ? *shadowIt : _sym_build_integer(s[i], 8),
            cExpr),
        /*taken*/ 1, reinterpret_cast<uintptr_t>(SYM(strchr)));
    ++shadowIt;
  }

  return result;
}

int SYM(memcmp)(const void *a, const void *b, size_t n) {
  tryAlternative(a, _sym_get_parameter_expression(0), SYM(memcmp));
  tryAlternative(b, _sym_get_parameter_expression(1), SYM(memcmp));
  tryAlternative(n, _sym_get_parameter_expression(2), SYM(memcmp));

  auto result = memcmp(a, b, n);
  _sym_set_return_expression(nullptr);

  if (isConcrete(a, n) && isConcrete(b, n))
    return result;

  auto aShadowIt = ReadOnlyShadow(a, n).begin_non_null();
  auto bShadowIt = ReadOnlyShadow(b, n).begin_non_null();
  auto *allEqual = _sym_build_equal(*aShadowIt, *bShadowIt);
  for (size_t i = 1; i < n; i++) {
    ++aShadowIt;
    ++bShadowIt;
    allEqual =
        _sym_build_bool_and(allEqual, _sym_build_equal(*aShadowIt, *bShadowIt));
  }

  _sym_push_path_constraint(allEqual, result == 0,
                            reinterpret_cast<uintptr_t>(SYM(memcmp)));
  return result;
}

int SYM(bcmp)(const void *a, const void *b, size_t n) {
  tryAlternative(a, _sym_get_parameter_expression(0), SYM(memcmp));
  tryAlternative(b, _sym_get_parameter_expression(1), SYM(memcmp));
  tryAlternative(n, _sym_get_parameter_expression(2), SYM(memcmp));

  auto result = memcmp(a, b, n);
  _sym_set_return_expression(nullptr);

  if (isConcrete(a, n) && isConcrete(b, n))
    return result;

  auto aShadowIt = ReadOnlyShadow(a, n).begin_non_null();
  auto bShadowIt = ReadOnlyShadow(b, n).begin_non_null();
  auto *allEqual = _sym_build_equal(*aShadowIt, *bShadowIt);
  for (size_t i = 1; i < n; i++) {
    ++aShadowIt;
    ++bShadowIt;
    allEqual =
        _sym_build_bool_and(allEqual, _sym_build_equal(*aShadowIt, *bShadowIt));
  }

  _sym_push_path_constraint(allEqual, result == 0,
                            reinterpret_cast<uintptr_t>(SYM(memcmp)));
  return result;
}

uint32_t SYM(ntohl)(uint32_t netlong) {
  auto netlongExpr = _sym_get_parameter_expression(0);
  auto result = ntohl(netlong);

  if (netlongExpr == nullptr) {
    _sym_set_return_expression(nullptr);
    return result;
  }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  _sym_set_return_expression(_sym_build_bswap(netlongExpr));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  _sym_set_return_expression(netlongExpr);
#else
#error Unsupported __BYTE_ORDER__
#endif

  return result;
}

uint16_t SYM(ntohs)(uint16_t netshort) {
  auto netlongExpr = _sym_get_parameter_expression(0);
  auto result = ntohs(netshort);

  if (netlongExpr == nullptr) {
    _sym_set_return_expression(nullptr);
    return result;
  }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  _sym_set_return_expression(_sym_build_bswap(netlongExpr));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  _sym_set_return_expression(netlongExpr);
#else
#error Unsupported __BYTE_ORDER__
#endif

  return result;
}

uint32_t SYM(htonl)(uint32_t hostlong) {
  auto netlongExpr = _sym_get_parameter_expression(0);
  auto result = htonl(hostlong);

  if (netlongExpr == nullptr) {
    _sym_set_return_expression(nullptr);
    return result;
  }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  _sym_set_return_expression(_sym_build_bswap(netlongExpr));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  _sym_set_return_expression(netlongExpr);
#else
#error Unsupported __BYTE_ORDER__
#endif

  return result;
}

uint16_t SYM(htons)(uint16_t hostshort) {
  auto netlongExpr = _sym_get_parameter_expression(0);
  auto result = htons(hostshort);

  if (netlongExpr == nullptr) {
    _sym_set_return_expression(nullptr);
    return result;
  }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  _sym_set_return_expression(_sym_build_bswap(netlongExpr));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  _sym_set_return_expression(netlongExpr);
#else
#error Unsupported __BYTE_ORDER__
#endif

  return result;
}

ssize_t SYM(send)(int socket, const void *message, size_t length, int flags) {
  std::cerr << "Path Assertions:\n" << _sym_path_constraints_to_string() << std::endl;
  std::cerr << "Message bytes:\n";
  for (size_t i = 0; i < length; i++) {
    auto messageExpr = _sym_read_memory(&reinterpret_cast<const uint8_t *>(message)[i], 1, false);
    if (messageExpr) {
      std::cerr << "SYM: " << _sym_expr_to_string(messageExpr) << "\n";
    } else {
      std::cerr << "CON: #x" << std::hex << std::setw(2) << std::setfill('0')
                << unsigned(reinterpret_cast<const uint8_t *>(message)[i]) << "\n";
    }
  }
  std::cerr << std::endl;

  // No symbolic sending -> result always concrete
  auto result = send(socket, message, length, flags);
  _sym_set_return_expression(nullptr);
  return result;
}

ssize_t SYM(sendto)(int socket,
                    const void *message,
                    size_t length,
                    int flags,
                    const struct sockaddr *dest_addr,
                    socklen_t dest_len) {
  std::cerr << "Path Assertions:\n" << _sym_path_constraints_to_string() << std::endl;
  std::cerr << "Message bytes:\n";
  for (size_t i = 0; i < length; i++) {
    auto messageExpr = _sym_read_memory(&reinterpret_cast<const uint8_t *>(message)[i], 1, false);
    if (messageExpr) {
      std::cerr << "SYM: " << _sym_expr_to_string(messageExpr) << "\n";
    } else {
      std::cerr << "CON: #x" << std::hex << std::setw(2) << std::setfill('0')
                << unsigned(reinterpret_cast<const uint8_t *>(message)[i]) << "\n";
    }
  }
  std::cerr << std::endl;

  // No symbolic sending -> result always concrete
  auto result = sendto(socket, message, length, flags, dest_addr, dest_len);
  _sym_set_return_expression(nullptr);
  return result;
}

ssize_t SYM(sendmsg)(int socket, const struct msghdr *msg, int flags) {
  std::cerr << "Path Assertions:\n" << _sym_path_constraints_to_string() << std::endl;
  std::cerr << "Message bytes:\n";
  for (size_t i = 0; i < msg->msg_iovlen; i++) {
    const void *message = msg->msg_iov[i].iov_base;
    size_t length = msg->msg_iov[i].iov_len;
    for (size_t j = 0; j < length; j++) {
      auto messageExpr = _sym_read_memory(&reinterpret_cast<const uint8_t *>(message)[j], 1, false);
      if (messageExpr) {
        std::cerr << "SYM: " << _sym_expr_to_string(messageExpr) << "\n";
      } else {
        std::cerr << "CON: #x" << std::hex << std::setw(2) << std::setfill('0')
                  << unsigned(reinterpret_cast<const uint8_t *>(message)[j]) << "\n";
      }
    }
  }
  std::cerr << std::endl;

  // No symbolic sending -> result always concrete
  auto result = sendmsg(socket, msg, flags);
  _sym_set_return_expression(nullptr);
  return result;
}

ssize_t SYM(sendmmsg)(int socket, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  std::cerr << "Path Assertions:\n" << _sym_path_constraints_to_string() << std::endl;
  for (unsigned int j = 0; j < vlen; j++) {
    std::cerr << "Message bytes:\n";
    auto msg = &msgvec[j].msg_hdr;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
      const void *message = msg->msg_iov[i].iov_base;
      size_t length = msg->msg_iov[i].iov_len;
      for (size_t k = 0; k < length; k++) {
        auto messageExpr = _sym_read_memory(&reinterpret_cast<const uint8_t *>(message)[k], 1, false);
        if (messageExpr) {
          std::cerr << "SYM: " << _sym_expr_to_string(messageExpr) << "\n";
        } else {
          std::cerr << "CON: #x" << std::hex << std::setw(2) << std::setfill('0')
                    << unsigned(reinterpret_cast<const uint8_t *>(message)[k]) << "\n";
        }
      }
    }
    std::cerr << std::endl;
  }

  // No symbolic sending -> result always concrete
  auto result = sendmmsg(socket, msgvec, vlen, flags);
  _sym_set_return_expression(nullptr);
  return result;
}

ssize_t SYM(recv)(int sockfd, void *buf, size_t len, int flags) {
  auto this_is_input_fd = is_input_fd(sockfd);
  if (this_is_input_fd && !packet_received) {
    listen_ready();
  }
  auto result = recv(sockfd, buf, len, flags);
  _sym_set_return_expression(nullptr);

  if (this_is_input_fd && !packet_received) {
    _sym_set_return_expression(_sym_get_input_length());
    // Reading symbolic input.
    ReadWriteShadow shadow(buf, result);
    std::generate(shadow.begin(), shadow.end(),
                  []() { return _sym_get_input_byte(inputOffset++); });
    packet_received = true;
  } else if (!isConcrete(buf, result)) {
    ReadWriteShadow shadow(buf, result);
    std::fill(shadow.begin(), shadow.end(), nullptr);
  }

  return result;
}

ssize_t SYM(recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  auto this_is_input_fd = is_input_fd(sockfd);
  if (this_is_input_fd && !packet_received) {
    listen_ready();
  }

  auto result = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  _sym_set_return_expression(nullptr);

  if (this_is_input_fd && !packet_received) {
    _sym_set_return_expression(_sym_get_input_length());
    // Reading symbolic input.
    ReadWriteShadow shadow(buf, result);
    std::generate(shadow.begin(), shadow.end(),
                  []() { return _sym_get_input_byte(inputOffset++); });
    packet_received = true;
  } else if (!isConcrete(buf, result)) {
    ReadWriteShadow shadow(buf, result);
    std::fill(shadow.begin(), shadow.end(), nullptr);
  }

  return result;
}

ssize_t SYM(recvmsg)(int sockfd, struct msghdr *msg, int flags) {
  auto this_is_input_fd = is_input_fd(sockfd);
  if (this_is_input_fd && !packet_received) {
    listen_ready();
  }
  auto result = recvmsg(sockfd, msg, flags);
  _sym_set_return_expression(nullptr);

  if (this_is_input_fd && !packet_received) {
    _sym_set_return_expression(_sym_get_input_length());
    size_t symbolized = 0;
    for (size_t i = 0; i < msg->msg_iovlen && static_cast<ssize_t>(symbolized) < result;
         i++, symbolized += msg->msg_iov[i].iov_len) {
      auto symbol_length = std::min(msg->msg_iov[i].iov_len, result - symbolized);
      // Reading symbolic input.
      ReadWriteShadow shadow(msg->msg_iov[i].iov_base, symbol_length);
      std::generate(shadow.begin(), shadow.end(),
                    []() { return _sym_get_input_byte(inputOffset++); });
      packet_received = true;
    }
  } else {
    size_t unsymbolized = 0;
    for (size_t i = 0; i < msg->msg_iovlen && static_cast<ssize_t>(unsymbolized) < result;
         i++, unsymbolized += msg->msg_iov[i].iov_len) {
      auto symbol_length = std::min(msg->msg_iov[i].iov_len, result - unsymbolized);
      if (!isConcrete(msg->msg_iov[i].iov_base, symbol_length)) {
        ReadWriteShadow shadow(msg->msg_iov[i].iov_base, symbol_length);
        std::fill(shadow.begin(), shadow.end(), nullptr);
      }
    }
  }

  return result;
}

ssize_t SYM(recvmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
  auto this_is_input_fd = is_input_fd(sockfd);
  if (this_is_input_fd && !packet_received) {
    listen_ready();
  }
  auto result = recvmmsg(sockfd, msgvec, vlen, flags, timeout);
  _sym_set_return_expression(nullptr);

  for (int j = 0; j < result; j++) {

    mmsghdr *mmsghdr_ptr = &msgvec[j];
    msghdr *msg = &mmsghdr_ptr->msg_hdr;
    unsigned int *msglen = &mmsghdr_ptr->msg_len;

    if (this_is_input_fd && !packet_received) {
      _sym_write_memory(reinterpret_cast<uint8_t *>(msglen),
                        sizeof(unsigned int),
                        _sym_get_input_length(),
                        IS_LITTLE_ENDIAN);
      size_t symbolized = 0;
      for (size_t i = 0; i < msg->msg_iovlen && static_cast<ssize_t>(symbolized) < result;
           i++, symbolized += msg->msg_iov[i].iov_len) {
        auto symbol_length = std::min(msg->msg_iov[i].iov_len, result - symbolized);
        // Reading symbolic input.
        ReadWriteShadow shadow(msg->msg_iov[i].iov_base, symbol_length);
        std::generate(shadow.begin(), shadow.end(),
                      []() { return _sym_get_input_byte(inputOffset++); });
        packet_received = true;
      }
    } else {
      if (!isConcrete(msglen, sizeof(unsigned int))) {
        ReadWriteShadow len_shadow(msglen, sizeof(unsigned int));
        std::fill(len_shadow.begin(), len_shadow.end(), nullptr);
      }
      size_t unsymbolized = 0;
      for (size_t i = 0; i < msg->msg_iovlen && static_cast<ssize_t>(unsymbolized) < result;
           i++, unsymbolized += msg->msg_iov[i].iov_len) {
        auto symbol_length = std::min(msg->msg_iov[i].iov_len, result - unsymbolized);
        if (!isConcrete(msg->msg_iov[i].iov_base, symbol_length)) {
          ReadWriteShadow shadow(msg->msg_iov[i].iov_base, symbol_length);
          std::fill(shadow.begin(), shadow.end(), nullptr);
        }
      }
    }
  }

  return result;
}

// select
int SYM(select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *timeout) {
  for (int i = 0; i < std::min(nfds, FD_SETSIZE); i++) {
    if (FD_ISSET(i, readfds) && is_input_fd(i)) {
      listen_ready();
    }
  }
  return select(nfds, readfds, writefds, errorfds, timeout);
}

// pselect
int SYM(pselect)(int nfds,
                 fd_set *readfds,
                 fd_set *writefds,
                 fd_set *errorfds,
                 const struct timespec *timeout,
                 const sigset_t *sigmask) {
  for (int i = 0; i < std::min(nfds, FD_SETSIZE); i++) {
    if (FD_ISSET(i, readfds) && is_input_fd(i)) {
      listen_ready();
    }
  }
  return pselect(nfds, readfds, writefds, errorfds, timeout, sigmask);
}

// poll
int SYM(poll)(struct pollfd *fds, nfds_t nfds, int timeout) {
  for (nfds_t i = 0; i < nfds; i++) {
    if (is_input_fd(fds[i].fd) && (fds[i].events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) != 0) {
      listen_ready();
    }
  }
  return poll(fds, nfds, timeout);
}

// ppoll
int SYM(ppoll)(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask) {
  for (nfds_t i = 0; i < nfds; i++) {
    if (is_input_fd(fds[i].fd) && (fds[i].events & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) != 0) {
      listen_ready();
    }
  }
  return ppoll(fds, nfds, tmo_p, sigmask);
}

// epoll_wait
int SYM(epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout) {
  listen_ready();
  return epoll_wait(epfd, events, maxevents, timeout);
}

// epoll_pwait
int SYM(epoll_pwait)(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) {
  listen_ready();
  return epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

}
