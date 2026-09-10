// =============================================================================
// attohttpd — a minimal multi-threaded HTTP/HTTPS server with a chat interface.
//
// What is here, and nothing else:
//   * BSD sockets + a blocking accept loop
//   * a producer/consumer thread pool over a bounded queue
//   * optional TLS via OpenSSL (a FILE* shim so all writes go through one path)
//   * a small HTTP/1.1 request reader and router
//   * end-to-end encrypted chat rooms, addressed by path (/standup, /ops, ...)
//
// The rooms are encrypted in the browser: AES-256-GCM under a PBKDF2-SHA256 key
// derived from a password the participants agree out of band.  This server is a
// blind relay.  It never receives a password, derives no key, and stores only
// opaque ciphertext — so it physically cannot read a room, and neither can
// anyone who takes the disk.  See CHAT_JS for the format and the crypto.
//
// Everything else the server used to do — the wiki, markdown rendering,
// directory listings, uploads, sessions, GeoIP, rate limiting, blacklists and
// metrics — has been removed.  There is no filesystem serving at all.
//
// -----------------------------------------------------------------------------
// PROVENANCE
//
// This file has two authors, and the split is worth keeping straight.
//
// [plotfi] — Puyan Lotfi, 2018-2020, hand-written.  The concurrency and socket
//   layer: the SyncQueue ADT (commit e700e9a, "Refactoring threading code into
//   SyncQueue ADT"), the producer/consumer thread pool (31a5e95, "Cleaning up
//   producer and consumer"), the accept/bind/listen path, and the CHECK macro.
//   That design is unchanged — a producer thread accepting into a shared queue,
//   a fixed pool of eight consumers each owning a connection end to end.  It is
//   still the backbone of this server; everything below is arranged around it.
//   Sections carrying a [plotfi] marker are his, with any later modification
//   noted inline so the original is still legible.
//
// [Claude] — everything else, and all of it later (2026).  The HTTP router,
//   TLS, the room store, the configuration and logging, and the whole browser
//   client including the cryptography.  Marked with [Claude] section banners.
//
// The pre-2026 history on `master` is entirely plotfi's; `feature/wiki` and
// `webchat` are where the machine-written work starts.  Earlier iterations of
// this file also carried [Codex] markers; none of that code survives.
// -----------------------------------------------------------------------------
// =============================================================================

// [plotfi] HTTPD, MAXPENDING and BUFFERLEN are from the original server.
// [Claude] changed the two sizes: the backlog was 5, the recv buffer 100 bytes.
#define HTTPD        "attohttpd"
#define MAXPENDING   64      // listen() backlog
#define BUFFERLEN    4096    // recv size per iteration
#define DEFAULT_PORT 1337

#include <algorithm>
#include <atomic>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <new>
#include <netinet/in.h>
#include <queue>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <vector>
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

#define CLR_RESET  "\033[0m"
#define CLR_STAR   "\033[1;36m"   // bold cyan   — startup lines
#define CLR_PROD   "\033[1;33m"   // bold yellow — [PRODUCER]
#define CLR_CONS   "\033[1;34m"   // bold blue   — [CONSUMER]
#define CLR_CHAT   "\033[1;32m"   // bold green  — chat events
#define CLR_ERR    "\033[1;31m"   // bold red    — warnings

// [plotfi] The original error-check macro, wrapped around every syscall in the
// socket path.  [Claude] changed only the reporting: fprintf/perror became
// std::cerr + std::strerror.  The shape and the call sites are his.
#define CHECK(check, message)                                                  \
  do {                                                                         \
    if ((check) < 0) {                                                         \
      std::cerr << (message) << " failed: Error on line " << __LINE__ << ".\n" \
                << (message) << ": " << std::strerror(errno) << '\n';          \
      std::exit(EXIT_FAILURE);                                                 \
    }                                                                          \
  } while (false)

namespace {

// -----------------------------------------------------------------------------
// [Claude] Configuration (attohttp.conf, "key = value")
// -----------------------------------------------------------------------------
std::string   g_bindAddress = "127.0.0.1"; // loopback unless explicitly widened
std::uint16_t g_port        = DEFAULT_PORT;
std::string   g_allowedHost;               // Host: validation, anti DNS-rebinding
std::string   g_chatDir     = "chats";     // one append-only transcript per room
// The room-residency ceiling, overridable with `max_memory_mb`.  Declared here
// because load_config sets it; its default matches MAX_TOTAL_MEMORY below, and
// a static_assert there keeps the two in step.  The default suits a
// workstation and is far too large for a small VPS -- a cap above physical RAM
// never fires before the OOM killer.
std::size_t   g_maxTotalMemory = 768u * 1024u * 1024u;
// The sealed-message ceiling and the two buffers derived from it, all
// overridable with `max_blob_mb`.  Declared here because load_config sets them;
// the defaults match the constants further down (static_assert'd there).  On a
// small box these are the biggest lever: the per-worker request/response buffer
// scales with the blob cap, and nothing but `threads` otherwise bounds it.
std::size_t   g_maxBlobLen      = 28u * 1024u * 1024u;
std::size_t   g_maxBodySize     = 32u * 1024u * 1024u;
std::size_t   g_maxResponseBytes = 32u * 1024u * 1024u;
std::string   g_servedJs;   // CHAT_JS with the configured blob cap substituted in
// Per-connection tracing of the producer/consumer hand-off.  Off by default:
// the client polls every two seconds over Connection: close, so every poll is a
// fresh connection and always-on tracing would bury everything else.
bool          g_debug       = false;
std::string   g_csrfToken;                 // generated at startup, checked on POST
// Worker count is the concurrency ceiling, not a throughput knob: a worker is
// held for a connection's whole life, so N slow connections stall the (N+1)th
// outright.  Measured at 8, eight stalled connections pushed a normal request
// from 3 ms to 5.3 s.  Throughput saturates around 12k req/s well before this
// matters, so this number buys headroom against slow clients, not speed.
unsigned      g_threads     = 128;
// Content hashes of the compiled-in CSS/JS, used as ?v= cache busters.  The
// assets live in the binary, so without this a rebuild would not reach any
// client still inside the 10-minute cache window.
std::string   g_cssVer;
std::string   g_jsVer;
std::string   g_swVer;

#ifdef HAVE_OPENSSL
SSL_CTX    *g_sslCtx = nullptr;
std::string g_tlsCert;
std::string g_tlsKey;

// A FILE* that writes through SSL, so response code never branches on TLS.
// funopen on macOS, fopencookie on glibc.
#ifdef __APPLE__
int ssl_write_fn(void *cookie, const char *buf, int len) {
  return SSL_write((SSL *)cookie, buf, len);
}
int ssl_close_fn(void *cookie) {
  SSL *ssl = (SSL *)cookie;
  int fd = SSL_get_fd(ssl);
  SSL_shutdown(ssl);
  BIO_set_close(SSL_get_rbio(ssl), BIO_NOCLOSE);
  SSL_free(ssl);
  if (fd >= 0) close(fd);
  return 0;
}
FILE *ssl_to_file(SSL *ssl) {
  return funopen(ssl, nullptr, ssl_write_fn, nullptr, ssl_close_fn);
}
#else
ssize_t ssl_write_fn(void *cookie, const char *buf, size_t len) {
  return (ssize_t)SSL_write((SSL *)cookie, buf, (int)len);
}
int ssl_close_fn(void *cookie) {
  SSL *ssl = (SSL *)cookie;
  int fd = SSL_get_fd(ssl);
  SSL_shutdown(ssl);
  BIO_set_close(SSL_get_rbio(ssl), BIO_NOCLOSE);
  SSL_free(ssl);
  if (fd >= 0) close(fd);
  return 0;
}
FILE *ssl_to_file(SSL *ssl) {
  cookie_io_functions_t funcs = {};
  funcs.write = ssl_write_fn;
  funcs.close = ssl_close_fn;
  return fopencookie(ssl, "w", funcs);
}
#endif // __APPLE__
#endif // HAVE_OPENSSL

void load_config(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open()) return;
  auto trim = [](std::string &s) {
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
  };
  std::string line;
  while (std::getline(f, line)) {
    if (!line.empty() && line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq), raw = line.substr(eq + 1);
    trim(key); trim(raw);
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::string val = raw; // lowercased copy; raw keeps case for paths
    std::transform(val.begin(), val.end(), val.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (val.empty()) continue;
    if (key == "bind")     g_bindAddress = val;
    if (key == "hostname") g_allowedHost = val;
    if (key == "chat_dir") g_chatDir = raw;
    if (key == "debug")
      g_debug = (val == "true" || val == "1" || val == "yes" || val == "on");
    if (key == "port") {
      unsigned p = 0;
      auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), p);
      (void)ptr;
      if (ec == std::errc{} && p > 0 && p < 65536) g_port = (std::uint16_t)p;
    }
    if (key == "threads") {
      unsigned t = 0;
      auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), t);
      (void)ptr;
      if (ec == std::errc{} && t >= 1 && t <= 1024) g_threads = t;
    }
    if (key == "max_memory_mb") {
      unsigned long mb = 0;
      auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), mb);
      (void)ptr;
      if (ec == std::errc{} && mb >= 8) g_maxTotalMemory = (size_t)mb * 1024u * 1024u;
    }
    if (key == "max_blob_mb") {
      unsigned long mb = 0;
      auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), mb);
      (void)ptr;
      if (ec == std::errc{} && mb >= 1 && mb <= 64) {
        g_maxBlobLen = (size_t)mb * 1024u * 1024u;
        // The body must clear the blob after percent-encoding (about +12.5% for
        // a base64 payload) and the other form fields; the response must fit at
        // least one whole blob.  These reproduce the 28/32/32 defaults at 28.
        g_maxBodySize      = g_maxBlobLen + g_maxBlobLen / 8 + 65536;
        g_maxResponseBytes = g_maxBlobLen + 4u * 1024u * 1024u;
      }
    }
#ifdef HAVE_OPENSSL
    if (key == "tls_cert") g_tlsCert = raw;
    if (key == "tls_key")  g_tlsKey  = raw;
#endif
  }
}

// -----------------------------------------------------------------------------
// [Claude] Logging
// -----------------------------------------------------------------------------
// Worker threads all log to stdout, so a line is composed first and written
// under a lock: piecemeal `<<` from eight threads interleaves mid-line.  The
// explicit flush matters because stdout is fully buffered when redirected to a
// file — the usual way this runs — so without it log lines sit in the buffer
// and are lost outright if the process is killed.
std::mutex g_logMutex;

void log_line(const std::string &s) {
  std::lock_guard<std::mutex> lock(g_logMutex);
  std::cout << s << '\n' << std::flush;
}

// -----------------------------------------------------------------------------
// [Claude] Small string helpers
// -----------------------------------------------------------------------------
unsigned char from_hex(char c) {
  if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
  if (c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
  return 0;
}

// Percent-decoding. plusIsSpace distinguishes a form body from a URL path.
std::string pct_decode(std::string_view s, bool plusIsSpace) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (plusIsSpace && s[i] == '+') {
      out += ' ';
    } else if (s[i] == '%' && i + 2 < s.size() &&
               std::isxdigit((unsigned char)s[i + 1]) &&
               std::isxdigit((unsigned char)s[i + 2])) {
      out += (char)((from_hex(s[i + 1]) << 4) | from_hex(s[i + 2]));
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}

std::string html_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (unsigned char c : s) {
    if      (c == '&')  out += "&amp;";
    else if (c == '<')  out += "&lt;";
    else if (c == '>')  out += "&gt;";
    else if (c == '"')  out += "&quot;";
    else if (c == '\'') out += "&#39;";
    else                out += (char)c;
  }
  return out;
}

// Reads one field out of an application/x-www-form-urlencoded body.
std::string form_get(const std::string &body, const std::string &field) {
  const std::string search = field + "=";
  size_t pos = 0;
  for (;;) {
    if (body.compare(pos, search.size(), search) == 0) {
      size_t start = pos + search.size();
      size_t end = body.find('&', start);
      return pct_decode(end == std::string::npos
                            ? std::string_view(body).substr(start)
                            : std::string_view(body).substr(start, end - start),
                        /*plusIsSpace=*/true);
    }
    pos = body.find('&', pos);
    if (pos == std::string::npos) break;
    ++pos;
  }
  return "";
}

// Reads one parameter out of a "?a=1&b=2" query string.
std::string query_get(std::string_view query, const std::string &field) {
  return form_get(std::string(query), field);
}

// Constant-time compare so the CSRF token is not leaked byte-by-byte by timing.
bool ct_eq(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  unsigned char acc = 0;
  for (size_t i = 0; i < a.size(); ++i)
    acc |= (unsigned char)(a[i] ^ b[i]);
  return acc == 0;
}

// -----------------------------------------------------------------------------
// [Claude] Room store.
//
// The server is a blind relay.  Every message arrives already sealed by the
// browser and is stored, served and forgotten as an opaque base64 blob; the
// server holds no password, derives no key and never sees a byte of plaintext.
// Consequently the only thing it can validate is the shape of a blob, and the
// only thing on disk is ciphertext, one blob per line.
// -----------------------------------------------------------------------------
struct Entry {
  std::uint64_t id;
  std::string   blob;   // base64( magic || salt || iv || ciphertext+tag )
};

struct Room {
  std::deque<Entry> log;
  std::uint64_t     nextId  = 1;
  std::uintmax_t    bytes   = 0;     // approximate on-disk size
  std::size_t       memory  = 0;     // bytes held by `log`
  std::uint64_t     used    = 0;     // LRU tick, for whole-room eviction
  bool              loaded  = false;
};

std::size_t   g_totalMemory = 0;   // across every loaded room; guarded by g_roomsMutex
std::uint64_t g_lruClock    = 0;

constexpr size_t MAX_BACKFILL  = 200;                 // blobs sent to a new client
// One sealed message.  A file is carried whole rather than split across
// messages and reassembled, so this is also the file-size ceiling, and base64
// costs a third on top: 28 MB of blob is 21 MB of content.
constexpr size_t MAX_BLOB_LEN  = 28u * 1024u * 1024u;
// Sized against the blob, not chosen freely: at 64 MB a room held two 20 MB
// files and then refused everything, which would have made the larger cap
// useless in practice.  384 MB is about thirteen of them.
constexpr size_t MAX_ROOM_SIZE = 384u * 1024u * 1024u;
// Messages can now be large, so bounding the in-memory ring by count alone is
// not enough: 500 × 192 KB would be 96 MB for one room.  Evict on bytes too.
// Memory is bounded across all rooms rather than within each one.  Trimming a
// room's ring was a bug, not a safeguard: an evicted message is on disk but
// unreachable, because room_load runs once and nothing re-reads it — so files
// silently became undownloadable as soon as later ones pushed them out.  A
// loaded room is now fully resident, and pressure is relieved by unloading
// whole rooms, which is safe because ids are line numbers and a reload
// reproduces them exactly.
// Must stay >= MAX_ROOM_SIZE.  memory_reclaim can only unload rooms other than
// the one being served, so a single room larger than the whole budget is
// tolerated ("let it exceed") rather than reclaimed -- the cap would then be
// routinely violated instead of enforced.  At 768 MB two full rooms fit.
constexpr size_t MAX_TOTAL_MEMORY = 768u * 1024u * 1024u;
static_assert(MAX_TOTAL_MEMORY == 768u * 1024u * 1024u,
              "keep g_maxTotalMemory's default in step with this");
// Cap on the blob bytes in one /messages response.  MAX_BACKFILL alone bounds
// the count, which at 28 megabytes each would be a 5 GB body built as a single
// string and pushed through a blocking socket under a send timeout.
//
// Kept at or above MAX_BLOB_LEN deliberately.  A response always carries at
// least one message, so a blob larger than this ceiling is still delivered --
// but it would arrive one per poll, making a room full of large files trickle
// in.  This costs little: the at-least-one rule already puts the worst case at
// one blob per worker regardless of what this says.
constexpr size_t MAX_RESPONSE_BYTES = 32u * 1024u * 1024u;
constexpr size_t MAX_ROOMS     = 512;                 // rooms on disk
constexpr size_t MAX_ROOM_NAME = 64;

// Return a room to its unloaded state.  Safe to do at any time: room_load
// assigns id == line number, so re-reading the file reproduces exactly the same
// ids, and a client's `since` cursor stays valid across the round trip.
inline void room_unload(Room &r) {
  g_totalMemory -= r.memory;
  r.log.clear();
  r.log.shrink_to_fit();
  r.memory = 0;
  r.bytes  = 0;
  r.nextId = 1;
  r.loaded = false;
}

// Set once, on the way out.  The producer and the workers both check it so a
// shutdown can join them instead of destroying them where they stand.
std::atomic<bool> g_shuttingDown{false};

std::mutex                  g_roomsMutex;   // guards g_rooms and g_roomCount
std::map<std::string, Room> g_rooms;
size_t                      g_roomCount = 0;

// Room names address a file, so the character set is a strict whitelist rather
// than a sanitiser: no dot, no slash, nothing to normalise away.  That makes
// path traversal unrepresentable instead of merely filtered.
bool room_name_valid(const std::string &n) {
  if (n.empty() || n.size() > MAX_ROOM_NAME) return false;
  for (unsigned char c : n) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) return false;
  }
  // Names the router owns.  Rejecting them keeps every route unambiguous.
  static const char *reserved[] = {"api", "healthz", "chat", "static", "favicon"};
  for (const char *r : reserved)
    if (n == r) return false;
  return true;
}

std::string room_path(const std::string &name) {
  return g_chatDir + "/" + name + ".log";
}

// A blob is opaque, but it still has to be one safe line of base64.
bool blob_valid(const std::string &b) {
  if (b.empty() || b.size() > g_maxBlobLen) return false;
  for (unsigned char c : b) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    if (!ok) return false;
  }
  return true;
}

// Counts existing transcripts so room creation can be capped.  Anyone who can
// reach the port can make a room, so without a ceiling they could fill the disk.
void rooms_scan() {
  DIR *d = opendir(g_chatDir.c_str());
  if (!d) return;
  size_t n = 0;
  while (struct dirent *e = readdir(d)) {
    std::string nm = e->d_name;
    if (nm.size() > 4 && nm.compare(nm.size() - 4, 4, ".log") == 0) ++n;
  }
  closedir(d);
  g_roomCount = n;
  log_line(CLR_STAR "* Rooms: " + std::to_string(n) + " transcript(s) in " +
           g_chatDir + CLR_RESET);
}

// Free memory by unloading whole rooms, least recently used first, never the
// one being served.  Caller must hold g_roomsMutex.
void memory_reclaim(const std::string &keep) {
  while (g_totalMemory > g_maxTotalMemory) {
    Room *victim = nullptr;
    std::uint64_t oldest = ~0ull;
    for (auto &kv : g_rooms) {
      Room &c = kv.second;
      if (kv.first == keep || !c.loaded || c.log.empty()) continue;
      if (c.used < oldest) { oldest = c.used; victim = &c; }
    }
    if (!victim) break;   // only the room in hand is left; let it exceed
    room_unload(*victim);
  }
}

// Caller must hold g_roomsMutex.
void room_load(Room &r, const std::string &name) {
  if (r.loaded) return;
  r.loaded = true;
  std::ifstream ifs(room_path(name));
  if (!ifs.is_open()) return;
  std::string line;
  while (std::getline(ifs, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    r.bytes  += line.size() + 1;
    r.memory += line.size();
    g_totalMemory += line.size();
    r.log.push_back(Entry{r.nextId++, line});
  }
}

// Presence — who is here, who is typing, who is editing what.
//
// Deliberately NOT part of the transcript.  These are ephemeral facts with no
// value ten seconds later, and the room log is append-only: a typing indicator
// written to disk would sit there forever and eat the room's 64 MB budget for
// nothing.  So they live in a small in-memory ring per room, expire by age, and
// are never persisted.  Still end-to-end encrypted -- the server relays these
// blobs exactly as blindly as it relays messages.
constexpr size_t   MAX_PRESENCE      = 64;               // entries kept per room
constexpr size_t   MAX_PRESENCE_BLOB = 4u * 1024u;       // one presence blob
constexpr std::time_t PRESENCE_TTL   = 60;               // seconds

struct Presence {
  std::uint64_t id;
  std::time_t   ts;
  std::string   blob;
};

std::mutex                              g_presenceMutex;
std::map<std::string, std::deque<Presence>> g_presence;
std::uint64_t                           g_presenceId = 1;

// Caller must hold g_presenceMutex.
inline void presence_expire(std::deque<Presence> &q, std::time_t now) {
  while (!q.empty() && now - q.front().ts > PRESENCE_TTL) q.pop_front();
  while (q.size() > MAX_PRESENCE) q.pop_front();
}

std::uint64_t presence_add(const std::string &room, const std::string &blob) {
  std::lock_guard<std::mutex> lock(g_presenceMutex);
  auto &q = g_presence[room];
  std::time_t now = std::time(nullptr);
  presence_expire(q, now);
  std::uint64_t id = g_presenceId++;
  q.push_back(Presence{id, now, blob});
  return id;
}

std::string presence_json(const std::string &room, std::uint64_t since) {
  std::lock_guard<std::mutex> lock(g_presenceMutex);
  auto it = g_presence.find(room);
  std::string out = "{\"presence\":[";
  if (it != g_presence.end()) {
    presence_expire(it->second, std::time(nullptr));
    bool first = true;
    for (const auto &p : it->second) {
      if (p.id <= since) continue;
      if (!first) out += ',';
      first = false;
      out += "{\"id\":" + std::to_string(p.id) +
             ",\"b\":\"" + p.blob + "\"}";
    }
  }
  out += "]}";
  return out;
}

enum class AppendResult { Ok, Full, TooManyRooms };

// Appends a sealed blob.  Returns the assigned id via `id` on success.
AppendResult room_append(const std::string &name, const std::string &blob,
                         std::uint64_t &id) {
  std::lock_guard<std::mutex> lock(g_roomsMutex);
  auto it = g_rooms.find(name);
  bool fresh = (it == g_rooms.end());
  Room &r = g_rooms[name];
  if (fresh) room_load(r, name);
  r.used = ++g_lruClock;

  // A room that has neither an in-memory log nor a file is about to be created.
  const bool creating = r.log.empty() && r.bytes == 0;
  if (creating && g_roomCount >= MAX_ROOMS) return AppendResult::TooManyRooms;
  if (r.bytes + blob.size() + 1 > MAX_ROOM_SIZE) return AppendResult::Full;

  const std::string path = room_path(name);
  std::ofstream ofs(path, std::ios::app);
  if (!ofs) return AppendResult::Full;
  ofs << blob << '\n';
  ofs.close();

  if (creating) {
    // ofstream honours the umask, which commonly yields 0644.  The directory is
    // already 0700, but the transcript itself should not be world-readable
    // either — belt and braces if the directory mode is ever loosened.
    chmod(path.c_str(), S_IRUSR | S_IWUSR);
    ++g_roomCount;
  }
  r.bytes += blob.size() + 1;
  id = r.nextId++;
  r.memory      += blob.size();
  g_totalMemory += blob.size();
  r.log.push_back(Entry{id, blob});
  memory_reclaim(name);
  return AppendResult::Ok;
}

// Blobs newer than `since`, as JSON.  A room that does not exist is reported
// exactly like one that is empty, so absence and emptiness are indistinguishable
// from outside.
// `tail` > 0 returns the newest `tail` messages instead of walking forward from
// `since`, so a client can open a long-lived room without dragging its whole
// history across first.  `more` says whether anything older was left behind.
//
// Bounding by count rather than by age is not a shortcut: message timestamps
// live inside the ciphertext, and the transcript on disk is pure blobs with no
// arrival times.  Recording them server-side would add exactly the metadata
// this design goes out of its way not to keep.
std::string room_json(const std::string &name, std::uint64_t since,
                      std::size_t tail) {
  std::lock_guard<std::mutex> lock(g_roomsMutex);
  Room &r = g_rooms[name];
  room_load(r, name);
  r.used = ++g_lruClock;
  memory_reclaim(name);

  size_t start = 0;
  bool more = false;
  if (tail) {
    // Walk back from the end taking what fits both bounds, then emit forward.
    size_t bytes = 0, count = 0, i = r.log.size();
    while (i > 0) {
      const Entry &e = r.log[i - 1];
      if (count >= tail) break;
      if (count > 0 && bytes + e.blob.size() > g_maxResponseBytes) break;
      bytes += e.blob.size();
      ++count;
      --i;
    }
    start = i;
    more = (i > 0);
  }

  std::string out = "{\"messages\":[";
  bool first = true;
  size_t bytes = 0, count = 0;
  for (size_t i = start; i < r.log.size(); ++i) {
    const Entry &e = r.log[i];
    if (!tail && e.id <= since) continue;
    if (!first && count >= MAX_BACKFILL) break;
    // Always take at least one, so a message larger than the budget is still
    // delivered rather than wedging the client on it forever.
    if (!first && bytes + e.blob.size() > g_maxResponseBytes) break;
    bytes += e.blob.size();
    ++count;
    if (!first) out += ',';
    first = false;
    out += "{\"id\":" + std::to_string(e.id) +
           ",\"b\":\"" + e.blob + "\"}";   // blob is validated base64
  }
  out += "],\"more\":";
  out += (more ? "true" : "false");
  out += "}";
  return out;
}

// -----------------------------------------------------------------------------
// [Claude] HTTP responses
// -----------------------------------------------------------------------------
// Every response is fully buffered before it is written, so Content-Length is
// always exact and no handler can leave the connection half-framed.
int send_response(FILE *sock, int status, const char *statusText,
                  const char *mime, const std::string &body,
                  bool noCache = true) {
  fprintf(sock, "HTTP/1.1 %d %s\r\n", status, statusText);
  fprintf(sock, "Server: %s\r\n", HTTPD);
  fprintf(sock, "Content-Type: %s\r\n", mime);
  fprintf(sock, "Content-Length: %zu\r\n", body.size());
  fprintf(sock, "X-Content-Type-Options: nosniff\r\n");
  fprintf(sock, "Referrer-Policy: same-origin\r\n");
  fprintf(sock, "Content-Security-Policy: default-src 'none'; script-src 'self';"
                " style-src 'self'; connect-src 'self'; img-src 'self' data:;"
                " worker-src 'self'; form-action 'self'; base-uri 'none';"
                " frame-ancestors 'none'\r\n");
  if (noCache)
    fprintf(sock, "Cache-Control: no-store\r\n");
  else
    fprintf(sock, "Cache-Control: public, max-age=600\r\n");
  fprintf(sock, "Connection: close\r\n\r\n");
  fwrite(body.data(), 1, body.size(), sock);
  fflush(sock);
  return status;
}

int send_error(FILE *sock, int status, const char *statusText,
               const std::string &detail = "") {
  std::string body =
      "<!DOCTYPE html><meta charset=\"utf-8\">"
      "<title>" + std::to_string(status) + " " + statusText + "</title>"
      "<h1>" + std::to_string(status) + " " + statusText + "</h1>";
  if (!detail.empty()) body += "<p>" + html_escape(detail) + "</p>";
  return send_response(sock, status, statusText, "text/html; charset=utf-8", body);
}

// -----------------------------------------------------------------------------
// [Claude] Front-end assets.  Served from memory as their own routes rather than
// inlined, which keeps the CSP at script-src 'self' with no 'unsafe-inline'.
// -----------------------------------------------------------------------------
const char CHAT_CSS[] = R"CSS(
/* A terminal, not a web page: one monospace grid, no chrome, no ornament.
   Committed to dark — a light-mode terminal is a contradiction — so the
   palette is stated once and `color-scheme: dark` keeps form controls in
   step rather than painting them light. */
:root {
  color-scheme: dark;
  --bg:     #0c0c0c;
  --fg:     #ccc;
  --dim:    #6a6a6a;
  --dimmer: #444;
  --bar:    #1b2b33;
  --barfg:  #9fc4d4;
  --accent: #6fb3d2;
  --warn:   #d76b6b;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
          "DejaVu Sans Mono", monospace;
}

* { box-sizing: border-box; }
/* An author `display` rule beats the UA stylesheet's [hidden]{display:none},
   so hiding via el.hidden silently fails on anything styled with display. */
[hidden] { display: none !important; }

html, body { height: 100%; }
body {
  margin: 0;
  display: flex;
  flex-direction: column;
  height: 100dvh;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 var(--mono);
  -webkit-text-size-adjust: 100%;
}
.sr-only {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}

/* The form wraps everything so one Enter submits from anywhere, so the form
   itself is the flex column. */
.composer-form {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

/* ---- room tabs ---- */
/* One browser tab, many rooms.  The bar scrolls rather than wrapping, so a
   long list never steals height from the scrollback. */
.tabs {
  flex: none;
  display: flex;
  gap: 1px;
  padding: 0 .3rem;
  padding-top: env(safe-area-inset-top);
  background: #101010;
  border-bottom: 1px solid #1e1e1e;
  overflow-x: auto;
  white-space: nowrap;
}
.tab {
  flex: none;
  padding: .3rem .8rem;
  font: 13px/1 var(--mono);
  color: var(--dim);
  background: transparent;
  border: 0;
  border-bottom: 2px solid transparent;
  cursor: pointer;
}
.tab:hover { color: var(--fg); }
.tab.on {
  color: #fff;
  background: var(--bg);
  border-bottom-color: var(--accent);
}
/* A room with unread traffic that you are not looking at. */
.tab.unread { color: var(--accent); }

.logs { flex: 1; min-height: 0; display: flex; flex-direction: column; }
/* Transient, so it sits outside the scrollback rather than in it: a typing
   note is not something anyone should scroll back to. */
.typing {
  flex: none;
  padding: .1rem .8rem;
  color: var(--dimmer);
  font-size: 12px;
  font-style: italic;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
#sbHere { margin-left: 1ch; }
.logs > .log { flex: 1; }

/* ---- scrollback ---- */
.log {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  -webkit-overflow-scrolling: touch;
  padding: .5rem .6rem;
  padding-top: calc(.5rem + env(safe-area-inset-top));
}
/* Hanging indent of one timestamp width, so a wrapped line resumes under the
   text rather than under the clock — the thing that makes a scrollback
   readable at a glance. */
.line {
  padding-left: 6ch;
  text-indent: -6ch;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.ts { color: var(--dimmer); }
.nk { font-weight: 700; }
.line.self .tx { color: #e8e8e8; }
/* An uploaded document, printed verbatim under its announcement line. */
.doc {
  margin: .15rem 0 .5rem 6ch;
  padding: .3rem .6rem;
  border-left: 2px solid #2a2a2a;
  color: #b6b6b6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.sys, .sys .tx { color: var(--dim); font-style: normal; }
.sys .pfx { color: var(--dimmer); }
/* sysLine(msg, "err") — command failures, so they do not read as chatter. */
.err .tx { color: var(--warn); }
/* /me — the whole line is the action, so the text sits closer to the nick's
   weight than ordinary speech does. */
.act .tx { color: #c4c4c4; }
/* An inline private message, distinct from room traffic at a glance. */
.pm .tx { color: #e0c56b; }
.pm .nk { color: #d7af5f; }
/* A private message, distinct from room traffic at a glance. */
.pm .tx { color: #e0c56b; }
.pm .nk { color: #d7af5f; }

/* Nick colours: the classic 16-colour terminal palette, picked by hash. */
.c0 { color: #d75f5f; }
.c1 { color: #5fd75f; }
.c2 { color: #d7af5f; }
.c3 { color: #5fafd7; }
.c4 { color: #d75fd7; }
.c5 { color: #5fd7d7; }
.c6 { color: #d7875f; }
.c7 { color: #af87d7; }

/* ---- irssi-style statusbar ---- */
.statusbar {
  flex: none;
  display: flex;
  align-items: center;
  gap: .75ch;
  padding: .15rem .6rem;
  background: var(--bar);
  color: var(--barfg);
  font-size: 13px;
  white-space: nowrap;
  overflow: hidden;
}
.sb { color: var(--barfg); }
.sb-dim { color: #6e8e9c; }
/* Brackets hug their contents: "[nick]", not "[ nick      ]". */
.grp { display: inline-flex; align-items: baseline; }
#nick {
  /* Width is set from the value length in JS; monospace makes ch exact. */
  width: 6ch;
  padding: 0;
  font: inherit;
  font-family: var(--mono);
  color: #fff;
  background: transparent;
  border: 0;
  outline: 0;
}
#nick:focus { background: #2a4450; }
#undec { color: var(--warn); }
.statusbar .spacer { flex: 1; }
#sbLink, #sbNotify, #sbBell {
  flex: none;
  padding: 0;
  font: inherit;
  font-family: var(--mono);
  color: var(--barfg);
  background: transparent;
  border: 0;
  cursor: pointer;
  opacity: .75;
}
#sbNotify, #sbBell { margin-right: 1ch; }
#sbLink:hover, #sbLink:active,
#sbNotify:hover, #sbNotify:active,
#sbBell:hover, #sbBell:active { opacity: 1; color: #fff; }
.dot { color: var(--warn); }
.dot.on { color: #5fd75f; }

/* ---- input line ---- */
.composer {
  flex: none;
  display: flex;
  align-items: baseline;
  gap: 1ch;
  padding: .35rem .6rem;
  padding-bottom: calc(.35rem + env(safe-area-inset-bottom));
  background: var(--bg);
  border-top: 1px solid #1e1e1e;
}
.prompt { flex: none; color: var(--accent); }
#text {
  flex: 1;
  min-width: 0;
  padding: 0;
  /* 16px keeps iOS Safari from zooming the whole page on focus. */
  font: 16px/1.5 var(--mono);
  color: var(--fg);
  background: transparent;
  border: 0;
  outline: 0;
  caret-color: var(--accent);
}
#text::placeholder { color: var(--dimmer); }
/* The send button is redundant next to Enter; keep it for touch, but quiet. */
#send {
  flex: none;
  padding: .2rem .6rem;
  font: 13px/1 var(--mono);
  color: var(--dim);
  background: transparent;
  border: 1px solid #262626;
  border-radius: 2px;
  cursor: pointer;
}
#send:active { color: var(--fg); border-color: #3a3a3a; }
#send.busy { opacity: .4; }

/* ---- note editor ---- */
/* A full-screen editor rather than a pane: editing wants the width, and the
   room is still there underneath when you close it. */
.editor {
  position: fixed;
  inset: 0;
  z-index: 20;
  display: flex;
  flex-direction: column;
  background: var(--bg);
}
.ed-head, .ed-foot {
  flex: none;
  display: flex;
  align-items: center;
  gap: 1ch;
  padding: .3rem .8rem;
  background: var(--bar);
  color: var(--barfg);
  font-size: 13px;
}
.ed-head { padding-top: calc(.3rem + env(safe-area-inset-top)); }
.ed-foot { padding-bottom: calc(.3rem + env(safe-area-inset-bottom)); }
.ed-head .spacer, .ed-foot .spacer { flex: 1; }
#edname { color: #fff; font-weight: 700; }
#edstat { color: #9ec3d4; }
.ed-hint { color: #6e8e9c; }
#edtext {
  flex: 1;
  min-height: 0;
  width: 100%;
  padding: .6rem .8rem;
  resize: none;
  color: var(--fg);
  background: var(--bg);
  border: 0;
  outline: 0;
  /* 16px so iOS does not zoom when the caret lands. */
  font: 16px/1.5 var(--mono);
  tab-size: 4;
}
.ed-foot button {
  padding: .25rem .8rem;
  font: 13px/1 var(--mono);
  color: var(--fg);
  background: transparent;
  border: 1px solid #33505e;
  border-radius: 2px;
  cursor: pointer;
}
.ed-foot button:active { border-color: var(--accent); }
/* A revision that a later one replaced: keep the line, drop the body. */
.doc.superseded { color: var(--dimmer); font-style: italic; }

/* ---- connect screen ---- */
.gate {
  position: fixed;
  inset: 0;
  z-index: 10;
  display: flex;
  padding: 1rem .9rem;
  padding-top: calc(1rem + env(safe-area-inset-top));
  padding-bottom: calc(1rem + env(safe-area-inset-bottom));
  background: var(--bg);
  overflow-y: auto;
}
.gate-card { width: 100%; max-width: 62ch; }
.banner { margin: 0 0 1rem; color: var(--dim); white-space: pre-wrap; }
.banner b { color: var(--accent); font-weight: 700; }
.field { display: flex; align-items: baseline; gap: 1ch; }
.field label { flex: none; color: var(--accent); }
#gateBtn {
  margin-top: 1rem;
  padding: .35rem .9rem;
  font: 14px/1 var(--mono);
  color: var(--fg);
  background: transparent;
  border: 1px solid #333;
  border-radius: 2px;
  cursor: pointer;
}
#gateBtn:active { border-color: var(--accent); }
#gateBtn:disabled, #gateBtn.busy { opacity: .5; }
#gateError { min-height: 1.5em; margin: .8rem 0 0; color: var(--warn); }
.hint { margin: 1.2rem 0 0; color: var(--dimmer); white-space: pre-wrap; }

/* ---- lobby ---- */
.lobby { width: 100%; max-width: 62ch; }
.lobby-wrap {
  flex: 1;
  display: flex;
  padding: 1rem .9rem;
  padding-top: calc(1rem + env(safe-area-inset-top));
  padding-bottom: calc(1rem + env(safe-area-inset-bottom));
  overflow-y: auto;
}
#roomName, #gatePass {
  flex: 1;
  min-width: 0;
  padding: 0 0 2px;
  font: 16px/1.6 var(--mono);
  color: var(--fg);
  background: transparent;
  border: 0;
  /* The only affordance a bare terminal field has is the caret, which is
     invisible until focus — so underline it to show where to type. */
  border-bottom: 1px solid #333;
  outline: 0;
  caret-color: var(--accent);
}
#roomName:focus, #gatePass:focus { border-bottom-color: var(--accent); }
#roomError { min-height: 1.5em; margin: .8rem 0 0; color: var(--warn); }

@media (min-width: 40rem) {
  body { font-size: 13.5px; }
  .log { padding: .6rem 1rem; }
  .statusbar, .composer { padding-left: 1rem; padding-right: 1rem; }
}
)CSS";

constexpr char CHAT_JS[] = R"JS(
(function () {
  "use strict";

  // ===========================================================================
  // One browser tab, many rooms.
  //
  // Everything that used to be per-page — password, salt, key cache, history,
  // poll cursor, scrollback element — is per *session*, one per open room, so
  // rooms can be open at once and messages for a background room still arrive
  // and render into its own log.  Identity is the exception: a keypair belongs
  // to the browser, not to a room, so it stays global.
  //
  //   blob = MAGIC(9) | salt(16) | iv(12) | AES-256-GCM(plaintext)
  //   "ATTOCHAT1" plaintext = JSON                                    (text)
  //   "ATTOCHAT2" plaintext = u32be headerLen | header JSON | bytes   (files)
  //   room key = PBKDF2-SHA256(password, salt, 310000)
  // ===========================================================================
  var MAGIC_PREFIX = [0x41,0x54,0x54,0x4f,0x43,0x48,0x41,0x54];
  var V1 = 0x31, V2 = 0x32;
  var SALT_LEN = 16, IV_LEN = 12, ITERATIONS = 310000;
  var MAX_BLOB = 28 * 1024 * 1024;      // keep in step with MAX_BLOB_LEN
  // What that leaves for content once base64 has taken its third.  The margin
  // covers the magic, salt, IV, GCM tag and the file header.
  var MAX_FILE = Math.floor(MAX_BLOB * 3 / 4) - 4096;
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function b64encode(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function b64decode(str) {
    var s = atob(str);
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  // ---- landing page ----------------------------------------------------------
  if (document.body.dataset.page === "landing") {
    var rf = document.getElementById("roomForm");
    rf.addEventListener("submit", function (e) {
      e.preventDefault();
      var name = document.getElementById("roomName").value.trim();
      if (/^[A-Za-z0-9_-]{1,64}$/.test(name)) location.href = "/" + name;
      else document.getElementById("roomError").textContent =
        "Letters, digits, - and _ only (max 64).";
    });
    return;
  }

  // ---- elements --------------------------------------------------------------
  var tabsEl   = document.getElementById("tabs");
  var logsEl   = document.getElementById("logs");
  var form     = document.getElementById("composer");
  var text     = document.getElementById("text");
  var nick     = document.getElementById("nick");
  var sendBtn  = document.getElementById("send");
  var dot      = document.getElementById("dot");
  var sbRoom   = document.getElementById("sbRoom");
  var sbClock  = document.getElementById("sbClock");
  var undecEl  = document.getElementById("undec");
  var sbHere   = document.getElementById("sbHere");
  var typingEl = document.getElementById("typing");
  var sbLink   = document.getElementById("sbLink");
  var sbNotify = document.getElementById("sbNotify");
  var sbBell = document.getElementById("sbBell");
  var mdFile   = document.getElementById("mdFile");
  var gate     = document.getElementById("gate");
  var gateForm = document.getElementById("gateForm");
  var gatePass = document.getElementById("gatePass");
  var gateErr  = document.getElementById("gateError");
  var gateBtn  = document.getElementById("gateBtn");
  var editor   = document.getElementById("editor");
  var edname   = document.getElementById("edname");
  var edstat   = document.getElementById("edstat");
  var edtext   = document.getElementById("edtext");
  var edsave   = document.getElementById("edsave");
  var edclose  = document.getElementById("edclose");

  var firstRoom = document.body.dataset.room;
  var csrf      = form.elements["_csrf"].value;

  if (!window.crypto || !crypto.subtle) {
    gateErr.textContent =
      "This page needs a secure context for encryption. Use HTTPS, or open it " +
      "on localhost.";
    gatePass.disabled = true;
    gateBtn.disabled = true;
    return;
  }

  // Tapping a button focuses it, which dismisses the on-screen keyboard.
  // Cancelling mousedown keeps focus where it is; the click still fires.
  [sendBtn, gateBtn, sbLink, sbNotify, sbBell, edsave, edclose].forEach(function (b) {
    b.addEventListener("mousedown", function (e) { e.preventDefault(); });
  });

  // ===========================================================================
  // Sessions
  // ===========================================================================
  var sessions = new Map();     // room -> session
  var S = null;                 // the active one

  function newSession(room, label) {
    var logEl = document.createElement("div");
    logEl.className = "log";
    logEl.hidden = true;
    logsEl.appendChild(logEl);

    var tab = document.createElement("button");
    tab.type = "button";
    tab.className = "tab";
    tab.textContent = label || ("#" + room);
    tab.addEventListener("mousedown", function (e) { e.preventDefault(); });
    tab.addEventListener("click", function () { activate(room); });
    tabsEl.appendChild(tab);

    var s = {
      room: room, label: label || ("#" + room),
      password: null, salt: null, keyCache: new Map(),
      history: [], lastId: 0, docEls: {}, undec: 0,
      truncated: false, primed: false,
      inFlight: false, unread: 0,
      logEl: logEl, tabEl: tab,
      stick: true, lastGesture: 0, announced: false
    };

    logEl.addEventListener("scroll", function () {
      if (Date.now() - s.lastGesture < 1200) s.stick = nearBottom(s);
    });
    ["wheel","touchstart","touchmove","mousedown","keydown"].forEach(function (ev) {
      logEl.addEventListener(ev, function () { s.lastGesture = Date.now(); },
                             { passive: true });
    });

    sessions.set(room, s);
    return s;
  }

  function activate(room) {
    var s = sessions.get(room);
    if (!s) return;
    sessions.forEach(function (o) {
      o.logEl.hidden = true;
      o.tabEl.classList.remove("on");
    });
    s.logEl.hidden = false;
    s.tabEl.classList.add("on");
    s.unread = 0;
    paintTab(s);
    S = s;
    sbRoom.textContent = s.label;
    paintUndec();
    document.title = s.label + " · attochat";
    repin();
    text.focus();
  }

  function paintTab(s) {
    s.tabEl.textContent = s.label + (s.unread ? " (" + s.unread + ")" : "");
    s.tabEl.classList.toggle("unread", s.unread > 0 && s !== S);
  }

  function closeSession(room) {
    var s = sessions.get(room);
    if (!s || sessions.size < 2) return false;
    s.logEl.remove();
    s.tabEl.remove();
    sessions.delete(room);
    if (S === s) activate(sessions.keys().next().value);
    return true;
  }

  // ---- per-session crypto ----------------------------------------------------
  function deriveKey(s, salt) {
    // A private conversation carries its key rather than deriving one from a
    // password; the salt in the blob header is written but unused there.
    if (s.fixedKey) return s.fixedKey;
    var tag = b64encode(salt);
    if (s.keyCache.has(tag)) return s.keyCache.get(tag);
    // Cache the promise: concurrent callers must not each start a 310k-round
    // derivation for the same salt.
    var p = crypto.subtle
      .importKey("raw", enc.encode(s.password), "PBKDF2", false, ["deriveKey"])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: salt, iterations: ITERATIONS, hash: "SHA-256" },
          base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      });
    s.keyCache.set(tag, p);
    return p;
  }

  function seal(s, obj) {
    if (!s.salt) s.salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    var salt = s.salt, iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    return deriveKey(s, salt).then(function (key) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key,
                                   enc.encode(JSON.stringify(obj)));
    }).then(function (ct) {
      var body = new Uint8Array(ct);
      var out = new Uint8Array(9 + SALT_LEN + IV_LEN + body.length);
      out.set(MAGIC_PREFIX, 0); out[8] = V1;
      out.set(salt, 9); out.set(iv, 9 + SALT_LEN);
      out.set(body, 9 + SALT_LEN + IV_LEN);
      return b64encode(out);
    });
  }

  function sealBytes(s, header, bytes) {
    if (!s.salt) s.salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    var salt = s.salt, iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    var hj = enc.encode(JSON.stringify(header));
    var pt = new Uint8Array(4 + hj.length + bytes.length);
    new DataView(pt.buffer).setUint32(0, hj.length, false);
    pt.set(hj, 4); pt.set(bytes, 4 + hj.length);
    return deriveKey(s, salt).then(function (key) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, pt);
    }).then(function (ct) {
      var body = new Uint8Array(ct);
      var out = new Uint8Array(9 + SALT_LEN + IV_LEN + body.length);
      out.set(MAGIC_PREFIX, 0); out[8] = V2;
      out.set(salt, 9); out.set(iv, 9 + SALT_LEN);
      out.set(body, 9 + SALT_LEN + IV_LEN);
      return b64encode(out);
    });
  }

  function unseal(s, blobB64) {
    var raw;
    try { raw = b64decode(blobB64); } catch (e) { return Promise.resolve(null); }
    var head = 9 + SALT_LEN + IV_LEN;
    if (raw.length < head + 16) return Promise.resolve(null);
    for (var i = 0; i < MAGIC_PREFIX.length; i++)
      if (raw[i] !== MAGIC_PREFIX[i]) return Promise.resolve(null);
    var version = raw[8];
    if (version !== V1 && version !== V2) return Promise.resolve(null);
    var salt = raw.slice(9, 9 + SALT_LEN);
    var iv   = raw.slice(9 + SALT_LEN, head);
    var ct   = raw.slice(head);
    return deriveKey(s, salt).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct);
    }).then(function (buf) {
      var pt = new Uint8Array(buf);
      if (version === V1) {
        var m = JSON.parse(dec.decode(pt));
        if (!m || typeof m !== "object") return null;
        // Only a plain message must carry text; kinded records need not.
        if (typeof m.t !== "string" && !m.k) return null;
        return m;
      }
      var hlen = new DataView(pt.buffer, pt.byteOffset).getUint32(0, false);
      if (hlen > pt.length - 4) return null;
      var f = JSON.parse(dec.decode(pt.slice(4, 4 + hlen)));
      f.bytes = pt.slice(4 + hlen);
      return f;
    }).catch(function () { return null; });
  }

  // ===========================================================================
  // Identity — belongs to the browser, not to a room, so it is global.
  // ===========================================================================
  var IDB_NAME = "attochat", IDB_STORE = "identity";
  var myKeys = null, myPub = null, myFp = null, myNick = "";
  var identities = new Map();   // pub -> {nick, fp, seen, ts}
  var seenCounter = 0;
  var pairRoomCache = new Map();   // pub -> {room, password}   for /dm
  var dmKeyCache    = new Map();   // pub -> AES-GCM key         for inline /msg

  function idb(fn) {
    return new Promise(function (resolve, reject) {
      var rq = indexedDB.open(IDB_NAME, 1);
      rq.onupgradeneeded = function () { rq.result.createObjectStore(IDB_STORE); };
      rq.onerror = function () { reject(rq.error); };
      rq.onsuccess = function () {
        var tx = rq.result.transaction(IDB_STORE, "readwrite");
        var req = fn(tx.objectStore(IDB_STORE));
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { reject(req.error); };
      };
    });
  }

  function loadIdentity() {
    return idb(function (s) { return s.get("ecdh"); })
      .then(function (found) {
        if (found && found.privateKey) return found;
        return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" },
                                         false, ["deriveBits"])
          .then(function (kp) {
            return idb(function (s) { return s.put(kp, "ecdh"); })
              .then(function () { return kp; });
          });
      })
      .then(function (kp) { myKeys = kp; return crypto.subtle.exportKey("raw", kp.publicKey); })
      .then(function (raw) { myPub = b64encode(new Uint8Array(raw)); return fingerprint(myPub); })
      .then(function (fp) { myFp = fp; });
  }

  function fingerprint(pubB64) {
    return crypto.subtle.digest("SHA-256", b64decode(pubB64)).then(function (h) {
      var b = new Uint8Array(h), out = [];
      for (var i = 0; i < 8; i++) out.push(("0" + b[i].toString(16)).slice(-2));
      return out.join("").replace(/(....)/g, "$1 ").trim();
    });
  }

  // Keyed by public key, never by nick: a nick is a label that moves, and
  // keying by it meant a rename orphaned the entry.
  function noteIdentity(pub, nick, ts) {
    var when = ts || Date.now();
    var e = identities.get(pub);
    if (!e) {
      e = { nick: nick || "?", fp: null, seen: ++seenCounter, ts: when };
      identities.set(pub, e);
      fingerprint(pub).then(function (fp) { e.fp = fp; });
      return { entry: e, isNew: true };
    }
    if (nick) e.nick = nick;
    e.seen = ++seenCounter;
    if (when > (e.ts || 0)) e.ts = when;
    return { entry: e, isNew: false };
  }

  // A room's key records are append-only, so every guest who ever passed
  // through is still in the transcript and gets replayed into the directory on
  // every load.  Nothing can delete them from the log, but they need not stay
  // addressable: an unnamed guest last heard from a day ago is not someone you
  // can usefully /dm, and leaving them in makes `guest-4127` ambiguous between
  // a live participant and a ghost from last week.
  //
  // Only ever drops still-default nicks.  Picking a name is the signal that
  // someone means to be found again, so a named identity is kept regardless of
  // age; and anyone currently in a room's roster is kept whatever they are
  // called.
  var GUEST_TTL_MS = 12 * 3600 * 1000;
  var DEFAULT_NICK = /^guest-[0-9]{4}$/;

  function pruneIdentities() {
    var now = Date.now(), live = {}, dropped = 0;
    sessions.forEach(function (s) {
      if (s.roster) Object.keys(s.roster).forEach(function (n) { live[n] = 1; });
    });
    identities.forEach(function (e, pub) {
      if (pub === myPub) return;
      if (!DEFAULT_NICK.test(e.nick)) return;
      if (live[e.nick]) return;
      if (now - (e.ts || 0) < GUEST_TTL_MS) return;
      identities.delete(pub);
      pairRoomCache.delete(pub);
      dmKeyCache.delete(pub);      // drop the derived AES key too, not just the row
      dropped++;
    });
    return dropped;
  }

  function renameIdentity(pub, oldNick, newNick) {
    if (pub && identities.has(pub)) { identities.get(pub).nick = newNick; return true; }
    var hit = null;
    identities.forEach(function (e) {
      if (e.nick === oldNick && (!hit || e.seen > hit.seen)) hit = e;
    });
    if (hit) { hit.nick = newNick; return true; }
    return false;
  }

  function pubForNick(n) {
    var best = null, bestPub = null;
    identities.forEach(function (e, pub) {
      if (e.nick === n && (!best || e.seen > best.seen)) { best = e; bestPub = pub; }
    });
    return bestPub;
  }

  // ---- the pair room ---------------------------------------------------------
  // Shared-secret material for a peer: ECDH against their published key, then
  // HKDF with a per-purpose info string so the room name, the room's message
  // key and the inline /msg key are independent of one another.
  function pairBits(peerPub, info, bytes) {
    return crypto.subtle.importKey("raw", b64decode(peerPub),
        { name: "ECDH", namedCurve: "P-256" }, false, [])
      .then(function (pk) {
        return crypto.subtle.deriveBits({ name: "ECDH", public: pk },
                                        myKeys.privateKey, 256);
      })
      .then(function (raw) {
        return crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
      })
      .then(function (hk) {
        return crypto.subtle.deriveBits(
          { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
            info: enc.encode(info) }, hk, bytes * 8);
      })
      .then(function (b) { return new Uint8Array(b); });
  }

  // A private conversation is keyed by the ECDH agreement *itself*: the room
  // name comes from it, and so does the AES key used for every message in it.
  // There is no password anywhere in the loop, which is the point -- a password
  // is a thing that can be copied out and handed to a third person, and this
  // conversation is supposed to hold exactly two.
  function pairRoom(peerPub) {
    if (pairRoomCache.has(peerPub)) return pairRoomCache.get(peerPub);
    var p = Promise.all([
      pairBits(peerPub, "attochat-dmroom-name-v1", 16),
      pairBits(peerPub, "attochat-dmroom-key-v1", 32)
    ]).then(function (parts) {
      var hex = "";
      parts[0].forEach(function (x) { hex += ("0" + x.toString(16)).slice(-2); });
      return crypto.subtle.importKey("raw", parts[1], { name: "AES-GCM" }, false,
                                     ["encrypt", "decrypt"])
        .then(function (k) { return { room: "dm" + hex, key: k }; });
    });
    pairRoomCache.set(peerPub, p);
    return p;
  }

  // The other kind of DM: a message that stays in the current room, encrypted
  // to the pair so only they can read it.  Different HKDF info from the pair
  // room, so the two are domain-separated even though both start from the same
  // ECDH agreement.
  function dmKey(peerPub) {
    if (dmKeyCache.has(peerPub)) return dmKeyCache.get(peerPub);
    var p = pairBits(peerPub, "attochat-dm-v1", 32).then(function (raw) {
      return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false,
                                     ["encrypt", "decrypt"]);
    });
    dmKeyCache.set(peerPub, p);
    return p;
  }

  function dmSeal(peerPub, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return dmKey(peerPub).then(function (k) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, k,
                                   enc.encode(JSON.stringify(obj)));
    }).then(function (ct) {
      return { iv: b64encode(iv), ct: b64encode(new Uint8Array(ct)) };
    });
  }

  function dmOpen(peerPub, ivB64, ctB64) {
    return dmKey(peerPub).then(function (k) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: b64decode(ivB64) },
                                   k, b64decode(ctB64));
    }).then(function (pt) { return JSON.parse(dec.decode(pt)); })
      .catch(function () { return null; });
  }

  // ===========================================================================
  // Rendering — always into the session the message belongs to.
  // ===========================================================================
  function nickClass(s) {
    var h = 0;
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return "c" + (h % 8);
  }
  function fmtTime(ms) {
    var d = new Date(ms);
    return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
  }
  function nearBottom(s) {
    return s.logEl.scrollHeight - s.logEl.scrollTop - s.logEl.clientHeight < 90;
  }
  function scrollEnd(s) { s.logEl.scrollTop = s.logEl.scrollHeight; }

  // A viewport change reflows the log and its new height is not known until
  // layout settles, so re-assert across the next few frames.
  function repin() {
    if (!S || !S.stick) return;
    scrollEnd(S);
    requestAnimationFrame(function () { scrollEnd(S); });
    setTimeout(function () { if (S) scrollEnd(S); }, 150);
    setTimeout(function () { if (S) scrollEnd(S); }, 350);
  }
  window.addEventListener("resize", repin);
  window.addEventListener("orientationchange", repin);
  if (window.visualViewport) {
    visualViewport.addEventListener("resize", repin);
    visualViewport.addEventListener("scroll", repin);
  }
  text.addEventListener("focus", function () { setTimeout(repin, 300); });

  function line(s, ts, cls) {
    var el = document.createElement("div");
    el.className = "line" + (cls ? " " + cls : "");
    var t = document.createElement("span");
    t.className = "ts";
    t.textContent = fmtTime(ts || Date.now()) + " ";
    el.appendChild(t);
    return el;
  }

  function put(s, el) {
    s.logEl.appendChild(el);
    while (s.logEl.children.length > 1000) s.logEl.removeChild(s.logEl.firstChild);
    if (s === S) repin(); else { s.unread++; paintTab(s); }
  }

  function sysLine(s, textStr, cls) {
    var el = line(s, Date.now(), "sys" + (cls ? " " + cls : ""));
    var p = document.createElement("span");
    p.className = "pfx"; p.textContent = "-!- ";
    var x = document.createElement("span");
    x.className = "tx"; x.textContent = textStr;
    el.appendChild(p); el.appendChild(x);
    put(s, el);
  }
  function say(textStr, cls) { sysLine(S, textStr, cls); }

  function humanSize(n) {
    return n < 1024 ? n + " B"
         : n < 1024 * 1024 ? (n / 1024).toFixed(1) + " KB"
         : (n / (1024 * 1024)).toFixed(1) + " MB";
  }
  function pad(str, w) {
    str = String(str);
    if (str.length >= w) return str.slice(0, w - 1) + "… ";
    return str + new Array(w - str.length + 1).join(" ");
  }

  function fileRecords(s) { return s.history.filter(function (m) { return m.f; }); }
  function latestFiles(s) {
    var byName = {};
    fileRecords(s).forEach(function (m) {
      var e = byName[m.f];
      if (!e) byName[m.f] = { name: m.f, rec: m, revs: 1 };
      else { e.rec = m; e.revs++; }
    });
    return Object.keys(byName).sort().map(function (n) { return byName[n]; });
  }
  function revisionsOf(s, name) {
    return fileRecords(s).filter(function (m) { return m.f === name; }).length;
  }
  function fileBytes(m) { return m.bytes ? m.bytes : enc.encode(m.t || ""); }

  function append(s, m) {
    s.history.push(m);
    if (s.history.length > 1000) s.history.shift();
    var name = m.n || "anon";

    if (m.k === "key" && m.pub) {
      var before = identities.get(m.pub);
      var claimed = pubForNick(name);
      noteIdentity(m.pub, name, m.ts);
      // Only two identities can derive this room's key, so a third one
      // appearing means a private key was shared or copied.  Say so loudly
      // rather than quietly rendering their traffic as ordinary chat.
      if (s.isDm && m.pub !== myPub && m.pub !== s.peerPub) {
        fingerprint(m.pub).then(function (fp) {
          sysLine(s, "WARNING: a third identity is in this private conversation" +
                  " - " + name + " / " + fp +
                  "; someone's private key has been copied", "err");
        });
        return;
      }
      if (!before && m.pub !== myPub) {
        fingerprint(m.pub).then(function (fp) {
          if (claimed && claimed !== m.pub)
            sysLine(s, "WARNING: " + name + " now claimed by a different key — " +
                    fp + "; verify out of band", "err");
          else sysLine(s, name + " is here — key " + fp);
        });
      }
      return;
    }

    // An inline private message.  The room sees that one happened and between
    // whom; only the two endpoints can read it.
    if (m.k === "pm") {
      var mine = m.sp === myPub, forMe = m.tp === myPub;
      if (!mine && !forMe) {
        var op = line(s, m.ts, "sys");
        var oq = document.createElement("span");
        oq.className = "pfx"; oq.textContent = "-!- ";
        var ot = document.createElement("span");
        ot.className = "tx";
        ot.textContent = name + " -> " + (m.to || "?") + "  (encrypted, not for you)";
        op.appendChild(oq); op.appendChild(ot);
        put(s, op);
        return;
      }
      var peerPub = mine ? m.tp : m.sp;
      var pel = line(s, m.ts, "pm");
      var pwho = document.createElement("span");
      pwho.className = "nk " + nickClass(mine ? (m.to || "?") : name);
      pwho.textContent = mine ? "[you -> " + (m.to || "?") + "] "
                              : "[" + name + " -> you] ";
      var pbody = document.createElement("span");
      pbody.className = "tx";
      pbody.textContent = "...";
      pel.appendChild(pwho); pel.appendChild(pbody);
      put(s, pel);
      dmOpen(peerPub, m.iv, m.ct).then(function (inner) {
        pbody.textContent = inner && typeof inner.t === "string"
          ? inner.t : "(could not decrypt)";
        if (s === S) repin();
      });
      return;
    }

    if (m.k === "nick") {
      renameIdentity(m.pub, name, m.t);
      var ev = line(s, m.ts, "sys");
      var ep = document.createElement("span");
      ep.className = "pfx"; ep.textContent = "-!- ";
      var et = document.createElement("span");
      et.className = "tx"; et.textContent = name + " is now known as " + m.t;
      ev.appendChild(ep); ev.appendChild(et);
      put(s, ev);
      return;
    }

    if (m.k === "me") {
      var ac = line(s, m.ts, "act");
      var an = document.createElement("span");
      an.className = "nk " + nickClass(name);
      an.textContent = "* " + name + " ";
      var at = document.createElement("span");
      at.className = "tx"; at.textContent = m.t;
      ac.appendChild(an); ac.appendChild(at);
      put(s, ac);
      return;
    }

    if (m.f && m.bytes) {
      var fh = line(s, m.ts, "sys");
      var fp2 = document.createElement("span");
      fp2.className = "pfx"; fp2.textContent = "-!- ";
      var ft = document.createElement("span");
      ft.className = "tx";
      ft.textContent = name + " attached " + m.f + " (" +
                       humanSize(m.bytes.length) + ")  —  /dl " +
                       latestFiles(s).length;
      fh.appendChild(fp2); fh.appendChild(ft);
      put(s, fh);
      return;
    }

    if (m.f) {
      // A later revision replaces an earlier one, so drop the earlier body
      // rather than printing the note again for every edit.
      var prior = s.docEls[m.f];
      if (prior) {
        prior.textContent = "(superseded by a later revision)";
        prior.className = "doc superseded";
      }
      var rev = revisionsOf(s, m.f);
      var head = line(s, m.ts, "sys");
      var hp = document.createElement("span");
      hp.className = "pfx"; hp.textContent = "-!- ";
      var ht = document.createElement("span");
      ht.className = "tx";
      ht.textContent = name + (prior ? " updated " : " uploaded ") + m.f + " (" +
                       humanSize((m.t || "").length) +
                       (rev > 1 ? ", rev " + rev : "") + ")";
      head.appendChild(hp); head.appendChild(ht);
      put(s, head);
      var doc = document.createElement("div");
      doc.className = "doc";
      doc.textContent = m.t;
      s.logEl.appendChild(doc);
      s.docEls[m.f] = doc;
      return;
    }

    var el = line(s, m.ts, name === myNick ? "self" : "");
    var nk = document.createElement("span");
    nk.className = "nk " + nickClass(name);
    nk.textContent = "<" + name + "> ";
    var tx = document.createElement("span");
    tx.className = "tx"; tx.textContent = m.t;
    el.appendChild(nk); el.appendChild(tx);
    put(s, el);
  }

  function paintUndec() {
    if (!S || !S.undec) { undecEl.hidden = true; return; }
    undecEl.hidden = false;
    undecEl.textContent = "!" + S.undec;
    undecEl.title = S.undec + " message(s) sealed with a different password";
  }

  // ===========================================================================
  // Sending
  // ===========================================================================
  function sendBlob(s, blobPromise) {
    sendBtn.classList.add("busy");
    return blobPromise
      .then(function (blob) {
        if (blob.length > MAX_BLOB)
          throw new Error("too large once encrypted (" + humanSize(blob.length) +
                          " > " + humanSize(MAX_BLOB) + ")");
        var params = new URLSearchParams();
        params.set("_csrf", csrf);
        params.set("b", blob);
        return fetch("/api/r/" + s.room + "/send", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: params.toString()
        });
      })
      .then(function (r) {
        sendBtn.classList.remove("busy");
        if (!r.ok) throw new Error("server said " + r.status);
        setOnline(true);
        poll(s);
      })
      .catch(function (err) {
        sendBtn.classList.remove("busy");
        setOnline(false);
        throw err;
      });
  }
  function post(s, record)             { return sendBlob(s, seal(s, record)); }
  function postBytes(s, header, bytes) { return sendBlob(s, sealBytes(s, header, bytes)); }

  // ===========================================================================
  // Presence: who is here, who is typing, who is touching what.
  //
  // Sent on a separate channel the server keeps only in memory, because these
  // are facts with a ten-second shelf life and the room log is append-only --
  // a typing indicator written to the transcript would outlive the
  // conversation.  Sealed with the room key like everything else, so the
  // server relays them just as blindly.
  //
  // Broadcasting activity is a choice, not a given: /quiet stops sending
  // without stopping you receiving.
  // ===========================================================================
  var PRESENCE_BEAT_MS = 20000;      // heartbeat
  var PRESENCE_GONE_MS = 50000;      // silence after which someone has left
  var TYPING_THROTTLE_MS = 3000;     // at most one typing note per this
  var TYPING_FADE_MS = 6000;         // how long a typing note stands
  var broadcasting = true;
  try { broadcasting = localStorage.getItem("attochat.quiet") !== "1"; } catch (e) {}

  function sendPresence(s, record) {
    if (!broadcasting || !s || s.password === null) return Promise.resolve();
    return seal(s, record).then(function (blob) {
      if (blob.length > 4096) return;          // server refuses larger
      var params = new URLSearchParams();
      params.set("_csrf", csrf);
      params.set("b", blob);
      return fetch("/api/r/" + s.room + "/presence", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString()
      });
    }).catch(function () {});
  }

  // Announce something the room might want to see you doing.
  function announceAct(s, what) { sendPresence(s, { k: "act", n: myNick, w: what, ts: Date.now() }); }

  function beat(s) { sendPresence(s, { k: "here", n: myNick, ts: Date.now() }); }

  var lastTypingSent = 0;
  function noteTyping() {
    if (!S || !text.value) return;
    var now = Date.now();
    if (now - lastTypingSent < TYPING_THROTTLE_MS) return;
    lastTypingSent = now;
    sendPresence(S, { k: "typing", n: myNick, ts: now });
  }
  text.addEventListener("input", noteTyping);

  // Roster and typing state, per session.
  function rosterTouch(s, nick, when) {
    if (!s.roster) s.roster = {};
    var known = s.roster[nick];
    s.roster[nick] = when;
    if (!known && nick !== myNick) sysLine(s, nick + " is here");
    paintPresence();
  }

  function rosterSweep() {
    var now = Date.now();
    sessions.forEach(function (s) {
      if (!s.roster) return;
      Object.keys(s.roster).forEach(function (n) {
        if (now - s.roster[n] > PRESENCE_GONE_MS) {
          delete s.roster[n];
          if (n !== myNick) sysLine(s, n + " has gone quiet");
        }
      });
      if (s.typing) {
        Object.keys(s.typing).forEach(function (n) {
          if (now - s.typing[n] > TYPING_FADE_MS) delete s.typing[n];
        });
      }
    });
    pruneIdentities();
    paintPresence();
  }

  function paintPresence() {
    if (!S) return;
    var here = S.roster ? Object.keys(S.roster).length : 0;
    sbHere.textContent = here ? "[" + here + " here]" : "";
    var t = [];
    if (S.typing) {
      var now = Date.now();
      Object.keys(S.typing).forEach(function (n) {
        if (n !== myNick && now - S.typing[n] <= TYPING_FADE_MS) t.push(n);
      });
    }
    if (!t.length) { typingEl.hidden = true; return; }
    typingEl.hidden = false;
    typingEl.textContent = t.length === 1
      ? t[0] + " is typing..."
      : t.slice(0, 3).join(", ") + " are typing...";
  }

  function pollPresence(s) {
    if (!s || s.password === null || s.presenceInFlight) return;
    if (document.hidden) return;
    s.presenceInFlight = true;
    fetch("/api/r/" + s.room + "/presence?since=" + (s.presenceLast || 0),
          { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var list = data.presence || [];
        if (!list.length) { s.presenceInFlight = false; return; }
        return Promise.all(list.map(function (p) { return unseal(s, p.b); }))
          .then(function (opened) {
            for (var i = 0; i < list.length; i++) {
              if (list[i].id > (s.presenceLast || 0)) s.presenceLast = list[i].id;
              var m = opened[i];
              if (!m || !m.n) continue;
              rosterTouch(s, m.n, Date.now());
              if (m.k === "typing") {
                if (!s.typing) s.typing = {};
                s.typing[m.n] = Date.now();
                paintPresence();
              } else if (m.k === "act" && m.n !== myNick) {
                sysLine(s, m.n + " " + m.w);
              }
            }
            s.presenceInFlight = false;
          });
      })
      .catch(function () { s.presenceInFlight = false; });
  }

  setInterval(function () {
    if (document.hidden) return;
    sessions.forEach(function (s) { beat(s); pollPresence(s); });
    rosterSweep();
  }, PRESENCE_BEAT_MS / 4);

  // Best effort only; an unload has no time for a round trip.
  window.addEventListener("pagehide", function () {
    if (!broadcasting) return;
    sessions.forEach(function (s) {
      if (s.password === null) return;
      seal(s, { k: "act", n: myNick, w: "left", ts: Date.now() }).then(function (blob) {
        var body = new URLSearchParams();
        body.set("_csrf", csrf); body.set("b", blob);
        if (navigator.sendBeacon)
          navigator.sendBeacon("/api/r/" + s.room + "/presence", body);
      });
    });
  });

  // ===========================================================================
  // Polling — every open session, plus a slower sweep for unopened DM rooms.
  // ===========================================================================
  var POLL_MS = 2000, POLL_HIDDEN_MS = 15000, timer = null;

  function setOnline(ok) {
    dot.className = "dot" + (ok ? " on" : "");
    dot.textContent = ok ? "+" : "!";
    dot.title = ok ? "connected" : "reconnecting";
  }

  function announce(s) {
    if (s.announced || !myPub || !s.password) return;
    var already = false;
    for (var i = s.history.length - 1; i >= 0; i--)
      if (s.history[i].k === "key" && s.history[i].pub === myPub) { already = true; break; }
    s.announced = true;
    if (already) return;
    post(s, { k: "key", n: myNick, pub: myPub, ts: Date.now() })
      .catch(function () { s.announced = false; });
  }

  function poll(s) {
    if (!s || s.inFlight || s.password === null) return;
    if (document.hidden && !notifyOn()) return;
    s.inFlight = true;
    fetch("/api/r/" + s.room + "/messages?since=" + s.lastId,
          { headers: { "Accept": "application/json" }, cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      })
      .then(function (data) {
        setOnline(true);
        var msgs = data.messages || [];
        announce(s);
        if (!msgs.length) { s.inFlight = false; return; }
        return Promise.all(msgs.map(function (m) { return unseal(s, m.b); }))
          .then(function (opened) {
            // Before the window, not after it: the notice describes the
            // history above these lines.
            if (s.truncated) {
              s.truncated = false;
              sysLine(s, "- older history not loaded; /fullload to fetch it -");
            }
            var bad = 0, fresh = [], heard = 0;
            for (var i = 0; i < msgs.length; i++) {
              if (msgs[i].id > s.lastId) s.lastId = msgs[i].id;
              if (!opened[i]) { bad++; continue; }
              append(s, opened[i]);
              var m = opened[i];
              // Someone else saying something, rather than plumbing: a key
              // announcement or a rename is not worth a noise.
              var speech = (!m.k || m.k === "me" || m.k === "pm" || m.k === "md");
              if (speech && m.n !== myNick) heard++;
              if (away() && m.n !== myNick) fresh.push(m);
            }
            if (bad) { s.undec += bad; if (s === S) paintUndec(); }
            // Not on the opening window: joining a busy room should not fire
            // one tone per message of its history.
            if (heard && s.primed) ring();
            s.primed = true;
            notify(s, fresh);
            s.inFlight = false;
          });
      })
      .catch(function () { s.inFlight = false; setOnline(false); });
  }

  function pollAll() { sessions.forEach(function (s) { poll(s); }); }

  function startPolling() {
    if (timer) { clearInterval(timer); timer = null; }
    if (document.hidden && !notifyOn()) return;
    timer = setInterval(pollAll, document.hidden ? POLL_HIDDEN_MS : POLL_MS);
    pollAll();
  }
  document.addEventListener("visibilitychange", function () {
    startPolling();
    if (!away()) clearNotifications();
  });
  window.addEventListener("focus", function () {
    if (!away()) clearNotifications();
  });

  // Unopened DM rooms are swept slowly: for every identity we know, the pair
  // room is computable, so a DM arrives without anyone having to signal first.
  var DM_SWEEP_MS = 12000;
  var sweeping = false;
  function sweepDmRooms() {
    if (sweeping || !myPub || document.hidden) return;
    sweeping = true;
    var peers = [];
    identities.forEach(function (e, pub) { if (pub !== myPub) peers.push([pub, e]); });
    var i = 0;
    function next() {
      if (i >= peers.length) { sweeping = false; return; }
      var pair = peers[i++];
      pairRoom(pair[0]).then(function (d) {
        if (sessions.has(d.room)) return next();
        return fetch("/api/r/" + d.room + "/messages?tail=1", { cache: "no-store" })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            if (!data.messages || !data.messages.length) return next();
            openDmRoom(pair[0], pair[1].nick, true);
            next();
          });
      }).catch(next);
    }
    next();
  }
  setInterval(sweepDmRooms, DM_SWEEP_MS);

  // ===========================================================================
  // Joining rooms
  // ===========================================================================
  // Unlock is the same test the gate makes: the password is right if it opens
  // any recent message.  Testing only the newest would let one foreign blob
  // lock a room permanently.
  // How much of a long-lived room to open with.  The rest stays on the server
  // until /fullload asks for it.
  var INITIAL_LOAD = 200;

  function unlockSession(s, password, full) {
    s.password = password;
    s.keyCache.clear();
    var q = full ? "?since=0" : "?tail=" + INITIAL_LOAD;
    return fetch("/api/r/" + s.room + "/messages" + q, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var msgs = data.messages || [];
        s.truncated = !!data.more;
        // Rewind to just before the oldest message we were given, so the
        // ordinary forward poll renders exactly this window and nothing older.
        if (msgs.length) s.lastId = msgs[0].id - 1;
        if (!msgs.length) return true;              // new room: nothing to test
        var SCAN = 50, DISTINCT = 5, salts = [], order = [];
        for (var i = msgs.length - 1; i >= Math.max(0, msgs.length - SCAN); i--) {
          var raw;
          try { raw = b64decode(msgs[i].b); } catch (e) { continue; }
          if (raw.length < 9 + SALT_LEN + IV_LEN + 16) continue;
          var tag = b64encode(raw.slice(9, 9 + SALT_LEN));
          if (salts.indexOf(tag) >= 0 || salts.length >= DISTINCT) continue;
          salts.push(tag); order.push(msgs[i].b);
        }
        if (!order.length) return true;
        var idx = 0;
        function attempt() {
          if (idx >= order.length) return false;
          var blob = order[idx++];
          return unseal(s, blob).then(function (m) {
            if (!m) return attempt();
            s.salt = b64decode(blob).slice(9, 9 + SALT_LEN);
            return true;
          });
        }
        return attempt();
      });
  }

  function joinRoom(room, password, label, quiet) {
    if (sessions.has(room)) { activate(room); return Promise.resolve(true); }
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(room)) {
      say("that is not a usable room name", "err");
      return Promise.resolve(false);
    }
    var s = newSession(room, label);
    return unlockSession(s, password).then(function (ok) {
      if (!ok) {
        s.logEl.remove(); s.tabEl.remove(); sessions.delete(room);
        say("that password does not open #" + room, "err");
        return false;
      }
      if (!quiet) activate(room);
      sysLine(s, "joined " + s.label);
      poll(s);
      announceAct(s, "joined"); beat(s);
      return true;
    });
  }

  function openDmRoom(peerPub, peerNick, quiet) {
    return pairRoom(peerPub).then(function (d) {
      var existing = sessions.get(d.room);
      if (existing) { if (!quiet) activate(d.room); return true; }
      var s = newSession(d.room, "@" + peerNick);
      s.isDm = true;
      s.peerPub = peerPub;
      s.fixedKey = Promise.resolve(d.key);
      s.password = "";          // marks it open; nothing derives from it
      if (!quiet) activate(d.room);
      sysLine(s, "joined " + s.label +
              " - keyed by your two identity keys, and no one else's");
      poll(s);
      return true;
    });
  }

  // ===========================================================================
  // Commands
  // ===========================================================================
  var COMMANDS = {};
  function defineCommand(names, help, fn) {
    names.forEach(function (n) { COMMANDS[n] = { fn: fn, help: help, name: names[0] }; });
  }
  function runCommand(input) {
    if (input.charAt(0) !== "/") return false;
    if (input.charAt(1) === "/") return false;      // "//" escapes
    var sp = input.indexOf(" ");
    var name = (sp < 0 ? input.slice(1) : input.slice(1, sp)).toLowerCase();
    var rest = sp < 0 ? "" : input.slice(sp + 1).trim();
    var cmd = COMMANDS[name];
    if (!cmd) { say("unknown command: /" + name + "  (try /help)", "err"); return true; }
    cmd.fn(rest);
    return true;
  }

  defineCommand(["help", "h"], "list commands", function () {
    var seen = {};
    say("commands:");
    Object.keys(COMMANDS).forEach(function (k) {
      var c = COMMANDS[k];
      if (seen[c.name]) return;
      seen[c.name] = 1;
      var aliases = Object.keys(COMMANDS).filter(function (a) {
        return COMMANDS[a].name === c.name;
      }).map(function (a) { return "/" + a; }).join(", ");
      say("  " + aliases + " — " + c.help);
    });
    say("  start a line with // to send a literal leading slash");
  });

  defineCommand(["join", "j"], "join a room: /join #room#password", function (rest) {
    var arg = rest.trim();
    if (!arg) { say("usage: /join #room#password   (or /join room password)"); return; }
    var room = null, pass = null;
    var m = arg.match(/^#?([A-Za-z0-9_-]{1,64})#(.*)$/);
    if (m) { room = m[1]; pass = m[2]; }
    else {
      var parts = arg.split(/\s+/);
      room = parts[0].replace(/^#/, "");
      pass = parts.slice(1).join(" ");
    }
    if (!pass) { say("a room needs a password: /join #" + room + "#<password>", "err"); return; }
    if (/^dm[0-9a-f]{32}$/.test(room)) {
      say("that is a private conversation - it has no password to join with; " +
          "use /dm <nick>", "err");
      return;
    }
    joinRoom(room, pass, "#" + room, false);
  });

  defineCommand(["close", "part"], "close the current tab", function () {
    if (sessions.size < 2) { say("that is the only room open", "err"); return; }
    var was = S.label;
    closeSession(S.room);
    say("closed " + was);
  });

  function resolvePeer(who) {
    if (!myPub || !myKeys) {
      say("your identity key is not ready \u2014 private messages are " +
          "unavailable in this browser (IndexedDB blocked?)", "err");
      return null;
    }
    if (who === myNick) { say("messaging yourself is not a feature", "err"); return null; }
    var pub = pubForNick(who);
    if (!pub) {
      say("no key seen for " + who + " \u2014 they must join this room once " +
          "first (/keys to list)", "err");
      return null;
    }
    return pub;
  }

  // Two kinds of private message, and the difference is what the room learns.
  //
  //   /msg  stays here.  Everyone sees that you messaged someone, and who, but
  //         only the two of you can read it.
  //   /dm   opens a separate room whose very name is derived from the pair, so
  //         this room learns nothing at all \u2014 not even that you talked.
  defineCommand(["msg"],
    "private message, stays in this room: /msg <nick> <text>", function (rest) {
      var arg = rest.trim(), sp = arg.indexOf(" ");
      var who = sp < 0 ? arg : arg.slice(0, sp);
      var body = sp < 0 ? "" : arg.slice(sp + 1).trim();
      if (!who || !body) {
        say("usage: /msg <nick> <text>   (/dm for a separate room)"); return;
      }
      var pub = resolvePeer(who);
      if (!pub) return;
      var s = S;
      s.stick = true; scrollEnd(s);
      dmSeal(pub, { t: body })
        .then(function (sealed) {
          return post(s, { k: "pm", n: myNick, to: who, sp: myPub, tp: pub,
                           iv: sealed.iv, ct: sealed.ct, ts: Date.now() });
        })
        .catch(function (err) {
          sysLine(s, "not sent: " + (err && err.message ? err.message : err), "err");
        });
    });

  defineCommand(["dm", "query"],
    "private room in its own tab: /dm <nick> [text]", function (rest) {
      var arg = rest.trim(), sp = arg.indexOf(" ");
      var who = sp < 0 ? arg : arg.slice(0, sp);
      var body = sp < 0 ? "" : arg.slice(sp + 1).trim();
      if (!who) { say("usage: /dm <nick> [text]"); return; }
      var pub = resolvePeer(who);
      if (!pub) return;
      openDmRoom(pub, who, false).then(function (ok) {
        if (ok && body) {
          var s = S;
          post(s, { n: myNick, t: body, ts: Date.now() })
            .catch(function (e) { sysLine(s, "not sent: " + e.message, "err"); });
        }
      });
    });

  defineCommand(["keys", "fp"], "list identity fingerprints", function () {
    say("you are " + myNick + " — key " + (myFp || "(not ready)"));
    var rows = [];
    identities.forEach(function (e, pub) {
      if (pub !== myPub) rows.push({ nick: e.nick, fp: e.fp, pub: pub });
    });
    var stale = pruneIdentities();
    if (stale) rows = rows.filter(function (r) { return identities.has(r.pub); });
    if (!rows.length) { say("no other identities seen in this room yet"); return; }
    say("identities seen here:");
    rows.sort(function (a, b) { return a.nick < b.nick ? -1 : 1; });
    rows.forEach(function (r) { say("  " + pad(r.nick, 18) + (r.fp || "(computing)")); });
    if (stale) say("(" + stale + " stale guest " +
                   (stale === 1 ? "identity" : "identities") + " expired)");
    say("compare these out of band before trusting a private room");
  });

  defineCommand(["rooms", "tabs"], "list open rooms", function () {
    var names = [];
    sessions.forEach(function (s) { names.push(s.label + (s === S ? " *" : "")); });
    say("open: " + names.join("   "));
  });

  defineCommand(["who"], "who is in this room", function () {
    var names = S.roster ? Object.keys(S.roster).sort() : [];
    if (!names.length) { say("nobody else has checked in yet"); return; }
    say("here now: " + names.join(", "));
  });

  defineCommand(["quiet"], "stop broadcasting your activity (toggle)", function () {
    broadcasting = !broadcasting;
    try { localStorage.setItem("attochat.quiet", broadcasting ? "0" : "1"); } catch (e) {}
    say(broadcasting
      ? "broadcasting again - others will see when you are here, typing or editing"
      : "quiet mode - you still see others, they no longer see you");
  });


  // ---- identity / nick -------------------------------------------------------
  // Control characters are filtered by code point rather than by a regex range,
  // so nothing in this file is itself a control character.
  function stripControl(str) {
    var out = "";
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c >= 32 && c !== 127) out += str.charAt(i);
    }
    return out;
  }
  function badFilename(name) {
    for (var i = 0; i < name.length; i++) {
      var c = name.charCodeAt(i);
      if (c < 32 || c === 127) return true;
      if (name.charAt(i) === "/" || name.charAt(i) === "\\") return true;
    }
    return false;
  }

  function sizeNick() { nick.style.width = Math.max(1, nick.value.length) + "ch"; }
  function saveNick() {
    var v = nick.value.trim().slice(0, 24);
    if (!v) v = "anon";
    nick.value = v; myNick = v;
    try { localStorage.setItem("attochat.nick", v); } catch (e) {}
    sizeNick();
    return v;
  }
  function loadNick() {
    var saved = null;
    try { saved = localStorage.getItem("attochat.nick"); } catch (e) {}
    if (!saved) saved = "guest-" + Math.floor(1000 + Math.random() * 9000);
    nick.value = saved;
    saveNick();
  }

  // Both /nick and the statusbar field come through here, so they cannot drift.
  function changeNick(want, spoken) {
    want = (want || "").trim();
    if (!want) {
      if (spoken) say("you are " + myNick);
      else { nick.value = myNick; sizeNick(); }
      return;
    }
    if (/\s/.test(want)) {
      say("a nick cannot contain spaces", "err");
      nick.value = myNick; sizeNick(); return;
    }
    want = stripControl(want).slice(0, 24);
    if (!want) {
      say("that is not a usable nick", "err");
      nick.value = myNick; sizeNick(); return;
    }
    if (want === myNick) {
      if (spoken) say("you are already " + myNick);
      nick.value = myNick; sizeNick(); return;
    }
    var old = myNick;
    nick.value = want; saveNick();
    say("you are now known as " + want);
    // Carry the public key so everyone rebinds the identity unambiguously
    // rather than guessing from the old name.  Announced in every open room.
    sessions.forEach(function (s) {
      if (s.password) {
        post(s, { n: old, t: want, ts: Date.now(), k: "nick", pub: myPub })
          .catch(function () {});
      }
    });
  }
  nick.addEventListener("input", sizeNick);
  nick.addEventListener("change", function () { changeNick(nick.value, false); });
  nick.addEventListener("blur",   function () { changeNick(nick.value, false); });
  nick.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    e.preventDefault(); changeNick(nick.value, false); text.focus();
  });
  defineCommand(["nick"], "change your nick: /nick <name>",
    function (rest) { changeNick(rest, true); });

  defineCommand(["me"], "send an action: /me <does something>", function (rest) {
    var action = rest.trim();
    if (!action) { say("usage: /me <does something>"); return; }
    S.stick = true; scrollEnd(S);
    post(S, { n: myNick, t: action, ts: Date.now(), k: "me" })
      .catch(function () { say("could not send that action", "err"); });
  });

  defineCommand(["clear", "cls"], "clear this room's local scrollback", function () {
    while (S.logEl.firstChild) S.logEl.removeChild(S.logEl.firstChild);
    S.history = []; S.docEls = {}; S.undec = 0;
    paintUndec();
    say("scrollback cleared - nothing was deleted; reload to restore it");
  });

  defineCommand(["fullload"], "load this room's complete history", function () {
    if (S.password === null) { say("unlock the room first"); return; }
    if (S.lastId === 0) { say("already showing everything this room has"); return; }
    while (S.logEl.firstChild) S.logEl.removeChild(S.logEl.firstChild);
    S.history = []; S.docEls = {}; S.undec = 0; S.truncated = false;
    S.lastId = 0;
    paintUndec();
    say("loading full history...");
    poll(S);
  });

  // ---- notes ------------------------------------------------------------------
  var edFile = null, edBase = "", edOpen = false, edSession = null;
  function markDirty() {
    edstat.textContent = edtext.value === edBase ? "saved" : "modified";
  }
  function openEditor(s, filename, content) {
    announceAct(s, "is editing " + filename);
    edSession = s; edFile = filename; edBase = content || "";
    edtext.value = edBase; edname.textContent = filename;
    edstat.textContent = "saved"; edOpen = true; editor.hidden = false;
    edtext.focus();
    edtext.setSelectionRange(edtext.value.length, edtext.value.length);
  }
  var discardArmed = false;
  function confirmDiscard() {
    if (discardArmed) { discardArmed = false; return true; }
    discardArmed = true;
    edstat.textContent = "unsaved - press esc again to discard";
    setTimeout(function () { discardArmed = false; markDirty(); }, 4000);
    return false;
  }
  function closeEditor(force) {
    if (!edOpen) return;
    if (!force && edtext.value !== edBase && !confirmDiscard()) return;
    edOpen = false; editor.hidden = true; edFile = null; edSession = null;
    text.focus();
  }
  function saveEditor() {
    if (!edOpen || !edFile || !edSession) return;
    var body = edtext.value, s = edSession;
    edsave.classList.add("busy"); edstat.textContent = "saving...";
    post(s, { n: myNick, t: body, ts: Date.now(), f: edFile,
              k: "md", mt: "text/markdown" })
      .then(function () {
        edsave.classList.remove("busy"); edBase = body; edstat.textContent = "saved";
        announceAct(s, "saved " + edFile);
      })
      .catch(function (err) {
        edsave.classList.remove("busy");
        edstat.textContent = "not saved: " + (err && err.message ? err.message : err);
      });
  }
  edtext.addEventListener("input", markDirty);
  edsave.addEventListener("click", function (e) { e.preventDefault(); saveEditor(); });
  edclose.addEventListener("click", function (e) { e.preventDefault(); closeEditor(false); });
  edtext.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
      e.preventDefault(); saveEditor(); return;
    }
    if (e.key === "Escape") { e.preventDefault(); closeEditor(false); }
  });

  function pickEntry(rest, verb) {
    var files = latestFiles(S), want = rest.trim();
    if (!want) { say("usage: /" + verb + " <number|name>   (/ls to list)"); return null; }
    if (!files.length) { say("no files in this room yet"); return null; }
    if (/^[0-9]+$/.test(want)) {
      var i = parseInt(want, 10) - 1;
      if (i < 0 || i >= files.length) {
        say("no file " + want + "; /ls shows 1.." + files.length, "err"); return null;
      }
      return files[i];
    }
    var hit = files.filter(function (f) { return f.name === want; })[0];
    if (!hit) { say("no file named " + want + "  (/ls to list)", "err"); return null; }
    return hit;
  }

  defineCommand(["edit", "ed"], "edit a note: /edit <number|name>", function (rest) {
    var e = pickEntry(rest, "edit");
    if (!e) return;
    if (e.rec.bytes) {
      say(e.name + " is a binary file, not text - /dl to fetch it", "err"); return;
    }
    openEditor(S, e.name, e.rec.t || "");
  });

  defineCommand(["new"], "create a note: /new <name.md>", function (rest) {
    var name = rest.trim();
    if (!name) { say("usage: /new <name.md>"); return; }
    if (badFilename(name)) {
      say("that name has characters a filename cannot carry", "err"); return;
    }
    var existing = latestFiles(S).filter(function (f) { return f.name === name; })[0];
    if (existing) {
      say(name + " already exists - opening it; save adds a revision");
      openEditor(S, name, existing.rec.t || ""); return;
    }
    openEditor(S, name, "");
  });

  // ---- files ------------------------------------------------------------------
  function pickFile(accept) { mdFile.accept = accept || ""; mdFile.value = ""; mdFile.click(); }
  defineCommand(["ul", "upload"], "upload any file into this room",
    function () { pickFile(""); });
  defineCommand(["ulmd", "uploadmd"], "upload, picker filtered to markdown",
    function () { pickFile(".md,.markdown,.txt,text/markdown,text/plain"); });

  mdFile.addEventListener("change", function () {
    var file = mdFile.files && mdFile.files[0];
    if (!file) return;
    var s = S;
    mdFile.value = "";                  // so the same file can be picked again
    // Checked before reading, not after sealing.  The old order read the whole
    // file, encrypted it and base64'd it before discovering it was too big,
    // which at this ceiling means three copies of a large buffer and, for a
    // genuinely huge pick, a dead tab instead of an error message.
    if (file.size > MAX_FILE) {
      sysLine(s, "too big: " + file.name + " is " + humanSize(file.size) +
              ", the limit is " + humanSize(MAX_FILE), "err");
      return;
    }
    sysLine(s, "reading " + file.name + " (" + humanSize(file.size) + ")...");
    announceAct(s, "is uploading " + file.name);
    file.arrayBuffer().then(function (buf) {
      var bytes = new Uint8Array(buf), asText = null;
      // Text or binary decided by content, not extension: valid UTF-8 with no
      // NUL prints into the scrollback, anything else is stored as bytes.
      try {
        var str = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (str.indexOf(String.fromCharCode(0)) < 0) asText = str;
      } catch (e) {}
      if (asText !== null) {
        return post(s, { n: myNick, t: asText, ts: Date.now(), f: file.name,
                         k: "md", mt: file.type || "text/plain" });
      }
      return postBytes(s, { n: myNick, ts: Date.now(), f: file.name,
                            mt: file.type || "application/octet-stream" }, bytes);
    }).then(function () { sysLine(s, "uploaded " + file.name); })
      .catch(function (err) {
        sysLine(s, "upload failed: " + (err && err.message ? err.message : err), "err");
      });
  });

  defineCommand(["ls", "files"], "list files in this room", function () {
    var files = latestFiles(S);
    if (!files.length) { say("no files in this room yet"); return; }
    say("files in " + S.label + ":");
    files.forEach(function (f, i) {
      var m = f.rec, n = String(i + 1);
      var w = new Date(m.ts || Date.now());
      var hh = ("0" + w.getHours()).slice(-2) + ":" + ("0" + w.getMinutes()).slice(-2);
      say("  " + (n.length < 2 ? " " + n : n) + "  " + pad(f.name, 28) +
          pad(humanSize(fileBytes(m).length), 10) + "  " + pad(m.n || "anon", 12) +
          pad(hh, 7) + (f.revs > 1 ? "rev " + f.revs : ""));
    });
    say("/dl <number|name> to download - /edit <number|name> to edit");
  });

  function saveFile(filename, content, mime) {
    var blob = new Blob([content], { type: mime || "text/markdown;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
  }

  defineCommand(["dl", "download"], "download a file: /dl <number|name>",
    function (rest) {
      var e = pickEntry(rest, "dl");
      if (!e) return;
      saveFile(e.name, fileBytes(e.rec), e.rec.mt || "application/octet-stream");
      say("downloaded " + e.name + " (" + humanSize(fileBytes(e.rec).length) + ")");
      announceAct(S, "downloaded " + e.name);
    });

  defineCommand(["dlmd", "downloadmd"], "download this room as markdown", function () {
    var out = ["# " + S.label, "", "_exported " + new Date().toISOString() + "_", ""];
    var count = 0;
    var current = latestFiles(S).map(function (f) { return f.rec; });
    S.history.forEach(function (m) {
      if (m.f && current.indexOf(m) < 0) return;    // superseded revision
      if (m.k === "key") return;                     // plumbing
      if (m.k === "pm") {
        count++;
        out.push("_(private message " + (m.n || "?") + " to " + (m.to || "?") +
                 ", not exported)_", "");
        return;
      }
      count++;
      if (m.k === "me") {
        out.push("_* " + (m.n || "anon") + " " + m.t + "_", "");
      } else if (m.k === "nick") {
        out.push("_" + (m.n || "anon") + " is now known as " + m.t + "_", "");
      } else if (m.f && m.bytes) {
        out.push("## " + m.f, "",
                 "_(binary, " + humanSize(m.bytes.length) + " - /dl " + m.f + ")_", "");
      } else if (m.f) {
        out.push("## " + m.f, "", m.t, "");
      } else {
        out.push("**" + (m.n || "anon") + "** - " +
                 new Date(m.ts || Date.now()).toISOString(), "", m.t, "");
      }
    });
    if (!count) { say("nothing to export yet"); return; }
    var name = S.room + "-" + new Date().toISOString().slice(0, 10) + ".md";
    saveFile(name, out.join("\n"));
    say("exported " + count + " message(s) to " + name);
  });

  // ---- the bell ----------------------------------------------------------------
  // Synthesised rather than played from a file.  An <audio> element would need
  // a media-src the CSP does not grant, and an asset the server would have to
  // carry and version; two oscillators need neither, and cost nothing when the
  // bell is off because the context is not created until it is switched on.
  var audioCtx = null, bellWanted = false;
  try { bellWanted = localStorage.getItem("attochat.bell") === "1"; } catch (e) {}

  function audioSupported() {
    return !!(window.AudioContext || window.webkitAudioContext);
  }
  function ensureAudio() {
    if (!audioSupported()) return null;
    if (!audioCtx) {
      try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); }
      catch (e) { return null; }
    }
    // Browsers start a context suspended until a gesture; the toggle is one.
    if (audioCtx.state === "suspended" && audioCtx.resume) {
      var p = audioCtx.resume();
      if (p && p.then) p.then(paintBell, function () {});
    }
    return audioCtx;
  }
  function ring() {
    if (!bellWanted) return;
    var ctx = ensureAudio();
    if (!ctx || ctx.state !== "running") return;
    var now = ctx.currentTime;
    // Two short notes, the second higher: distinct from a system sound and
    // short enough not to grate when a room is busy.
    [[880, 0], [1318.5, 0.07]].forEach(function (note) {
      var osc = ctx.createOscillator(), gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = note[0];
      var t = now + note[1];
      // Ramped at both ends: a square-edged gate on a sine is an audible click.
      gain.gain.setValueAtTime(0.0001, t);
      gain.gain.exponentialRampToValueAtTime(0.12, t + 0.008);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.07);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.08);
    });
  }
  // A context created without a user gesture starts suspended and stays that
  // way, so a bell remembered as "on" from a previous visit would be silent
  // until the page happened to be clicked -- switched on by every appearance,
  // and mute.  Take the first gesture of any kind, whatever it was for.
  function armAudio() {
    document.removeEventListener("pointerdown", armAudio);
    document.removeEventListener("keydown", armAudio);
    if (bellWanted) ensureAudio();
  }
  document.addEventListener("pointerdown", armAudio, { passive: true });
  document.addEventListener("keydown", armAudio, { passive: true });

  function paintBell() {
    if (!audioSupported()) {
      sbBell.textContent = "[bell:n/a]";
      sbBell.title = "this browser has no Web Audio";
      return;
    }
    if (bellWanted && audioCtx && audioCtx.state !== "running") {
      // Honest rather than reassuring: it is on and it is not going to sound.
      sbBell.textContent = "[bell:on*]";
      sbBell.title = "on, but this browser wants a click on the page before it"
        + " will play anything";
      return;
    }
    sbBell.textContent = bellWanted ? "[bell:on]" : "[bell:off]";
    sbBell.title = bellWanted
      ? "a short tone when someone else says something"
      : "silent";
  }
  sbBell.addEventListener("click", function (e) {
    e.preventDefault();
    bellWanted = !bellWanted;
    try { localStorage.setItem("attochat.bell", bellWanted ? "1" : "0"); } catch (e2) {}
    paintBell();
    // The click is the gesture that lets the context start, so take it, and
    // ring once so "on" is audibly different from "off".
    if (bellWanted) { ensureAudio(); ring(); }
  });
  paintBell();

  // ---- notifications -----------------------------------------------------------
  var swReg = null, notifyWanted = false;
  try { notifyWanted = localStorage.getItem("attochat.notify") === "1"; } catch (e) {}

  function notifySupported() { return typeof Notification !== "undefined"; }
  function notifyOn() {
    return notifyWanted && notifySupported() && Notification.permission === "granted";
  }
  // "Not looking" is broader than document.hidden, which only covers the tab
  // being backgrounded within the browser.
  function away() {
    return document.hidden || (document.hasFocus && !document.hasFocus());
  }
  function paintNotify() {
    if (!notifySupported()) {
      sbNotify.textContent = "[notify:n/a]";
      sbNotify.title = "this browser will not raise notifications from a tab" +
        " (on iOS, add the page to your Home Screen first)";
      return;
    }
    if (Notification.permission === "denied") {
      sbNotify.textContent = "[notify:blocked]";
      sbNotify.title = "notifications are blocked for this site";
      return;
    }
    sbNotify.textContent = notifyOn() ? "[notify:on]" : "[notify:off]";
  }
  function ensureWorker() {
    if (swReg || !("serviceWorker" in navigator)) return Promise.resolve(null);
    return navigator.serviceWorker.register("/sw.js")
      .then(function (r) {
        return navigator.serviceWorker.ready.then(function () { swReg = r; return r; });
      })
      .catch(function () { return null; });
  }
  function show(title, body) {
    var opts = { body: body, tag: "attochat", renotify: true,
                 data: { url: location.origin + "/" + firstRoom } };
    if (swReg && swReg.showNotification) { swReg.showNotification(title, opts); return; }
    try {
      var n = new Notification(title, opts);
      n.onclick = function () { window.focus(); n.close(); };
    } catch (e) { /* Android only raises via a service worker */ }
  }
  function notify(s, msgs) {
    if (!msgs.length || !notifyOn()) return;
    var last = msgs[msgs.length - 1];
    show(s.label, msgs.length === 1
      ? "<" + last.n + "> " + last.t
      : msgs.length + " new messages - <" + last.n + "> " + last.t);
  }
  function clearNotifications() {
    if (!swReg || !swReg.getNotifications) return;
    swReg.getNotifications({ tag: "attochat" })
      .then(function (l) { l.forEach(function (n) { n.close(); }); })
      .catch(function () {});
  }
  sbNotify.addEventListener("click", function (e) {
    e.preventDefault();
    if (!notifySupported()) { say("notifications are not available here"); return; }
    if (Notification.permission === "denied") {
      say("notifications are blocked for this site; re-enable in browser settings");
      return;
    }
    if (notifyOn()) {
      notifyWanted = false;
      try { localStorage.setItem("attochat.notify", "0"); } catch (e2) {}
      paintNotify(); say("notifications off"); startPolling(); return;
    }
    Notification.requestPermission().then(function (perm) {
      if (perm !== "granted") { paintNotify(); say("notifications not granted"); return; }
      notifyWanted = true;
      try { localStorage.setItem("attochat.notify", "1"); } catch (e2) {}
      ensureWorker().then(function () {
        paintNotify();
        say("notifications on - alerts when this window is not in front");
        show(S.label, "notifications are on");
      });
    });
  });

  // ---- statusbar clock, share link ---------------------------------------------
  function startClock() {
    function tick() { sbClock.textContent = fmtTime(Date.now()); }
    tick(); setInterval(tick, 15000);
  }
  sbLink.addEventListener("click", function (e) {
    e.preventDefault();
    if (!S || S.password === null) return;
    if (S.isDm) {
      // There is no password to put in a link, and inventing one would be the
      // whole two-person property handed away in a clipboard.
      say("a private conversation has no shareable link - it is keyed by your " +
          "two identity keys, so there is nothing to share", "err");
      return;
    }
    var url = location.origin + "/" + encodeURIComponent(S.room) +
              "#" + encodeURIComponent(S.password);
    function fallback() { say("share link: " + url); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url)
        .then(function () { say("share link copied to clipboard"); })
        .catch(fallback);
    } else { fallback(); }
  });

  // ---- composer ----------------------------------------------------------------
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!S || S.password === null) return;
    saveNick();
    var body = text.value.trim();
    if (!body) return;
    if (runCommand(body)) { text.value = ""; repin(); return; }
    if (body.slice(0, 2) === "//") body = body.slice(1);
    text.value = "";
    var s = S;
    s.stick = true; scrollEnd(s);
    text.focus();
    post(s, { n: myNick, t: body, ts: Date.now() })
      .catch(function () { if (!text.value) text.value = body; });
  });

  // ---- unlock ------------------------------------------------------------------
  var unlocking = false;
  function passwordFromUrl() {
    var h = location.hash;
    if (!h || h.length < 2) return null;
    var raw = h.slice(1);
    try { return decodeURIComponent(raw); } catch (e) { return raw; }
  }
  window.addEventListener("hashchange", function () { location.reload(); });

  gateForm.addEventListener("submit", function (e) {
    e.preventDefault();
    if (unlocking) return;
    var pw = gatePass.value;
    if (!pw) return;
    gateErr.textContent = "";
    unlocking = true;
    gateBtn.classList.add("busy");
    gateBtn.textContent = "working";

    var s = newSession(firstRoom, "#" + firstRoom);
    unlockSession(s, pw).then(function (ok) {
      unlocking = false;
      gateBtn.classList.remove("busy");
      gateBtn.textContent = "connect";
      if (!ok) {
        s.logEl.remove(); s.tabEl.remove(); sessions.delete(firstRoom);
        gateErr.textContent = "That password does not open this room.";
        gatePass.select();
        return;
      }
      gatePass.value = "";
      // The fragment did its job; leaving it in the address bar keeps the
      // password on screen for the whole session.  replaceState fires no
      // hashchange, so the reload handler above does not loop.
      if (location.hash && window.history && history.replaceState)
        history.replaceState(null, "", location.pathname + location.search);
      gate.hidden = true;
      activate(firstRoom);
      loadNick();
      sysLine(s, "attochat - aes-256-gcm, decrypted locally");
      sysLine(s, "joined #" + firstRoom);
      paintNotify();
      loadIdentity()
        .then(function () { if (notifyOn()) return ensureWorker(); })
        .catch(function () {
          say("could not set up an identity key; /msg will be unavailable", "err");
        });
      startClock();
      startPolling();
      announceAct(s, "joined"); beat(s);
      text.focus();
    }).catch(function () {
      unlocking = false;
      gateBtn.classList.remove("busy");
      gateBtn.textContent = "connect";
      gateErr.textContent = "Could not reach the server.";
    });
  });

  // ---- start -------------------------------------------------------------------
  var urlPassword = passwordFromUrl();
  if (urlPassword !== null) {
    gatePass.value = urlPassword;
    if (gateForm.requestSubmit) gateForm.requestSubmit();
    else gateForm.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
  } else {
    gatePass.focus();
  }
})();
)JS";

// The cap exists twice -- once for the server to enforce, once for the client
// to check before it spends time encrypting -- and nothing but this ties them
// together.  Drift would show up as an upload that succeeds locally and is
// rejected on arrival, so let the build fail instead.
static_assert(MAX_BLOB_LEN == 28u * 1024u * 1024u &&
                  std::string_view(CHAT_JS, sizeof(CHAT_JS) - 1).find("var MAX_BLOB = 28 * 1024 * 1024;") !=
                      std::string_view::npos,
              "MAX_BLOB in CHAT_JS must match MAX_BLOB_LEN");

// A service worker exists here for exactly one reason: Chrome on Android
// refuses `new Notification(...)` from a page and will only raise one through
// ServiceWorkerRegistration.showNotification.  It caches nothing, intercepts no
// fetches and receives no push — it is the smallest thing that makes
// notifications work on Android, and the hook a real Web Push implementation
// would later attach to.
const char CHAT_SW[] = R"SW(
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });

// Focus an existing tab for this room rather than opening a second one.
self.addEventListener("notificationclick", function (e) {
  e.notification.close();
  var url = (e.notification.data && e.notification.data.url) || "/";
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true })
      .then(function (list) {
        for (var i = 0; i < list.length; i++) {
          if (list[i].url.indexOf(url) >= 0 && "focus" in list[i])
            return list[i].focus();
        }
        if (self.clients.openWindow) return self.clients.openWindow(url);
      }));
});
)SW";

// Shared <head>.  %s is the page title.
// A terminal prompt: the app's own composer line as an icon.  Cyan chevron and
// green block, the exact --accent (#6fb3d2) and nick-green (#5fd75f) from the
// stylesheet, so the tab matches the room.  SVG so it stays crisp at any size;
// no script inside it, so the strict CSP (img-src 'self') is happy to load it.
const char FAVICON_SVG[] =
    R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32"><rect x="1" y="1" width="30" height="30" rx="7" fill="#0c0c0c" stroke="#2a2a2a" stroke-width="1.5"/><path d="M8.5 8 L17 16 L8.5 24" fill="none" stroke="#6fb3d2" stroke-width="3.6" stroke-linecap="round" stroke-linejoin="round"/><rect x="19.5" y="9.5" width="7" height="13" rx="1.3" fill="#5fd75f"/></svg>)SVG";

const char PAGE_HEAD[] = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<meta name="theme-color" content="#161b22">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="same-origin">
<title>)HTML";

const char PAGE_HEAD2[] = R"HTML(</title>
<link rel="stylesheet" href="/chat.css?v=)HTML";

const char PAGE_HEAD3[] = R"HTML(">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
</head>
)HTML";

const char PAGE_TAIL[] = R"HTML(
<script src="/chat.js?v=)HTML";

const char PAGE_TAIL2[] = R"HTML("></script>
</body>
</html>
)HTML";

// FNV-1a, only ever used to fingerprint the static assets.
std::string asset_version(const char *data, size_t len) {
  std::uint64_t h = 1469598103934665603ull;
  for (size_t i = 0; i < len; ++i) {
    h ^= (unsigned char)data[i];
    h *= 1099511628211ull;
  }
  std::ostringstream oss;
  oss << std::hex << std::setw(16) << std::setfill('0') << h;
  return oss.str().substr(0, 12);
}

std::string page_open(const std::string &title) {
  return PAGE_HEAD + html_escape(title) + PAGE_HEAD2 + g_cssVer + PAGE_HEAD3;
}
std::string page_close() {
  return std::string(PAGE_TAIL) + g_jsVer + PAGE_TAIL2;
}

// Landing page: rooms are unlisted, so this only takes a name.  It deliberately
// cannot tell you whether the channel you type already exists.
std::string landing_html() {
  return page_open("attochat") +
      "<body data-page=\"landing\">\n"
      "<div class=\"lobby-wrap\"><div class=\"lobby\">\n"
      "<pre class=\"banner\"><b>attochat</b> \xE2\x80\x94 end-to-end encrypted channels\n"
      "channels are unlisted.\n"
      "</pre>\n"
      "<form id=\"roomForm\" autocomplete=\"off\">\n"
      "  <div class=\"field\">\n"
      "    <label for=\"roomName\">/join #</label>\n"
      "    <input id=\"roomName\" type=\"text\" maxlength=\"64\" autocapitalize=\"none\"\n"
      "           spellcheck=\"false\" autocomplete=\"off\" autofocus>\n"
      "  </div>\n"
      "  <p id=\"roomError\"></p>\n"
      "</form>\n"
      "<p class=\"hint\">a-z A-Z 0-9 - _   (max 64)\n"
      "\n"
      "the server stores ciphertext only.\n"
      "it never sees your password, nick or messages.</p>\n"
      "<noscript><p class=\"hint\">encryption happens in the browser, so this\n"
      "needs javascript.</p></noscript>\n"
      "</div></div>\n" +
      page_close();
}

// Channel page.  No transcript is rendered here — the server cannot read one.
std::string room_html(const std::string &room) {
  std::string esc = html_escape(room);
  return page_open(room + " \xC2\xB7 attochat") +
      "<body data-page=\"room\" data-room=\"" + esc + "\">\n"
      "<div id=\"gate\" class=\"gate\"><div class=\"gate-card\">\n"
      "<form id=\"gateForm\" autocomplete=\"off\">\n"
      "<pre class=\"banner\"><b>#" + esc + "</b>\n"
      "end-to-end encrypted \xE2\x80\x94 aes-256-gcm, pbkdf2-sha256\n"
      "nothing readable is ever sent to the server.\n"
      "</pre>\n"
      "  <div class=\"field\">\n"
      "    <label for=\"gatePass\">password:</label>\n"
      "    <input id=\"gatePass\" type=\"password\" maxlength=\"256\"\n"
      "           autocomplete=\"current-password\">\n"
      "  </div>\n"
      "  <button id=\"gateBtn\" type=\"submit\">connect</button>\n"
      "  <p id=\"gateError\" role=\"alert\"></p>\n"
      "</form>\n"
      "<p class=\"hint\">if the channel is new, the password you\n"
      "type here becomes its password.</p>\n"
      "</div></div>\n"
      "<form id=\"composer\" class=\"composer-form\" autocomplete=\"off\">\n"
      "<div id=\"tabs\" class=\"tabs\"></div>\n"
      "<main id=\"logs\" class=\"logs\"></main>\n"
      "<div id=\"typing\" class=\"typing\" hidden></div>\n"
      "<div class=\"statusbar\">\n"
      "  <span id=\"sbClock\" class=\"sb\">--:--</span>\n"
      "  <span id=\"dot\" class=\"dot\" title=\"connecting\">!</span>\n"
      "  <label class=\"sr-only\" for=\"nick\">your nick</label>\n"
      "  <span class=\"grp\"><span class=\"sb-dim\">[</span>"
      "<input id=\"nick\" type=\"text\" maxlength=\"24\" autocapitalize=\"none\""
      " spellcheck=\"false\" autocomplete=\"nickname\">"
      "<span class=\"sb-dim\">]</span></span>\n"
      "  <span class=\"grp\"><span class=\"sb-dim\">[</span>"
      "<span id=\"sbRoom\" class=\"sb\">#" + esc + "</span>"
      "<span class=\"sb-dim\">]</span></span>\n"
      "  <span id=\"undec\" hidden></span>\n"
      "  <span id=\"sbHere\" class=\"sb-dim\"></span>\n"
      "  <span class=\"spacer\"></span>\n"
      "  <button id=\"sbBell\" type=\"button\">[bell]</button>\n"
      "  <button id=\"sbNotify\" type=\"button\">[notify]</button>\n"
      "  <button id=\"sbLink\" type=\"button\"\n"
      "          title=\"copy a link with the password in the URL fragment\">"
      "[link]</button>\n"
      "</div>\n"
      "<input type=\"hidden\" name=\"_csrf\" value=\"" + html_escape(g_csrfToken) + "\">\n"
      "<div class=\"composer\">\n"
      "  <span class=\"prompt\">&gt;</span>\n"
      "  <label class=\"sr-only\" for=\"text\">message</label>\n"
      "  <input id=\"text\" type=\"text\" maxlength=\"2000\" autocomplete=\"off\"\n"
      "         autocapitalize=\"sentences\" enterkeyhint=\"send\">\n"
      "  <button id=\"send\" type=\"submit\">send</button>\n"
      "  <input id=\"mdFile\" type=\"file\"\n"
      "         accept=\".md,.markdown,.txt,text/markdown,text/plain\" hidden>\n"
      "</div>\n"
      "</form>\n"
      "<div id=\"editor\" class=\"editor\" hidden>\n"
      "  <div class=\"ed-head\">\n"
      "    <span id=\"edname\"></span>\n"
      "    <span class=\"spacer\"></span>\n"
      "    <span id=\"edstat\"></span>\n"
      "  </div>\n"
      "  <label class=\"sr-only\" for=\"edtext\">note contents</label>\n"
      "  <textarea id=\"edtext\" spellcheck=\"false\" autocapitalize=\"none\"></textarea>\n"
      "  <div class=\"ed-foot\">\n"
      "    <span class=\"ed-hint\">cmd/ctrl-s save \u00b7 esc close</span>\n"
      "    <span class=\"spacer\"></span>\n"
      "    <button id=\"edsave\" type=\"button\">save</button>\n"
      "    <button id=\"edclose\" type=\"button\">close</button>\n"
      "  </div>\n"
      "</div>\n"
      "<noscript><p class=\"hint\">encryption happens in the browser, so this\n"
      "needs javascript.</p></noscript>\n" +
      page_close();
}

// -----------------------------------------------------------------------------
// [Claude] Routing
// -----------------------------------------------------------------------------
// Splits "/api/r/<room>/<action>".  Returns false if the shape does not match.
bool parse_api_path(const std::string &path, std::string &room,
                    std::string &action) {
  static const std::string prefix = "/api/r/";
  if (path.compare(0, prefix.size(), prefix) != 0) return false;
  auto rest = path.substr(prefix.size());
  auto slash = rest.find('/');
  if (slash == std::string::npos) return false;
  room   = rest.substr(0, slash);
  action = rest.substr(slash + 1);
  return !room.empty() && !action.empty();
}

int handle_send(FILE *sock, const std::string &room, const std::string &body) {
  if (!ct_eq(form_get(body, "_csrf"), g_csrfToken))
    return send_error(sock, 403, "Forbidden", "Bad or missing CSRF token.");

  // The blob is opaque; all the server can check is that it is base64 and sane.
  std::string blob = form_get(body, "b");
  if (!blob_valid(blob))
    return send_error(sock, 400, "Bad Request", "Malformed message.");

  std::uint64_t id = 0;
  switch (room_append(room, blob, id)) {
    case AppendResult::TooManyRooms:
      return send_error(sock, 507, "Insufficient Storage", "Too many rooms.");
    case AppendResult::Full:
      return send_error(sock, 507, "Insufficient Storage", "This room is full.");
    case AppendResult::Ok:
      break;
  }
  log_line(CLR_CHAT "[CHAT] " + room + " #" + std::to_string(id) + " (" +
           std::to_string(blob.size()) + " B sealed)" CLR_RESET);
  return send_response(sock, 200, "OK", "application/json; charset=utf-8",
                       "{\"ok\":true,\"id\":" + std::to_string(id) + "}");
}

int handle_presence(FILE *sock, const std::string &room, const std::string &body) {
  if (!ct_eq(form_get(body, "_csrf"), g_csrfToken))
    return send_error(sock, 403, "Forbidden", "Bad or missing CSRF token.");
  std::string blob = form_get(body, "b");
  if (blob.empty() || blob.size() > MAX_PRESENCE_BLOB || !blob_valid(blob))
    return send_error(sock, 400, "Bad Request", "Malformed presence.");
  // No room-creation or size accounting: presence never reaches the disk, so it
  // cannot fill it, and a room that exists only in presence is not a room.
  std::uint64_t id = presence_add(room, blob);
  return send_response(sock, 200, "OK", "application/json; charset=utf-8",
                       "{\"ok\":true,\"id\":" + std::to_string(id) + "}");
}

int http_proto(FILE *sock, const std::string &request) {
  std::string method, target, protocol;
  if (!(std::istringstream(request) >> method >> target >> protocol))
    return send_error(sock, 400, "Bad Request", "Could not parse request line.");

  std::transform(method.begin(), method.end(), method.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (target.empty() || target[0] != '/')
    return send_error(sock, 400, "Bad Request", "Malformed request target.");

  std::string query;
  auto q = target.find('?');
  if (q != std::string::npos) {
    query  = target.substr(q + 1);
    target = target.substr(0, q);
  }
  std::string path = pct_decode(target, /*plusIsSpace=*/false);
  if (path.find('\0') != std::string::npos)
    return send_error(sock, 400, "Bad Request", "Illegal request target.");

  // Host validation — blocks DNS rebinding, where a browser is steered at this
  // server's address while carrying an attacker's origin (and thus its script).
  {
    auto hdrEnd = request.find("\r\n\r\n");
    std::string hdrs = request.substr(
        0, hdrEnd == std::string::npos ? request.size() : hdrEnd);
    std::string lower = hdrs;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    auto hp = lower.find("\r\nhost:");
    if (hp != std::string::npos) {
      hp += 7;
      auto he = lower.find("\r\n", hp);
      std::string host =
          lower.substr(hp, he == std::string::npos ? std::string::npos : he - hp);
      auto s = host.find_first_not_of(" \t");
      auto e = host.find_last_not_of(" \t");
      host = (s == std::string::npos) ? "" : host.substr(s, e - s + 1);
      // Only a name or a bracketed literal can carry a ":port" suffix.  A bare
      // IPv6 address is nothing but colons and digits, so this used to rewrite
      // "::1" to ":" and the "::1" arm of the allow-list below could never be
      // reached -- it read as permitted while being refused.
      const bool bracketed = !host.empty() && host.front() == '[';
      const bool bareV6 = !bracketed && host.find(':') != host.rfind(':');
      auto cp = host.rfind(':');
      if (cp != std::string::npos && !bareV6) {
        bool allDigits = cp + 1 < host.size();
        for (size_t j = cp + 1; j < host.size(); ++j)
          if (!std::isdigit((unsigned char)host[j])) { allDigits = false; break; }
        if (allDigits) host = host.substr(0, cp);
      }
      bool active = (g_bindAddress != "0.0.0.0") || !g_allowedHost.empty();
      if (active && !host.empty() && host != "localhost" && host != "127.0.0.1" &&
          host != "[::1]" && host != "::1" &&
          (g_allowedHost.empty() || host != g_allowedHost) &&
          host != g_bindAddress)
        return send_error(sock, 421, "Misdirected Request",
                          "Host header does not match this server.");
    }
  }

  const bool isGet  = (method == "get" || method == "head");
  const bool isPost = (method == "post");
  if (!isGet && !isPost)
    return send_error(sock, 405, "Method Not Allowed");

  std::string apiRoom, apiAction;
  const bool isApi = parse_api_path(path, apiRoom, apiAction);

  if (isPost) {
    if (!isApi || !room_name_valid(apiRoom))
      return send_error(sock, 404, "Not Found");
    auto bodyStart = request.find("\r\n\r\n");
    std::string body =
        (bodyStart == std::string::npos) ? "" : request.substr(bodyStart + 4);
    if (apiAction == "send")     return handle_send(sock, apiRoom, body);
    if (apiAction == "presence") return handle_presence(sock, apiRoom, body);
    return send_error(sock, 404, "Not Found");
  }

  if (isApi) {
    if (!room_name_valid(apiRoom)) return send_error(sock, 404, "Not Found");
    if (apiAction != "messages" && apiAction != "presence")
      return send_error(sock, 404, "Not Found");
    std::uint64_t since = 0;
    std::string sinceStr = query_get(query, "since");
    if (!sinceStr.empty()) {
      auto [ptr, ec] = std::from_chars(
          sinceStr.data(), sinceStr.data() + sinceStr.size(), since);
      (void)ptr;
      if (ec != std::errc{}) since = 0;
    }
    std::size_t tail = 0;
    std::string tailStr = query_get(query, "tail");
    if (!tailStr.empty()) {
      unsigned long v = 0;
      auto [tp, tec] = std::from_chars(
          tailStr.data(), tailStr.data() + tailStr.size(), v);
      (void)tp;
      if (tec == std::errc{}) tail = (std::size_t)std::min(v, 5000ul);
    }
    return send_response(sock, 200, "OK", "application/json; charset=utf-8",
                         apiAction == "presence" ? presence_json(apiRoom, since)
                                                 : room_json(apiRoom, since, tail));
  }

  if (path == "/")
    return send_response(sock, 200, "OK", "text/html; charset=utf-8",
                         landing_html());

  if (path == "/chat.css")
    return send_response(sock, 200, "OK", "text/css; charset=utf-8",
                         CHAT_CSS, /*noCache=*/false);

  if (path == "/chat.js")
    return send_response(sock, 200, "OK", "text/javascript; charset=utf-8",
                         g_servedJs, /*noCache=*/false);

  // Served from the root so its scope covers every room.  Not cached: a stale
  // worker is far harder to displace than a stale stylesheet.
  if (path == "/favicon.svg")
    return send_response(sock, 200, "OK", "image/svg+xml",
                         FAVICON_SVG, /*noCache=*/false);

  if (path == "/sw.js")
    return send_response(sock, 200, "OK", "text/javascript; charset=utf-8",
                         CHAT_SW, /*noCache=*/true);

  if (path == "/healthz")
    return send_response(sock, 200, "OK", "text/plain; charset=utf-8", "ok\n");

  // Anything else is a room name.  An unknown room and an empty room render
  // identically, so this reveals nothing about which rooms exist.
  std::string room = path.substr(1);
  if (room_name_valid(room))
    return send_response(sock, 200, "OK", "text/html; charset=utf-8",
                         room_html(room));

  return send_error(sock, 404, "Not Found");
}

// -----------------------------------------------------------------------------
// [Claude] Connection handling.  The outer shape is plotfi's HttpProto — read
// the request, wrap the fd in a FILE*, hand off to http_proto — but the body is
// rewritten: TLS, the wall-clock deadline, the header and body caps.
// One worker thread owns a connection end to end.
// -----------------------------------------------------------------------------
struct ClientConn { int fd; std::string ip; };

constexpr size_t MAX_HEADER_SIZE = 64u * 1024u;
// Must clear MAX_BLOB_LEN plus percent-encoding expansion and the other form
// fields.  '+' and '/' are 2 of base64's 64 symbols and each becomes three
// bytes, so a 28 MB blob arrives as roughly 29.8 MB; 32 MB leaves headroom.
constexpr size_t MAX_BODY_SIZE   = 32u * 1024u * 1024u;
// The runtime g_maxBodySize / g_maxResponseBytes default to these and are
// derived from the blob cap when max_blob_mb is set; the invariant that a body
// clears a blob and a response fits one holds at every setting.
static_assert(MAX_BODY_SIZE >= MAX_BLOB_LEN && MAX_RESPONSE_BYTES >= MAX_BLOB_LEN,
              "a body must clear a blob and a response must fit one");
constexpr auto   REQUEST_DEADLINE = std::chrono::seconds(30);

void handle_connection(int socket, const std::string &clientIP) {
  (void)clientIP;

#ifdef HAVE_OPENSSL
  SSL *ssl = nullptr;
  if (g_sslCtx) {
    ssl = SSL_new(g_sslCtx);
    if (!ssl) { close(socket); return; }
    SSL_set_fd(ssl, socket);
    if (SSL_accept(ssl) <= 0) {
      SSL_free(ssl);
      close(socket);
      return;
    }
  }
  // Owns the SSL object until it is handed to the FILE*, covering every
  // early return between the handshake and that transfer.
  struct ScopedSSL {
    SSL *ssl;
    int  fd;
    ~ScopedSSL() {
      if (ssl) {
        SSL_shutdown(ssl);
        BIO_set_close(SSL_get_rbio(ssl), BIO_NOCLOSE);
        SSL_free(ssl);
        close(fd);
      }
    }
  } sslGuard{ssl, socket};
#endif

  auto sock_read = [&](char *buf, int len) -> int {
#ifdef HAVE_OPENSSL
    if (ssl) return SSL_read(ssl, buf, len);
#endif
    return (int)read(socket, buf, len);
  };

  // Read headers.  The per-socket SO_RCVTIMEO only fires when a single read
  // stalls; the wall-clock deadline is what stops a slow-drip client from
  // pinning a worker thread indefinitely.
  std::string request;
  bool failed = false;
  auto deadline = std::chrono::steady_clock::now() + REQUEST_DEADLINE;
  for (char buffer[BUFFERLEN];;) {
    int n = sock_read(buffer, BUFFERLEN);
    if (n > 0) request.append(buffer, n);
    else { failed = true; break; }
    if (request.find("\r\n\r\n") != std::string::npos) break;
    if (request.size() > MAX_HEADER_SIZE) { failed = true; break; }
    if (std::chrono::steady_clock::now() >= deadline) { failed = true; break; }
  }
  if (failed) {
#ifdef HAVE_OPENSSL
    if (ssl) return;  // ScopedSSL shuts down TLS and closes the fd
#endif
    close(socket);
    return;
  }

  // Read the body, if the headers announced one.
  auto headerEnd = request.find("\r\n\r\n");
  bool bodyTooLarge = false;
  {
    std::string lower = request.substr(0, headerEnd);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    auto cl = lower.find("content-length:");
    if (cl != std::string::npos) {
      size_t want = 0;
      const char *p = lower.c_str() + cl + 15;
      const char *end = lower.c_str() + lower.size();
      while (p < end && (*p == ' ' || *p == '\t')) ++p;
      unsigned long long v = 0;
      auto [ptr, ec] = std::from_chars(p, end, v);
      if (ec == std::errc{} && ptr > p) want = (size_t)v;
      // Say so rather than quietly reading the first MAX_BODY_SIZE bytes.
      // Clamping left the rest of the body unread in the socket, so the reply
      // raced the client's remaining writes and it saw a connection reset
      // instead of an error -- survivable when bodies were 8 MB and a stray
      // one meant a bug, misleading now that a legitimate upload is 30.
      //
      // Answering alone is not enough: a client mid-upload is blocked writing
      // and never gets to read, so the close still reaches it as a reset.  The
      // overage has to be drained first, which is only worth doing for a
      // plausible one -- past DRAIN_LIMIT, hanging up is the right answer.
      if (want > g_maxBodySize) {
        bodyTooLarge = true;
        const size_t DRAIN_LIMIT = 2 * g_maxBodySize;
        size_t drained = request.size() > headerEnd + 4
                             ? request.size() - (headerEnd + 4) : 0;
        char sink[BUFFERLEN];
        while (drained < want && want <= DRAIN_LIMIT) {
          int n = sock_read(sink, (int)std::min((size_t)BUFFERLEN, want - drained));
          if (n <= 0) break;
          drained += (size_t)n;
          if (std::chrono::steady_clock::now() >= deadline) break;
        }
        want = 0;
      }

      size_t bodyStart = headerEnd + 4;
      size_t have = request.size() > bodyStart ? request.size() - bodyStart : 0;
      while (have < want) {
        char buffer[BUFFERLEN];
        int n = sock_read(buffer,
                          (int)std::min((size_t)BUFFERLEN, want - have));
        if (n <= 0) break;
        request.append(buffer, n);
        have += (size_t)n;
        if (std::chrono::steady_clock::now() >= deadline) break;
      }
    }
  }

  // From here on, all writes go through a FILE* — plain fd or TLS-backed.
  FILE *out = nullptr;
#ifdef HAVE_OPENSSL
  if (ssl) {
    out = ssl_to_file(ssl);
    if (out) sslGuard.ssl = nullptr; // ownership moved into the FILE*
  }
#endif
  if (!out) {
#ifdef HAVE_OPENSSL
    if (ssl) return; // TLS is up but the shim failed; let the guard clean up
#endif
    out = fdopen(socket, "w");
    if (!out) { close(socket); return; }
  }
  struct ScopedFile {
    FILE *f;
    ~ScopedFile() { if (f) fclose(f); }
  } sf{out};

  if (bodyTooLarge) { send_error(out, 413, "Payload Too Large"); return; }
  http_proto(out, request);
}

// [Claude] One request must not be able to kill the server.  A 32 MB body and
// a 32 MB response are each a single allocation, so a machine under memory
// pressure will fail one of them -- and this used to build with
// -fno-exceptions, where that failure is not a throw but a call to
// std::terminate.  The whole process died because one client asked for more
// than there was.
//
// The worker catches instead, drops that connection, and goes back to the
// queue.  No reply is attempted: a failure while the reply is being built
// leaves the socket's state unknown, and closing is the one thing that is
// certainly safe.
void serve(int fd, const std::string &ip, const std::string &tag) {
  try {
    handle_connection(fd, ip);
  } catch (const std::bad_alloc &) {
    log_line(tag + "out of memory serving " + ip + "; connection dropped" +
             CLR_RESET);
    close(fd);
  } catch (const std::exception &e) {
    log_line(tag + "error serving " + ip + ": " + e.what() +
             "; connection dropped" + CLR_RESET);
    close(fd);
  } catch (...) {
    log_line(tag + "unknown error serving " + ip + "; connection dropped" +
             CLR_RESET);
    close(fd);
  }
}

// [plotfi] The bind/listen path, CHECK-per-syscall, with his column-aligned
// commentary preserved.  [Claude] changed the address: the original bound
// htonl(INADDR_ANY) unconditionally, this takes a configured address through
// inet_pton so exposure is opt-in, and value-initialises saddr instead of bzero.
int construct_tcp_socket(std::uint16_t port) {
  int ssock;
  int one = 1;
  struct sockaddr_in saddr = {};
  saddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, g_bindAddress.c_str(), &saddr.sin_addr) != 1) {
    std::cerr << "Invalid bind address: " << g_bindAddress << '\n';
    std::exit(EXIT_FAILURE);
  }
  saddr.sin_port = htons(port);
  CHECK(ssock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP), "socket()");
  CHECK(setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)), "setsockopt()");
  CHECK(bind(ssock, (struct sockaddr *)&saddr, sizeof(saddr)), "bind()");
  CHECK(listen(ssock, MAXPENDING), "listen()");
  return ssock;
}

// [plotfi] The accept wrapper.  [Claude] changed: returns ClientConn rather than
// a bare fd so the peer address travels with the connection; inet_ntop replaces
// inet_ntoa, which is not thread-safe and cannot be called from eight consumers;
// and the socket gets send/recv timeouts plus SO_NOSIGPIPE.
ClientConn accept_connection(int ssock) {
  struct sockaddr_in addr = {};
  socklen_t len = sizeof(addr);
  int fd = accept(ssock, (struct sockaddr *)&addr, &len);
  if (fd < 0) return ClientConn{-1, ""};
#ifdef SO_NOSIGPIPE
  { int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)); }
#endif
  // Both directions time out: RCVTIMEO stops slowloris, SNDTIMEO stops a
  // slow-reading client from holding a worker thread forever.
  // Receive stays tight against slowloris.  Send is looser because a response
  // may now carry a multi-megabyte file: ten seconds would demand 500 KB/s and
  // strand slower clients on a file they could otherwise fetch.  The cost is
  // that a slow reader occupies a worker for up to a minute.
  { struct timeval rcv = {10, 0}, snd = {60, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof(rcv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof(snd)); }

  char ipbuf[INET_ADDRSTRLEN] = {};
  const char *ipstr = inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf));
  return ClientConn{fd, ipstr ? std::string(ipstr) : std::string("?")};
}

// =============================================================================
// [plotfi] SyncQueue — the threading ADT, from commit e700e9a (2018).
//
// A mutex, a condition variable and a std::queue, wrapped so the producer and
// the consumers never touch the container directly.  The interface, the
// ownership model and the blocking dequeue are his and are unchanged.
//
// [Claude] modified it in three ways, all additive:
//   * bounded it at MAX_SIZE, so a full queue is a signal the acceptor can act
//     on (shed the connection) rather than unbounded memory and fd growth;
//     enqueue therefore returns bool where his returned void
//   * notify_one instead of notify_all, and the predicate form of cv.wait —
//     one waiter is enough per item, and the predicate closes the spurious
//     wakeup gap that the bare `while (!size()) cv.wait()` loop handled by hand
//   * the optional depth out-parameters, for the debug tracing below
// =============================================================================
template <class T> class SyncQueue {
public:
  static constexpr size_t MAX_SIZE = 256;

  // `depth` receives the new size on success, so the producer can report queue
  // pressure without reacquiring the lock (and without racing a consumer).
  bool enqueue(T t, size_t *depth = nullptr) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.size() >= MAX_SIZE) return false;
    queue_.push(std::move(t));
    if (depth) *depth = queue_.size();
    cv_.notify_one();
    return true;
  }

  T dequeue(size_t *remaining = nullptr) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return !queue_.empty(); });
    T t = std::move(queue_.front());
    queue_.pop();
    if (remaining) *remaining = queue_.size();
    return t;
  }

private:
  std::mutex              mutex_;
  std::condition_variable cv_;
  std::queue<T>           queue_;
};

} // anonymous namespace

// [plotfi] main's skeleton is his: set up, start the producer and the consumer
// pool, then idle on stdin until 'q'.  [Claude] added everything between —
// config, the CSRF token, the chat directory, TLS setup and the signal
// disposition — and the startup banner lines.
int main(int argc, char **argv) {
  (void)argc; (void)argv;

  // stdio writes to a peer-closed socket must return EPIPE, not kill us.
  { struct sigaction sa{};
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, nullptr); }

  // 128-bit CSRF token, minted once per process and embedded in the page.
  { std::random_device rd;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 4; ++i) oss << std::setw(8) << rd();
    g_csrfToken = oss.str(); }

  load_config("attohttp.conf");
  // The blob cap lives in the C++ and in the browser JS the C++ serves.  Rather
  // than let a config change desync them, substitute the configured value into
  // the served copy, so the client always enforces exactly what the server
  // will accept.  The version hash is taken from the substituted copy, so the
  // cache-busting query follows the config too.
  g_servedJs.assign(CHAT_JS, sizeof(CHAT_JS) - 1);
  {
    const std::string needle = "var MAX_BLOB = 28 * 1024 * 1024;";
    auto at = g_servedJs.find(needle);
    if (at != std::string::npos)
      g_servedJs.replace(at, needle.size(),
                         "var MAX_BLOB = " + std::to_string(g_maxBlobLen) + ";");
  }
  g_cssVer = asset_version(CHAT_CSS, sizeof(CHAT_CSS) - 1);
  g_jsVer  = asset_version(g_servedJs.data(), g_servedJs.size());
  g_swVer  = asset_version(CHAT_SW,  sizeof(CHAT_SW)  - 1);
  // 0700: the transcripts are ciphertext, but there is no reason to publish
  // even the room names to other users on the box.
  if (mkdir(g_chatDir.c_str(), 0700) != 0 && errno != EEXIST) {
    std::cerr << "Cannot create chat directory " << g_chatDir << ": "
              << std::strerror(errno) << '\n';
    return EXIT_FAILURE;
  }
  rooms_scan();

#ifdef HAVE_OPENSSL
  if (!g_tlsCert.empty() && !g_tlsKey.empty()) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_sslCtx = SSL_CTX_new(TLS_server_method());
    if (!g_sslCtx) { std::cerr << "SSL_CTX_new failed\n"; return EXIT_FAILURE; }
    SSL_CTX_set_min_proto_version(g_sslCtx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_chain_file(g_sslCtx, g_tlsCert.c_str()) <= 0) {
      std::cerr << "Failed to load TLS cert: " << g_tlsCert << '\n';
      return EXIT_FAILURE;
    }
    if (SSL_CTX_use_PrivateKey_file(g_sslCtx, g_tlsKey.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
      std::cerr << "Failed to load TLS key: " << g_tlsKey << '\n';
      return EXIT_FAILURE;
    }
    if (!SSL_CTX_check_private_key(g_sslCtx)) {
      std::cerr << "TLS cert and key do not match\n";
      return EXIT_FAILURE;
    }
    log_line(CLR_STAR "* TLS: enabled (min TLSv1.2)" CLR_RESET);
  } else {
    log_line(CLR_STAR "* TLS: disabled (set tls_cert and tls_key in attohttp.conf)"
             CLR_RESET);
  }
#else
  log_line(CLR_STAR "* TLS: not compiled in (OpenSSL not found)" CLR_RESET);
#endif

  log_line(CLR_STAR "* Debug tracing: " +
           std::string(g_debug ? "on" : "off (set debug = true)") + CLR_RESET);
  log_line(CLR_STAR "* Listening on " + g_bindAddress + ":" +
           std::to_string(g_port) + " with " + std::to_string(g_threads) +
           " worker threads" CLR_RESET);

  // Say the memory budget out loud, and warn when it does not fit the box.
  // The worst case is every worker holding a full request body plus the whole
  // room-residency ceiling; if that exceeds physical RAM, the OOM killer is a
  // when, not an if -- and on a systemd login it takes the session with it.
  {
    size_t bodies = (size_t)g_threads * g_maxBodySize;
    size_t worst  = bodies + g_maxTotalMemory;
    log_line(CLR_STAR "* Memory budget: up to " +
             std::to_string(g_maxTotalMemory / (1024 * 1024)) +
             " MB of rooms + " + std::to_string(g_threads) + " x " +
             std::to_string(g_maxBodySize / (1024 * 1024)) + " MB request buffers = " +
             std::to_string(worst / (1024 * 1024)) + " MB worst case" CLR_RESET);
    long physMb = -1;
    if (FILE *f = fopen("/proc/meminfo", "r")) {   // Linux; skipped elsewhere
      char line[256];
      while (fgets(line, sizeof line, f))
        if (sscanf(line, "MemTotal: %ld kB", &physMb) == 1) { physMb /= 1024; break; }
      fclose(f);
    }
    if (physMb > 0 && worst > (size_t)physMb * 1024u * 1024u) {
      log_line(CLR_ERR "! The worst case (" + std::to_string(worst / (1024 * 1024)) +
               " MB) exceeds this machine's RAM (" + std::to_string(physMb) +
               " MB)." CLR_RESET);
      log_line(CLR_ERR "! Under load the OOM killer will stop the server. Lower "
               "'threads' and 'max_memory_mb' in attohttp.conf." CLR_RESET);
    }
  }

  // ===========================================================================
  // [plotfi] The producer/consumer pool, from commit 31a5e95 (2018).  One
  // producer thread accepts and enqueues; a fixed pool of consumers each take a
  // connection and own it end to end.  The lambda structure, the thread count
  // and the [PRODUCER]/[CONSUMER] log convention are his.
  //
  // [Claude] changed: the queue carries ClientConn rather than a raw int so the
  // peer address rides along; a full queue closes the connection instead of
  // blocking; and the tracing gained worker identity, queue depth and timing,
  // gated on `debug`.
  // ===========================================================================
  SyncQueue<ClientConn> queue;
  int serverSocket = construct_tcp_socket(g_port);

  std::thread producer([&] {
    log_line(CLR_PROD "[PRODUCER] listening on " + g_bindAddress + ":" +
             std::to_string(g_port) + CLR_RESET);
    for (;;) {
      ClientConn c = accept_connection(serverSocket);
      if (g_shuttingDown) { if (c.fd >= 0) close(c.fd); break; }
      if (c.fd < 0) continue;
      int fd = c.fd;
      std::string ip = c.ip;
      size_t depth = 0;
      if (!queue.enqueue(std::move(c), &depth)) {
        log_line(CLR_PROD "[PRODUCER] queue full, dropping " + ip + CLR_RESET);
        close(fd);
        continue;
      }
      if (g_debug)
        log_line(CLR_PROD "[PRODUCER] accept fd=" + std::to_string(fd) +
                 " from " + ip + " -> queue " + std::to_string(depth) + "/" +
                 std::to_string(SyncQueue<ClientConn>::MAX_SIZE) + CLR_RESET);
    }
  });

  std::vector<std::thread> workers;
  for (unsigned i = 0; i < g_threads; ++i) {
    workers.emplace_back([&, i] {
      // Belt and braces alongside the process-wide SIG_IGN above: on Linux
      // there is no SO_NOSIGPIPE, so block the signal in the thread that writes.
      { sigset_t ss;
        sigemptyset(&ss);
        sigaddset(&ss, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &ss, nullptr); }
      const std::string tag =
          CLR_CONS "[CONSUMER " + std::to_string(i) + "] ";
      for (;;) {
        size_t remaining = 0;
        ClientConn c = queue.dequeue(&remaining);
        // A negative fd is the wake-up a shutdown enqueues; otherwise it is a
        // failed accept and the worker goes back to waiting.
        if (c.fd < 0) { if (g_shuttingDown) break; continue; }
        if (!g_debug) { serve(c.fd, c.ip, tag); continue; }
        log_line(tag + "take fd=" + std::to_string(c.fd) + " from " + c.ip +
                 " (queue " + std::to_string(remaining) + ")" CLR_RESET);
        auto t0 = std::chrono::steady_clock::now();
        serve(c.fd, c.ip, tag);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0).count();
        log_line(tag + "done fd=" + std::to_string(c.fd) + " in " +
                 std::to_string(ms) + "ms" CLR_RESET);
      }
    });
  }

  // [plotfi] His idle loop: press 'q' to quit, everything else keeps serving.
  // [Claude] fixed two bugs in it.
  //
  // With stdin closed — daemonised, or output redirected — getchar returned
  // EOF forever, which spun a tight loop against std::cout's lock and starved
  // the consumers.  EOF now sleeps instead.
  //
  // And it quit on a 'q' anywhere in the input.  The server is usually in the
  // foreground of a terminal, so it is holding that terminal's stdin: typing
  // `ls /tmp/queue` at what looks like a shell prompt stopped the server.  It
  // now reads a whole line and quits only when that line is exactly "q" or
  // "quit", which is the documented gesture and nothing else.
  {
    std::string line;
    while (std::getline(std::cin, line)) {
      const std::string cmd = [&] {
        auto a = line.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return std::string();
        auto b = line.find_last_not_of(" \t\r\n");
        return line.substr(a, b - a + 1);
      }();
      if (cmd == "q" || cmd == "quit") break;
      if (!cmd.empty())
        log_line("* Type 'q' alone on a line to stop the server.");
    }
    if (!std::cin) {
      // stdin is gone (daemonised, or redirected from /dev/null).  There is
      // nothing left to read, so idle rather than spin.
      while (!g_shuttingDown)
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
  }

  // Returning here used to destroy 130 joinable std::threads, and
  // ~thread on a joinable thread calls std::terminate -- so the ordinary
  // way of stopping the server was an abort, complete with a core dump and
  // a "libc++abi: terminating" where the goodbye should have been.
  log_line("* Shutting down");
  g_shuttingDown = true;

  // Unblock the producer's accept(), then hand every worker a sentinel so the
  // ones parked on the queue wake up and see the flag.
  shutdown(serverSocket, SHUT_RDWR);
  close(serverSocket);
  for (unsigned i = 0; i < g_threads; ++i) queue.enqueue(ClientConn{-1, ""});

  if (producer.joinable()) producer.join();
  for (auto &w : workers)
    if (w.joinable()) w.join();

  log_line("* Stopped");
  return EXIT_SUCCESS;
}
