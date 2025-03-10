/*
    @author yuanshixi
    @brief A http file server written in C++11, no 3rd-parties, just using linux raw socket.
           supports file list, file uploading, chunked data transfer.
           only for linux platform.
*/
#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <utility>
#include <algorithm>
#include <forward_list>
#include <unordered_map>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cerrno>

// linux headers.
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <ifaddrs.h>

constexpr uint32_t MAX_HTTP_REQUEST_LENGTH = 2048;
constexpr uint32_t MAX_HTTP_REQUEST_METHOD_LENGTH = 32;
constexpr uint32_t MAX_HTTP_REQUEST_URL_LENGTH = 1024;
constexpr uint32_t MAX_HTTP_REQUEST_VERSION_LENGTH = 32;
constexpr uint32_t MAX_HTTP_REQUEST_HEADERS_NUM = 32;

constexpr uint32_t MAX_HTTP_RESPONSE_FIRST_LINE_LENGTH = 128;
constexpr uint32_t MAX_IP_PORT_LENGTH = INET6_ADDRSTRLEN + 7;

static volatile sig_atomic_t running = 1;   // server is running ?
static std::string local_ip_port;

void handle_sigint(int sigum) noexcept {
	running = 0;
}

void handle_sigchld(int signum) noexcept {
    pid_t pid;
    int status;

    // zombie process handling.
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* do nothing. */    
    }
}

void set_signals(void) {
	struct sigaction actionSIGINT;
    struct sigaction actionSIGCHLD;

    actionSIGINT.sa_handler = handle_sigint;
    actionSIGINT.sa_flags = 0;
    sigemptyset(&(actionSIGINT.sa_mask));

    actionSIGCHLD.sa_handler = handle_sigchld;
    actionSIGCHLD.sa_flags = SA_RESTART;
    sigemptyset(&(actionSIGCHLD.sa_mask));

    if (sigaction(SIGINT, &actionSIGINT, nullptr) < 0) {
        throw std::system_error(errno, std::system_category(), "sigaction() on `SIGINT` failed");
    }

    if (sigaction(SIGCHLD, &actionSIGCHLD, nullptr) < 0) {
        throw std::system_error(errno, std::system_category(), "sigaction() on `SIGCHLD` failed");
    }

	/* 
        if we cancel send() with large data, this would make send() return immediately, 
        otherwise the whole program would terminated, that should not be happend.
    */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        throw std::system_error(errno, std::system_category(), "signal() set SIG_IGN to `SIGPIPE` failed");
	}
}

int parse_port(const char* param) noexcept {
    int result = 0;

    while (*param != '\0') {
        if (isdigit(*param)) {
            result = 10 * result + (*param - '0');
        }
        else {
            return -1;
        }

        ++param;
    }

    if (result > 65535) {   // port should between: 0 ~ 65535
        return -1;
    }

    return result;
}

bool is_dir(const char* path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        auto ec = errno;
        std::cerr << "stat() failed: `" << path << "`, " << strerror(ec) << "\n";
        return false;
    }

    return S_ISDIR(st.st_mode);
}

bool is_regular_file(const char* path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        auto ec = errno;
        std::cerr << "stat() failed: `" << path << "`, " << strerror(ec) << "\n";
        return false;
    }

    return S_ISREG(st.st_mode);
}

// get the remote socket's ip and port, return a formated string like "192.168.52.204:8039".
std::string get_remote_sock_info(int fd) {
    std::array<char, INET6_ADDRSTRLEN> ip;
    std::string info;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (getpeername(fd, (struct sockaddr*)(&addr), &len) != 0) {
        throw std::system_error(errno, std::system_category(), "getpeername() failed");
    }

    if (inet_ntop(addr.sin_family, &(addr.sin_addr), ip.data(), ip.size()) == nullptr) {
        throw std::system_error(errno, std::system_category(), "inet_ntop() failed");
    }

    info.reserve(MAX_IP_PORT_LENGTH);
    info += ip.data();
    info += ":";
    info += std::to_string(ntohs(addr.sin_port));
    return info;
}

template<typename Func>
class Finally {
    Func f;
public:
    Finally(Func _f) : f{ _f } {}

    ~Finally() noexcept {
        f();
    }
};

template<typename Func>
Finally<Func> finally(Func f) {
    return Finally<Func>{ f };
}

struct StrHashIgnoreCase {
    size_t operator()(const std::string& str) const {
        size_t hashval = 0;

        for (size_t i = 0; i < str.length(); ++i) {
            hashval = static_cast<size_t>(tolower(str[i])) + 31 * hashval;
        }

        return hashval;
    }
};

struct StrEqualIgnoreCase {
    bool operator()(const std::string& left, const std::string& right) const {
        auto cond = [](char c1, char c2) {
            return tolower(c1) == tolower(c2);
        };

        return std::equal(left.cbegin(), left.cend(), right.cbegin(), cond);
    }
};

bool string_compare_ignore_case(const std::string& left, const std::string& right) {
    StrEqualIgnoreCase seic;
    return seic(left, right);
}

using Headers = std::unordered_map<std::string, std::string, StrHashIgnoreCase, StrEqualIgnoreCase>;
using MimeMap = std::unordered_map<std::string, std::string, StrHashIgnoreCase, StrEqualIgnoreCase>;

static MimeMap mimeMap;

std::string extension_to_mime(const std::string& extension) {
    auto iter = mimeMap.find(extension);
    
    if (iter == mimeMap.cend()) {
        return "text/plain";
    }
    else {
        return iter->second;
    }
}

struct Request {
    std::string method;
    std::string url;
    std::string version;
    Headers headers;
};

struct Response {
    std::string version;
    std::string code;
    std::string msg;
    Headers headers;
    std::string body;
};

struct Connection {
    int fd;
    std::string ip_port;

    Connection(int _fd) : fd{ _fd }, ip_port{ get_remote_sock_info(_fd) } {}

    ~Connection() noexcept {
        if (fd >= 0) {
            close(fd);
        }
    }

    void set_recv_timeout(long sec, long usec) {
        struct timeval timeout;
        timeout.tv_sec = sec;
		timeout.tv_usec = usec;

		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			throw std::system_error(errno, std::system_category(), ip_port + ", setsockopt() failed on `SO_RCVTIMEO`");
		}
    }

    /*
        do what recv() did, but will throw a system_error when failed.
        if connection has been closed, throw a std::runtime_error.
    */
    ssize_t recv(char* buf, size_t len, int flags) {
        ssize_t recvLen = ::recv(fd, buf, len, flags);

        if (recvLen < 0) {
            throw std::system_error(errno, std::system_category(), ip_port + ", recv() failed");
        }
        else if (recvLen == 0) {
            throw std::runtime_error{ ip_port + ", connection has been closed" };
        }

        return recvLen;
    }

    /*
        do what send() did.
        this function using a loop to call send() until all `len` bytes
        data are sent. if any send() failed, this function will throw a system_error.
    */
    ssize_t send(const char* buf, size_t len, int flags) {
        ssize_t total = 0;
        ssize_t sent = 0;

        while (len > 0) {
            sent = ::send(fd, buf + sent, len - sent, flags);

            if (sent < 0) {
                throw std::system_error(errno, std::system_category(), ip_port + ", send() failed");
            }

            len -= sent;
            total += sent;
        }

        return total;
    }

    ssize_t send(const char* buf, size_t len) {
        return send(buf, len, 0);
    }

    ssize_t send(const std::string& data) {
        return send(data.c_str(), data.length(), 0);
    }

    /*
        read a http line into the buf, exclude the tail \r\n.

        if any system call error occurs or connection has been closed, throw a exception.
        if request length exceed the `N`, return -1.
        if meets the final \r\n, return 0.
        else return the length of the line.
    */
    template<size_t N>
    ssize_t read_line(std::array<char, N>& buf) {
        ssize_t recvBytesLen = 0;
        char c;

        while (recvBytesLen < N) {
            recv(&c, 1, 0);

            if (c == '\r') {
                recv(&c, 1, MSG_PEEK);

                if (c == '\n') {   // this line finished.
                    recv(&c, 1, 0);   // ignore this character.
                    break;
                }
                else {
                    return -1;   // must be \r\n, not \r\XXXXX
                }
            }
            else {
                buf[recvBytesLen] = c;
                ++recvBytesLen;
            }
        }

        return c == '\n' ? recvBytesLen : -1;   // exceed the N.
    }

    template<size_t N>
    ssize_t read_line(std::array<char, N>& buf, size_t limit) {
        ssize_t recvBytesLen = 0;
        char c;

        while (recvBytesLen < limit) {
            recv(&c, 1, 0);

            if (c == '\r') {
                recv(&c, 1, MSG_PEEK);

                if (c == '\n') {   // this line finished.
                    recv(&c, 1, 0);   // ignore this character.
                    break;
                }
                else {
                    return -1;   // must be \r\n.
                }
            }
            else {
                buf[recvBytesLen] = c;
                ++recvBytesLen;
            }
        }

        return c == '\n' ? recvBytesLen : -1;   // exceed the limit.
    }
};

template<size_t N>
bool parse_request_method_url_version(Connection& conn, Request& req, std::array<char, N>& buf) {
    ssize_t len = conn.read_line(buf);
    ssize_t i;

    if (len < 0) {
        return false;
    }

    i = 0;
    while (buf[i] != ' ') {
        if (req.method.length() == MAX_HTTP_REQUEST_METHOD_LENGTH) {
            return false;
        }

        req.method += buf[i];
        ++i;
    }

    ++i;   // ignore the space.
    while (buf[i] != ' ') {
        if (req.url.length() == MAX_HTTP_REQUEST_URL_LENGTH) {
            return false;
        }

        req.url += buf[i];
        ++i;
    }

    ++i;   // ignore the space.
    while (i < len) {
        if (req.version.length() == MAX_HTTP_REQUEST_VERSION_LENGTH) {
            return false;
        }

        req.version += buf[i];
        ++i;
    }

    return true;
}

template<size_t N>
void split_header_and_save(Request& req, std::array<char, N>& buf, ssize_t len) {
    size_t i = 0;

    while (i < len && buf[i] != ':') {   // key, value are split by ": "
        ++i;
    }

    std::string key{ buf.data(), i };
    std::string value{ buf.data() + i + 2, len - i - 2 };
    req.headers.emplace(std::move(key), std::move(value));
}

template<size_t N>
bool parse_request_headers(Connection& conn, Request& req, std::array<char, N>& buf) {
    ssize_t len;

    while (true) {
        len = conn.read_line(buf);

        if (len < 0) {
            return false;
        }
        else if (len == 0) {   // meets the final \r\n
            return true;
        }
        else {
            if (req.headers.size() == MAX_HTTP_REQUEST_HEADERS_NUM) {
                return false;   // too many headers is not allowed.
            }

            split_header_and_save(req, buf, len);
        }
    }
}

int hex_to_decimal(char c) {
    if (c >= '0' && c <= '9'){
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f'){
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F'){
        return c - 'A' + 10;
    }
    else {
        return -1;
    }
}

bool decode_percent_encoding_url(Request& req) {
    std::string temp;
    size_t i = 0;
    int p1, p2;

    temp.reserve(req.url.length());
    while (i < req.url.length()) {
        if (req.url[i] == '%') {
            if (i + 2 >= req.url.length()) {   // there must be 2 characters behind a '%'.
                return false;
            }

            p1 = hex_to_decimal(req.url[i + 1]);
            p2 = hex_to_decimal(req.url[i + 2]);

            if (p1 >= 0 && p2 >= 0) {
                temp += static_cast<char>(16 * p1 + p2);
                i += 3;     
            }
            else {
                return false;
            }
        }
        else {
            temp += req.url[i];
            ++i;
        }
    }

    req.url = std::move(temp);
    return true;
}

template<size_t N>
bool parse_request(Connection& conn, Request& req, std::array<char, N>& buf) {
    return parse_request_method_url_version(conn, req, buf) 
            && parse_request_headers(conn, req, buf) 
            && decode_percent_encoding_url(req);
}

void response_init_by_template(Response& res, const std::string& code, const std::string& msg) {
    res.version = "HTTP/1.1";
    res.code = code;
    res.msg = msg;

    res.body += "<html><head><h1>";
    res.body += code;
    res.body += "</h1></head><body>";
    res.body += msg;
    res.body += "</body></html>";

    res.headers.emplace("Content-Type", "text/html");
    res.headers.emplace("Content-Length", std::to_string(res.body.length()));
}

std::string response_to_str(const Response& res) {
    std::string temp;
    temp.reserve(MAX_HTTP_RESPONSE_FIRST_LINE_LENGTH + res.body.length());

    temp += res.version;
    temp += " ";
    temp += res.code;
    temp += " ";
    temp += res.msg;
    temp += "\r\n";

    for (const auto& pair : res.headers) {
        temp += pair.first;
        temp += ": ";
        temp += pair.second;
        temp += "\r\n";
    }

    temp += "\r\n";
    temp += res.body;
    
    return temp;
}

void send_response_template(Connection& conn, const std::string& code, const std::string& msg) {
    Response res;
    response_init_by_template(res, code, msg);
    conn.send(response_to_str(res));
}

std::string concatenate_path(const std::string& parent, const std::string& sub) {
    std::string temp;
    temp.reserve(parent.length() + 2 + sub.length());

    temp += parent;
    if (temp.back() == '/') {
        temp.pop_back();
    }

    if (sub.front() != '/') {
        temp += '/';
    }

    temp += sub;
    return temp;
}

void reverse_string(std::string& str) {
	size_t len = str.length();

	for (size_t i = 0; i < len / 2; ++i) {
		std::swap(str[i], str[len - 1 - i]);
	}
}

std::string integer_to_hex_str(long number) {
	std::string result;

	while (number > 0) {
		long remainder = number % 16;

		if (remainder < 10) {
			result += remainder + '0';
		}
		else {
			result += remainder - 10 + 'A';
		}

		number = number / 16;
	}

	reverse_string(result);
	return result;
}

void send_chunked_data(Connection& conn, const char* data, size_t len) {
    conn.send(integer_to_hex_str(len));
    conn.send("\r\n");
    conn.send(data, len);
    conn.send("\r\n");
}

void send_chunked_data(Connection& conn, const std::string& data) {
    conn.send(integer_to_hex_str(data.length()));
    conn.send("\r\n");
    conn.send(data.c_str(), data.length());
    conn.send("\r\n");
}

std::string float_to_str(float num, int precision) {
    long long_part = (long)num;
    float float_part = num - long_part;
    long digit;
    
    std::string numStr = std::to_string(long_part);
    numStr += ".";
    
    for (int i = 0; i < precision; ++i) {
        float_part *= 10;
        digit = static_cast<long>(float_part);
        numStr += static_cast<char>(digit + '0');
        float_part -= digit;
    }

    return numStr;
}

std::string file_size_to_str(float fileSize, int precision) {
    int level = 0;
    std::string str;

	while (true) {
		if (fileSize / 1024.0 < 1.0f || level == 4) {
			break;
		}
		else {
			fileSize /= 1024.0;
			++level;
		}
	}

    str = float_to_str(fileSize, precision);

    switch(level) {
        case 0:
            str += " B";
            break;
        case 1:
            str += " KB";
            break;
        case 2:
            str += " MB";
            break;
        case 3:
            str += " GB";
            break;
        case 4:
        default:
            str += " TB";
            break;
    }

    return str;
}

void traverse_dir(DIR* dir, const std::string& rootPath, const std::string& url, std::forward_list<std::string>& collector) {
    struct dirent* entry;
    struct stat st;

    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string entryName = entry->d_name;
        std::string subUrl = concatenate_path(url, entryName);
        std::string completePath = concatenate_path(rootPath, subUrl);

        if (stat(completePath.c_str(), &st) < 0) {
            // maybe permission denied or some other error, just skip.
            continue;
        }

        std::string line;
        line += "<li><a href=\"";
        line += subUrl;
        line += "\">";

        if (S_ISDIR(st.st_mode)) {
            line += "/";
        }

        line += entryName;

        if (S_ISREG(st.st_mode)) {
            line += "</a><span>&nbsp;&nbsp;";
            line += file_size_to_str(st.st_size, 2);
            line += "</span></li>\n";
        }
        else {
            line += "</a></li>\n";
        }

        collector.push_front(std::move(line));
    }
}

void build_file_list_then_send(Connection& conn, DIR* dir, const std::string& rootPath, const std::string& url) {
    std::forward_list<std::string> collector;
    std::string temp;
    const int capacity = 8192;
    const int threshold = capacity - 512;

    temp.reserve(capacity);

    traverse_dir(dir, rootPath, url, collector);
    for (const std::string& str : collector) {
        if (temp.length() >= threshold) {
            send_chunked_data(conn, temp);
            temp.clear();
        }
        else {
            temp += str;
        }
    }

    if (temp.length() > 0) {
        send_chunked_data(conn, temp);
    }
}

void send_file_list(Connection& conn, const Request& req, const std::string& rootPath, DIR* dir) {
    std::string temp;

    temp += "<html><head><h1>Http File Server</h1></head><body>";
    temp += "<form id=\"uploadForm\" action=\"http://";
    temp += local_ip_port;
    temp += req.url;
    temp += "\" method=\"POST\" enctype=\"multipart/form-data\">";
    temp += "<input type=\"file\" id=\"fileInput\" name=\"fileInput\" />";
    temp += "<button type=\"submit\">Upload</button></form><hr><ul>";

    send_chunked_data(conn, temp);
    build_file_list_then_send(conn, dir, rootPath, req.url);
    send_chunked_data(conn, "</ul><hr></body></html>");
    conn.send("0\r\n\r\n");   // end of chunked data.
}

void serve_file_list(Connection& conn, const Request& req, const std::string& currentPath, const std::string& rootPath) {
    Response res;
    DIR* dir;

    if ((dir = opendir(currentPath.c_str())) == nullptr) {
        auto ec = errno;
        send_response_template(conn, "500", "Internal Server Error");
        std::cerr << conn.ip_port << " can't open `" << currentPath << "`, " << strerror(ec) << "\n";
    }
    else {
        auto clean_dir = finally([dir](){
            closedir(dir);
        });

        res.version = "HTTP/1.1";
        res.code = "200";
        res.msg = "OK";

        res.headers.emplace("Content-Type", "text/html; charset=utf-8");
        res.headers.emplace("Transfer-Encoding", "chunked");

        conn.send(response_to_str(res));
        send_file_list(conn, req, rootPath, dir);
    }
}

std::string get_file_extension(const std::string& path) {
    size_t i = 0;

    while (i < path.length() && path[i] != '.') {
        ++i;
    }

    if (i != path.length()) {
        return path.substr(i + 1);
    }
    else {
        return "";
    }
}

void send_chunked_file_data(Connection& conn, const std::string& path) {
    std::array<char, 8192> buf;
    std::ifstream in{ path, std::ios::binary };

    while (!in.eof()) {
        in.read(buf.data(), buf.size());
        long len = in.gcount();

        send_chunked_data(conn, buf.data(), len);
    }

    conn.send("0\r\n\r\n");   // end of chunked data.
}

void serve_single_file(Connection& conn, const std::string& path) {
    std::string extension = get_file_extension(path);
    std::string mimeType;
    Response res;

    if (extension == "") {
        mimeType = "text/html";
    }
    else {
        mimeType = extension_to_mime(extension);
    }

    res.version = "HTTP/1.1";
    res.code = "200";
    res.msg = "OK";

    res.headers.emplace("Content-Type", mimeType);
    res.headers.emplace("Transfer-Encoding", "chunked");

    conn.send(response_to_str(res));
    send_chunked_file_data(conn, path);
}

void handle_files_page(Connection& conn, const Request& req, const std::string& rootPath) {
    std::string currentPath = concatenate_path(rootPath, req.url);

    if (is_dir(currentPath.c_str())) {
        serve_file_list(conn, req, currentPath, rootPath);
    }
    else if(is_regular_file(currentPath.c_str())) {
        serve_single_file(conn, currentPath);
    }
    else {
        send_response_template(conn, "404", "Not Found");
    }
}

std::string parse_boundary(const std::string& contentTypeValue) {
    const std::string pattern = "multipart/form-data; boundary=";
    auto pos = contentTypeValue.find(pattern);

    if (pos != std::string::npos) {
        return contentTypeValue.substr(pos + pattern.length());
    }
    else {
        return "";
    }
}

void send_upload_success_page(Connection& conn) {
    Response res;

    res.version = "HTTP/1.1";
    res.code = "200";
    res.msg = "OK";

    res.body += "<html><head><h1>";
    res.body += "Http File Server";
    res.body += "</h1></head><body>";
    res.body += "Upload success";
    res.body += "</body></html>";

    res.headers.emplace("Content-Type", "text/html; charset=utf-8");
    res.headers.emplace("Content-Length", std::to_string(res.body.length()));

    conn.send(response_to_str(res));
}

void recv_uploaded_file_data(Connection& conn, long long fileSize, const std::string& boundary, const std::string parentDir) {
    const std::string pattern = "filename=\"";
    std::string fileName;
    std::array<char, 8192> buf;
    ssize_t recvLen;

    // get the filename.
    while (true) {
        recvLen = conn.read_line(buf, buf.size() - 1);   // leave one place to hold '\0'.

        if (recvLen < 0) {
            send_response_template(conn, "413", "Request Entity Too Large");
            return;
        }
        else if (recvLen == 0) {   // meets the final \r\n
            fileSize -= 2;   // subtract the length of the \r\n
            break;
        }
        else {
            fileSize -= (recvLen + 2);   // subtract the `recvLen` and `\r\n`.
            
            buf[recvLen] = '\0';
            char* pos = strstr(buf.data(), pattern.data());

            if (pos != nullptr) {
                pos += pattern.length();

                while (*pos != '"') {
                    fileName += *pos;
                    ++pos;
                }
            }
        }
    }

    if (fileName.length() == 0) {
        send_response_template(conn, "400", "Bad Request");
        return;
    }

    /*
        receive the file data.

        because after the file data, the data remain: "\r\n--boundary--\r\n", so if 
        we have read all the file data, the length of the bytes left must be 
        boundary's length + 8.
    */
    std::string completePath = concatenate_path(parentDir, fileName);
    std::ofstream out{ completePath, std::ios::binary };

    while ((long long)fileSize > (long long)(boundary.length() + 8)) {
        size_t needToReadLen = std::min((long long)buf.size(), (long long)(fileSize - boundary.length() - 8));
        recvLen = conn.recv(buf.data(), needToReadLen, 0);
        out.write(buf.data(), recvLen);

        fileSize -= recvLen;
    }

    out.close();

    /*
        read the final 2 line, `boundary` is the param boundary:

        "\r\n"
        "--boundary--\r\n"
    */
    conn.read_line(buf);
    conn.read_line(buf);

    send_upload_success_page(conn);
    std::cout << conn.ip_port << ", upload file success: `" << completePath << "`\n";
}

void handle_upload(Connection& conn, const Request& req, const std::string& rootPath) {
    auto iter = req.headers.find("Content-Length");
    if (iter == req.headers.cend()) {
        send_response_template(conn, "411", "Length required");
        return;
    }

    std::string contentLength = iter->second;

    iter = req.headers.find("Content-Type");
    if (iter == req.headers.cend()) {
        send_response_template(conn, "400", "Bad Request");
        return;
    }

    std::string contentTypeValue = iter->second;
    std::string boundary = parse_boundary(contentTypeValue);
    if (boundary == "") {
        send_response_template(conn, "400", "Bad Request");
        return;
    }

    long long fileSize = std::stoll(contentLength);
    std::string parentDir = concatenate_path(rootPath, req.url);
    recv_uploaded_file_data(conn, fileSize, boundary, parentDir);
}

void handle_http_request(Connection& conn, const std::string& rootPath) {
    std::array<char, MAX_HTTP_REQUEST_LENGTH> buf;
    Request req;

    if (!parse_request(conn, req, buf)) {
        send_response_template(conn, "400", "Bad Request");
        std::cerr << conn.ip_port <<  ", can't parse http request.\n";
        return;
    }

    if (string_compare_ignore_case(req.method, "GET")) {
        std::cout << conn.ip_port << ", GET - " << req.url << "\n";
        handle_files_page(conn, req, rootPath);
    }
    else if (string_compare_ignore_case(req.method, "POST")) {
        std::cout << conn.ip_port << ", POST - " << req.url << "\n";
        handle_upload(conn, req, rootPath);
    }
    else {
        send_response_template(conn, "405", "Method Not Allowed");
    }
}

void handle_connection(int fd, const std::string& rootPath) {
    try {
        Connection conn{ fd };
        conn.set_recv_timeout(5, 0);

        std::cout << conn.ip_port << ", connected\n";
        handle_http_request(conn, rootPath);
    }
    catch(const std::system_error& se) {
        std::cerr << "system error, code: " << se.code() << ", detail: " << se.what() << "\n";
    }
    catch(const std::runtime_error& re) {
        std::cerr << "runtime error: " << re.what() << "\n";
    }
}

class HttpFileServer {
    std::string rootPath;
    int server_fd;
public:
    HttpFileServer() : rootPath{ "." } {
        server_fd = ::socket(AF_INET, SOCK_STREAM, 0);

        if (server_fd < 0) {
            throw std::system_error(errno, std::system_category(), "socket() failed");
        }
    }

    ~HttpFileServer() noexcept {
        if (server_fd >= 0) {
            close(server_fd);
        }
    }

    void bind(const std::string& ip, int& port) {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        int ret = ::inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr));
        if (ret < 0) {
			throw std::system_error(errno, std::system_category(), "inet_pton() failed");
        }
        else if (ret == 0) {
			throw std::invalid_argument("`" + ip + "` is not a valid ipv4/ipv6 address");
        }

        while (::bind(server_fd, (const struct sockaddr*)(&addr), sizeof(addr)) != 0) {
            if (port == 65535) {
                throw std::system_error(errno, std::system_category(), "bind() failed");
            }
            else {
                port += 1;
                addr.sin_port = htons(port);
            }
        }

        if (::listen(server_fd, 32) != 0) {
            throw std::system_error(errno, std::system_category(), "listen() failed");
        }

        int option = 1;
        if (::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void*)(&option), sizeof(option)) < 0) {
			throw std::system_error(errno, std::system_category(), "setsockopt() on `SO_REUSEADDR` failed");
        }
    }

    void set_root_path(const std::string& _rootPath) {
        rootPath = _rootPath;
    }

    void serve() {
        pid_t pid;

        while (running) {
            int client = ::accept(server_fd, nullptr, nullptr);

            if (client < 0) {
                if (errno == EINTR) {
                    return;
                }
                else {
                    throw std::system_error(errno, std::system_category(), "accept() failed");
                }
            }

            pid = fork();
            if (pid < 0) {
                throw std::system_error(errno, std::system_category(), "fork() failed");
            }
            else if (pid > 0) {  /* parent. */
                close(client);
            }
            else {  /* child. */
                close(server_fd);
                handle_connection(client, rootPath);
                exit(EXIT_SUCCESS);
            }
        }
    }
};

void split_mime_line_and_save(const std::string& line) {
    std::string key;
    std::string value;
    size_t i = 0;

    while (line[i] != ' ' && line[i] != '\t') {
        ++i;
    }

    key.assign(line.c_str(), i);

    while (line[i] == ' ' || line[i] == '\t') {
        ++i;
    }

    value.assign(line.c_str() + i, line.length() - i);
    mimeMap.emplace(std::move(key), std::move(value));
}

bool global_mime_map_init(const std::string& mimeFile) {
    std::ifstream f{ mimeFile };
    if (!f.is_open()) {
        std::cerr << "mime map init failed, can't open `" << mimeFile << "`\n";
        return false;
    }

    std::string line;
    while (!f.eof()) {
        std::getline(f, line);
        
        if (line.length() == 0) {
            continue;
        }
        else {
            split_mime_line_and_save(line);
        }
    }

    return true;
}

void local_ip_port_init(int port) {
    struct ifaddrs* ifaddr;
    struct ifaddrs* cursor;
    struct sockaddr_in* sockaddr;
    std::array<char, INET6_ADDRSTRLEN> ip;

    local_ip_port.reserve(MAX_IP_PORT_LENGTH);

    if (getifaddrs(&ifaddr) != 0) {
        throw std::system_error(errno, std::system_category(), "getifaddrs() failed");
    }

    for (cursor = ifaddr; cursor != nullptr; cursor = cursor->ifa_next) {
        if (cursor->ifa_addr->sa_family == AF_INET) {   // ignore ipv6.
            sockaddr = (struct sockaddr_in*)(cursor->ifa_addr);

            if (inet_ntop(AF_INET, &(sockaddr->sin_addr), ip.data(), INET6_ADDRSTRLEN) == nullptr) {
                auto ec = errno;
                freeifaddrs(ifaddr);
                throw std::system_error(ec, std::system_category(), "inet_ntop() failed");
            }

            // ignore the 127.0.0.1 or 172.xxx.xxx.xxx
            if (strstr(ip.data(), "127") == nullptr && strstr(ip.data(), "172") == nullptr) {
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    local_ip_port += ip.data();
    local_ip_port += ":";
    local_ip_port += std::to_string(port);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <port> <root_dir>\n";
        return 1;
    }

    int port = parse_port(argv[1]);
    if (port < 0) {
        std::cerr << "given port is not valid: `" << argv[1] << "`\n";
        return 1;
    }

    if (!is_dir(argv[2])) {
        std::cerr << "given path is not a dir: `" << argv[2] << "`\n";
        return 1;
    }

    if (!global_mime_map_init("mime.txt")) {
        return 1;
    }

    try {
        HttpFileServer hfs;

        set_signals();
        hfs.set_root_path(argv[2]);
        hfs.bind("0.0.0.0", port);
        local_ip_port_init(port);

        std::cout << "server starts at port: " << port << "\n";
        hfs.serve();
    }
    catch(const std::system_error& se) {
        std::cerr << "system error, code: " << se.code() << ", detail: " << se.what() << "\n";
    }
    catch(const std::runtime_error& re) {
        std::cerr << "runtime error: " << re.what() << "\n";
    }

    std::cout << "server exists\n";
    return 0;
}
