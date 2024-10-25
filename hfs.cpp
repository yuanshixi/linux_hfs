#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <utility>
#include <string>
#include <map>
#include <array>
#include <thread>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <stdexcept>
#include <exception>
#include <system_error>
#include <cerrno>
#include <cstdint>
#include <cstring>

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
constexpr uint32_t MAX_HTTP_METHOD_LENGTH = 32;
constexpr uint32_t MAX_HTTP_URL_LENGTH = 1024;
constexpr uint32_t MAX_HTTP_VERSION_LENGTH = 32;
constexpr uint32_t MAX_HTTP_HEADERS_NUM = 32;

std::string DEFAULT_HTML_HEADER = "<!DOCTYPE HTML PUBLIC -//W3C//DTD HTML 4.01//EN"
				                    "http://www.w3.org/TR/html4/strict.dtd>"
				                    "<html><head>"
				                    R"(<meta http-equiv="Content-Type")"
				                    R"(content="text/html; charset=UTF-8">)"
				                    "<title>File Server</title></head>"
				                    "<body><h1>File Server</h1>"
                                    R"(<form id="uploadForm" action="http://)"
                                    "#ip_port"
                                    R"(/upload_files" method="POST" enctype="multipart/form-data">)"
                                    R"(<input type="file" id="fileInput" name="fileInput" />)"
                                    R"(<button type="submit">Upload</button>)"
                                    "</form>"
				                    "<hr><ul>";

constexpr const char* DEFAULT_HTML_END = "</ul><hr></body></html>";

volatile sig_atomic_t running = 1;
std::mutex output_mut;   // avoid output confusion.

void handle_signal_int(int sigum) {
	running = 0;
}

void setting_signals() {
	struct sigaction actionSIGINT;
    actionSIGINT.sa_handler = handle_signal_int;
    actionSIGINT.sa_flags = 0;
    sigemptyset(&(actionSIGINT.sa_mask));

    if (sigaction(SIGINT, &actionSIGINT, nullptr) < 0) {	
		throw std::system_error(errno, std::system_category(), "sigaction() for `sigint` failed, can't setting signal");
    }

	// if we cancel send() with large data, this would make send() immediately, otherwise the whole program would terminated.
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		throw std::system_error(errno, std::system_category(), "ignore `SIGPIPE` failed, can't setting signal");
	}
}

int try_parse_port(const char* param) {
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

bool is_dir(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == -1) {
        return false;
    }

    return S_ISDIR(st.st_mode);
}

bool is_regular_file(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == -1) {
        return false;
    }

    return S_ISREG(st.st_mode);
}

std::vector<std::string> string_split(const std::string& str, const std::string& pattern) {
    std::vector<std::string> vec;
    std::string tempStr;
    size_t begin = 0;
    size_t pos = 0;

    while (true) {
        pos = str.find(pattern, begin);

        if (pos == std::string::npos) {
            tempStr = str.substr(begin);

            if (tempStr != "") {
                vec.emplace_back(std::move(tempStr));
            }
        
            break;
        }
        else {
            tempStr = str.substr(begin, pos - begin);
            
            if (tempStr != "") {
                vec.emplace_back(std::move(tempStr));
            }

            begin = pos + pattern.length();
        }
    }

    return vec;
}

int hex_to_decimal(char c) noexcept {
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

void reverse_string(std::string& str) {
	size_t len = str.length();

	for (size_t i = 0; i < len / 2; ++i) {
		std::swap(str[i], str[len - 1 - i]);
	}
}

std::string int_to_hex_str(int number) {
	std::string result;

	while (number > 0) {
		int remainder = number % 16;

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

bool compare_string_ignore_case(const std::string& left, const std::string& right) {
	if (left.length() != right.length()) {
		return false;
	}

	for (size_t i = 0; i < left.length(); ++i) {
		if (tolower(left[i]) != tolower(right[i])) {
			return false;
		}
	}

	return true;
}

std::string file_size_to_str(float fileSize) {
	int level = 0;

	while (true) {
		if (fileSize / 1024.0 < 0.01f || level == 4) {   // float compare to 0 should be careful.
			break;
		}
		else {
			fileSize = fileSize / 1024.0;
			++level;
		}
	}

	std::ostringstream oss;
	oss << std::fixed << std::setprecision(2) << fileSize;

	switch(level) {
		case 0:
			return oss.str() + " B";
		case 1:
			return oss.str() + " KB";
		case 2:
			return oss.str() + " MB";
		case 3:
			return oss.str() + " GB";
		case 4:
		default:
			return oss.str() + " TB";
	}
}

struct Request {
    std::string method;
    std::string url;
    std::string version;
    std::map<std::string, std::string> headers;
};

struct Response {
    std::string version;
    uint32_t code;
    std::string msg;
    std::map<std::string, std::string> headers;
    std::string body;

    std::string to_str() {
        std::string str;

        str += version;
        str += " ";
        str += std::to_string(code);
        str += " ";
        str += msg;
        str += "\r\n";

        for (const auto& item : headers) {
            str += item.first;
            str += ": ";
            str += item.second;
            str += "\r\n";
        }

        str += "\r\n";
        str += body;
        return str;
    }
};

/*
    Thread pool.
    This thread pool ignores the return value, so you have to push some functions like: void my_func(void);
    Drawing inspiration from Jakob Progschj and yhirose's thread pool implementation.
*/
class ThreadPool {
    std::queue<std::function<void()>> taskQueue;
    std::vector<std::thread> workers;
    std::mutex mut;
    std::condition_variable cv;
public:
    explicit ThreadPool(size_t numOfWorkers) {
        for (size_t i = 0; i < numOfWorkers; ++i) {
            workers.emplace_back([this]() {
                while (running) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock{ mut };
                        cv.wait(lock, [this]() { return !running || !taskQueue.empty(); });

                        if (!running && taskQueue.empty()) {
                            return;
                        }

                        task = std::move(taskQueue.front());
                        taskQueue.pop();
                    }

                    task();
                }
            });
        }
    }

    ThreadPool() : ThreadPool{ std::thread::hardware_concurrency() } {}

    ~ThreadPool() noexcept {
        {
            std::lock_guard<std::mutex> lock{ mut };
            running = false;
        }

        cv.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
    }

    void add_task(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock{ mut };
            taskQueue.emplace(std::move(task));
        }

        cv.notify_one();
    }
};

struct MimeTypeMapping {
    const char* extension;
    const char* mimeType;
} mimeTypeMap[] = 
{
    {  "bmp", "image/bmp" },
    {    "c", "text/plain" },
    {  "cpp", "text/plain" },
    {  "gif", "image/gif" },
    {  "htm", "text/html" },
    { "html", "text/html" },
    {  "ico", "image/x-icon" },
    { "jpeg", "image/jpeg" },
    {  "jpg", "image/jpeg" },
    {   "js", "application/javascript"},
    {  "log", "text/plain" },
    {  "pdf", "application/pdf" },
    {  "pic", "image/pict" },
    {  "png", "image/png" },
    {   "py", "text/plain" },
    {  "txt", "text/plain" }
};

std::string extension_to_mime_type(const std::string& extension) {
    int low = 0;
    int high = sizeof(mimeTypeMap) / sizeof(MimeTypeMapping) - 1;

    while (low <= high) {
        int mid = low + (high - low) / 2;

        if (extension > mimeTypeMap[mid].extension) {
            low = mid + 1;
        }
        else if (extension < mimeTypeMap[mid].extension) {
            high = mid - 1;
        }
        else {
            return mimeTypeMap[mid].mimeType;
        }
    }

    return "text/plain";
}

class Connection {
    int fd;
    std::string info;   // ip:port
    std::string rootPath;

    void init_connection_info() {
        char ip[INET6_ADDRSTRLEN];
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);

        if (getpeername(fd, (struct sockaddr*)(&addr), &len) != 0) {
			throw std::system_error(errno, std::system_category(), "getpeername() failed");
        }

        if (inet_ntop(addr.sin_family, &(addr.sin_addr), ip, INET6_ADDRSTRLEN) == nullptr) {
            throw std::system_error(errno, std::system_category(), "inet_ntop() failed");
        }

        info += ip;
        info += ":";
        info += std::to_string(ntohs(addr.sin_port));
    }

    bool decode_percent_encoding_url(Request& req) {
        std::string temp;

        for (size_t i = 0; i < req.url.length(); ) {
            if (req.url[i] == '%') {
                if (i + 2 >= req.url.length()) {
                    return false;
                }

                int p1 = hex_to_decimal(req.url[i + 1]);
                int p2 = hex_to_decimal(req.url[i + 2]);

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

        req.url = temp;
        return true;
    }

	void setting_recv_timeout() {
		struct timeval timeout;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			throw std::system_error(errno, std::system_category(), "setsockopt() failed on `SO_RCVTIMEO` for " + info);
		}
	}

    std::string build_response_template(uint32_t code, const std::string& msg) {
        Response res;

        res.version = "HTTP/1.1";
        res.code = code;
        res.msg = msg;
        res.body = "<html><head><h1>" + std::to_string(code) + "</h1></head><body>" + msg + "</body></html>";

        res.headers.emplace("Content-Type", "text/html");
        res.headers.emplace("Content-Length", std::to_string(res.body.length()));

        return res.to_str();
    }

    int do_send(const char* str, int len) {
		int writeLen = ::send(fd, str, len, 0);

		if (writeLen < 0) {
			throw std::system_error(errno, std::system_category(), "send() failed for " + info);
		}

		return writeLen;
    }

    void do_send(const std::string& responseStr) {
        do_send(responseStr.c_str(), responseStr.length());
    }

    void print_brief_request(const Request& req) {
        std::lock_guard<std::mutex> lock(output_mut);
        std::cout << info << " " << req.method << " " << req.url << "\n";
    }

    std::string get_extension(const std::string& path) {
        size_t pos = path.find_last_of(".");
        
        if (pos == std::string::npos) {
            return "";
        }
        else {
            return path.substr(pos + 1);
        }
    }

    std::string concat_url_path(const std::string& url, const char* entryName) {
        if (url.back() != '/') {
            if (entryName[0] == '/') {
               return url + entryName;
            }
            else {
                return url + "/" + entryName;
            }
        }
        else {
            if (entryName[0] == '/') {
                ++entryName;
               return url + entryName;
            }
            else {
                return url + entryName;
            }
        }
    }

    void build_file_list(const std::string& path, std::string& body, const std::string& url) {
        DIR* dir;
        struct dirent* entry;
		struct stat st;

        dir = opendir(path.c_str());
        if (dir == nullptr) {
			throw std::system_error(errno, std::system_category(), "opendir() failed for " + info);
        }

        body += DEFAULT_HTML_HEADER;

        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name == std::string{ "." } || entry->d_name == std::string{ ".." }) {
                continue;
            }

			std::string completePath = rootPath + concat_url_path(url, entry->d_name);
			if (stat(completePath.c_str(), &st) == -1) {
        		continue;
    		}

            body += "<li><a href=\"";
            body += concat_url_path(url, entry->d_name);
            body += "\">";

			if (S_ISDIR(st.st_mode)) {
				body += "/";
			}

            body += entry->d_name;

			if (S_ISREG(st.st_mode)) {
				body += "</a><span>&nbsp;&nbsp;";
				body += file_size_to_str(st.st_size);
				body += "</span></li>\n";
			}
			else {
				body += "</a></li>\n";
			}
        }

        closedir(dir);
        body += DEFAULT_HTML_END;
    }

    void send_file_list(const std::string& path, const std::string& url) {
        Response res;

        build_file_list(path, res.body, url);
        res.version = "HTTP/1.1";
        res.code = 200;
        res.msg = "OK";
        res.headers.emplace("Content-Type", "text/html; charset=utf-8");
        res.headers.emplace("Content-Length", std::to_string(res.body.length()));

        std::string responseStr = res.to_str();
        do_send(responseStr);
    }

    void send_file(const std::string& path, const std::string& url) {
        std::string extension = get_extension(url);
        std::string mimeType = extension_to_mime_type(extension);

        Response res;
        res.version = "HTTP/1.1";
        res.code = 200;
        res.msg = "OK";

        res.headers.emplace("Content-Type", mimeType);
        res.headers.emplace("Transfer-Encoding", "chunked");

        std::string responseStr = res.to_str();
        do_send(responseStr);

        std::ifstream in(path, std::ios::binary);
        std::array<char, 1024> buf;
        while (!in.eof()) {
            in.read(buf.data(), 1024);
            int len = in.gcount();
            
            do_send(int_to_hex_str(len));
            do_send("\r\n");
            do_send(buf.data(), len);
            do_send("\r\n");
        }

        do_send("0\r\n\r\n");
    }

    void handle_files(const Request& req) {
        std::string completePath = rootPath + req.url;

        if (is_dir(completePath)) {
            send_file_list(completePath, req.url);
        }
        else if (is_regular_file(completePath)) {
            send_file(completePath, req.url);
        }
        else {
            std::string responseStr = build_response_template(404, "Not Found");
            do_send(responseStr);
        }
    }

    std::string parse_boundary(const Request& req) {
        const std::string pattern = "boundary=";
        const std::string& value = req.headers.at("Content-Type");
        return value.substr(value.find(pattern) + pattern.length());
    }

    void try_parse_filename(std::string&& str, std::string& fileName) {
        const std::string pattern = "filename=\"";
        size_t pos = str.find(pattern);

        if (pos != std::string::npos) {
            pos += pattern.length();

            while (str[pos] != '"') {
                fileName += str[pos];
                ++pos;
            }
        }
    }

    void handle_upload(const Request& req) {
        uint64_t length = std::stoll(req.headers.at("Content-Length"));
        std::string boundary = parse_boundary(req);
        std::string responseStr;
        std::string fileName;
        int n;

        // first, parse --boundary
        std::array<char, 8192> buf;
        while (true) {
            n = read_line(buf);
            length -= (n + 2);

            if (fileName.length() == 0) {
                try_parse_filename(std::string(buf.data(), n), fileName);
            }

            if (n == 0) {
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock{ output_mut };
            std::cout << "save file `" << fileName << "`\n";
        }

        std::ofstream out{ fileName, std::ios::binary };

        // after file data, there is a \r\n, and a --boundary--\r\n
        while (length > boundary.length() + 8) {
            n = ::recv(fd, buf.data(), length - boundary.length() - 8, 0);
            length -= n;

            out.write(buf.data(), n);
        }

        out.close();

        read_line(buf);
        read_line(buf);
        responseStr = build_response_template(200, "OK");
        do_send(responseStr);
    }

    template<size_t N>
    int read_line(std::array<char, N>& buf) {
        int numOfRecvBytes = 0;
        int n;
        char c;

        while (numOfRecvBytes < N) {
            n = ::recv(fd, &c, 1, 0);

            if (n <= 0) {
                return -1;
            }
            else {
                if (c == '\r') {
                    n = ::recv(fd, &c, 1, MSG_PEEK);
                    
                    if (n <= 0) {
                        return -1;
                    }
                    else {
                        if (c == '\n') {
                            ::recv(fd, &c, 1, 0);
                            break;
                        }
                        else {
                            return -1;
                        }
                    }
                }
                else {
                    buf[numOfRecvBytes] = c;
                    numOfRecvBytes += 1;
                }
            }
        }

        return c == '\n' ? numOfRecvBytes : -1;
    }

    template<size_t N>
    void parse_method_url_version(const std::array<char, N>& buf, int length, Request& req) {
        int i = 0;

        while (buf[i] != ' ') {
            req.method += buf[i];
            ++i;
        }

        ++i;
        while (buf[i] != ' ') {
            req.url += buf[i];
            ++i;
        }

        ++i;
        while (i < length) {
            req.version += buf[i];
            ++i;
        }
    }

    template<size_t N>
    void save_one_http_header(const std::array<char, N>& buf, int length, Request& req) {
        std::string key;
        std::string value;
        int i = 0;

        while (buf[i] != ':') {
            key += buf[i];
            ++i;
        }

        i += 2;
        while (i < length) {
            value += buf[i];
            ++i;
        }

        req.headers.emplace(std::move(key), std::move(value));
    }

    void handle_recv() {
        std::array<char, MAX_HTTP_REQUEST_LENGTH> buf;
        std::string responseStr;
        Request req;
        int n;

        n = read_line(buf);
        if (n < 0) {
            return;
        }

        parse_method_url_version(buf, n, req);
        if (!decode_percent_encoding_url(req)) {
            responseStr = build_response_template(400, "Bad Request");
            do_send(responseStr);
            return;
        }

        print_brief_request(req);

        while (true) {
            n = read_line(buf);

            if (n < 0) {
                return;
            }
            else if (n == 0) {
                break;
            }

            if (req.headers.size() == MAX_HTTP_HEADERS_NUM) {
                responseStr = build_response_template(400, "Bad Request");
                do_send(responseStr);
                return;
            }

            save_one_http_header(buf, n, req);
        }

        if (compare_string_ignore_case(req.method, "GET")) {
            handle_files(req);
        }
        else if (compare_string_ignore_case(req.method, "POST")) {
            handle_upload(req);
        }
        else {
            responseStr = build_response_template(405, "Method Not Allowed");
            do_send(responseStr);
        }
    }
public:
    Connection(int _fd, const char* _rootPath) : fd{ _fd }, rootPath{ _rootPath } {
        if (rootPath.back() == '/') {
            rootPath.pop_back();
        }
    }

    ~Connection() noexcept {
        if (fd != -1) {
            close(fd);
        }
    }

    void handle() noexcept {
        try {
            init_connection_info();
            setting_recv_timeout();
            handle_recv();
        }
        catch(const std::exception& e) {
			std::lock_guard<std::mutex> lock{ output_mut };
			std::cerr << e.what() << "\n";
		}
    }
};

class HttpFileServer {
    int fd;
    ThreadPool pool;

    void bind_ip_port(const std::string& ip, uint16_t& port) {
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

        while (::bind(fd, (const struct sockaddr*)(&addr), sizeof(addr)) != 0) {
            if (port == 65535) {
                throw std::system_error(errno, std::system_category(), "bind() failed");
            }
            else {
                port += 1;
                addr.sin_port = htons(port);
            }
        }

        if (::listen(fd, 32) != 0) {
            throw std::system_error(errno, std::system_category(), "listen() failed");
        }

        int option = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)(&option), sizeof(option)) < 0) {
			throw std::system_error(errno, std::system_category(), "setsockopt() on `SO_REUSEADDR` failed");
        }

        std::cout << "server listen on " << port << "\n";
    }

    // see https://stackoverflow.com/questions/212528/how-can-i-get-the-ip-address-of-a-linux-machine
    std::string get_local_ip() {
        struct ifaddrs* ifaddr;
        struct ifaddrs* cursor;
        char ip[INET6_ADDRSTRLEN];

        if (getifaddrs(&ifaddr) != 0) {
            throw std::system_error(errno, std::system_category(), "getifaddrs() failed");
        }

        for (cursor = ifaddr; cursor != nullptr; cursor = cursor->ifa_next) {
            if (cursor->ifa_addr->sa_family == AF_INET) {   // ignore ipv6.
                struct sockaddr_in* sockaddr = (struct sockaddr_in*)(cursor->ifa_addr);

                if (inet_ntop(AF_INET, &(sockaddr->sin_addr), ip, INET6_ADDRSTRLEN) == nullptr) {
                    freeifaddrs(ifaddr);
                    throw std::system_error(errno, std::system_category(), "inet_ntop() failed");
                }

                // ignore the 127.0.0.1 or 172.xxx.xxx.xxx
                if (strstr(ip, "127") == nullptr && strstr(ip, "172") == nullptr) {
                    break;
                }
            }
        }
        
        freeifaddrs(ifaddr);
        return std::string{ ip };
    }

    void modify_html_header(uint16_t port) {
        const std::string pattern = "#ip_port";
        std::string ip_port = get_local_ip() + ":" + std::to_string(port);

        auto pos = DEFAULT_HTML_HEADER.find(pattern);
        if (pos == std::string::npos) {
            throw std::runtime_error("invalid html header, lose `#ip_port`");
        }

        DEFAULT_HTML_HEADER.replace(pos, pattern.length(), ip_port);
    }
public:
    HttpFileServer() : fd{ -1 } {
		fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
            throw std::system_error(errno, std::system_category(), "socket() failed");
        }
	}

    ~HttpFileServer() noexcept {
        if (fd != -1) {
            close(fd);
        }
    }

    void serve(const std::string& ip, uint16_t port, const char* rootPath) {
        bind_ip_port(ip, port);   // port will be modified.
        modify_html_header(port);

		while (running) {
			int client = ::accept(fd, nullptr, nullptr);
			if (client < 0) {
				if (errno == EINTR) {
					return;
				}
				else {
					throw std::system_error(errno, std::system_category(), "accept() failed");
				}
			}

			pool.add_task([client, rootPath]() {
				Connection conn{ client, rootPath };
				conn.handle();
			});
		}
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <root_dir>\n";
        return 1;
    }

    int port = try_parse_port(argv[1]);
    if (port < 0) {
        std::cerr << "`" << argv[1] << "` is not a valid port\n";
        return 1;
    }

    if (!is_dir(argv[2])) {
        std::cerr << "`" << argv[2] << "` is not a valid directory path\n";
        return 1;
    }

	try {
		setting_signals();

    	HttpFileServer hfs;
    	hfs.serve("0.0.0.0", port, argv[2]);
	}
	catch(const std::exception& e) {
		std::cerr << e.what() << "\n";
	}

    std::cout << "server exit\n";
    return 0;
}
