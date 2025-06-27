#pragma once

#define CURL_STATICLIB

#include <fstream>
#include <string>
#include <vector>
#include <curl/curl.h>

#include "sha256/sha256.hpp"
#include "json.hpp"
#include "xor.hpp"
#include "skCrypter.h"

#include "hwid_utils.hpp"
#include "cacert.hpp"

//Libraries
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

using json = nlohmann::json;

extern const uint8_t ca_cert[];

struct response_t
{
	std::string unix_expire_time;
	bool valid;
	std::string message;
};

class authlib
{
private:

	bool authorized = false;
	std::string link{};
	std::string application_name{};
	std::string api_public_key {};
	std::string cert_hash{};
	std::string ca_cert_path;

public:

	authlib();
	~authlib();
	
	bool init(std::string application_name, std::string api_public_key, std::string link);

	std::string get_hwid_string();
	std::string get_hwid_hash();

	bool auth(const std::string& key, response_t& result);

	std::vector<uint8_t> download_file(int file_id, const std::string& key);
	
	bool ban_key(const std::string& key);

	bool create_ca_cert();
	bool delete_ca_cert();

	bool is_authorized();
};
