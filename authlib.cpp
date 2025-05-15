#include "authlib.hpp"




authlib::authlib()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	this->curl = curl_easy_init();
	create_ca_cert();
}

authlib::~authlib()
{
	curl_easy_cleanup(this->curl);
	curl_global_cleanup();
	delete_ca_cert();
}

bool authlib::init(std::string application_name, std::string api_public_key, std::string link)
{
	this->application_name = application_name;
	this->api_public_key = api_public_key;
	this->link = link;
	return true;
}
std::string authlib::get_hwid_string()
{
	std::string buffer;
	buffer += hwid_utils::get_user_cid();

	for (auto i : hwid_utils::get_disk_serials())
	{
		buffer += i;
	}
	buffer += hwid_utils::get_gpu_serial();
	for (auto i : hwid_utils::get_ram_serial())
	{
		buffer += i;
	}

	buffer += hwid_utils::get_cpu_serial();
	return buffer;
}

std::string authlib::get_hwid_hash()
{
	std::string buffer;
	buffer += hwid_utils::get_user_cid();
	buffer += hwid_utils::get_cpu_serial();
	for (auto i : hwid_utils::get_disk_serials())
	{
		buffer += i;
	}
	buffer += hwid_utils::get_gpu_serial();
	for (auto i : hwid_utils::get_ram_serial())
	{
		buffer += i;
	}

	buffer += hwid_utils::get_cpu_serial();

	std::string hash = picosha2::hash256_hex_string(buffer);
	buffer.clear();
	return hash;
	
}

bool authlib::auth(const std::string& key, responce_t& result)
{
	
	json j;
	auto key_str = skCrypt("key");
	auto application_name = skCrypt("application_name");
	auto hardware_id_hash = skCrypt("hardware_id_hash");
	j[key_str.decrypt()] = key;
	j[application_name.decrypt()] = this->application_name;
	j[hardware_id_hash.decrypt()] = get_hwid_hash();

	key_str.clear();
	application_name.clear();
	hardware_id_hash.clear();

	std::string json_str = j.dump(); // сериализуем в строку

	std::string auth_link = this->link + skCrypt("/api/validate_key").decrypt();

	curl_easy_setopt(curl, CURLOPT_URL, auth_link.c_str());

	curl_easy_setopt(curl, CURLOPT_CAINFO, this->ca_cert_path.c_str());
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, skCrypt("sha256//oGwi7ILV7mhHVD+xEhgSLR+D0UiBNsRsDdk9AVPh6XQ=").decrypt());
	// 4. Заголовки
	struct curl_slist* headers = nullptr;
	std::string content_type = skCrypt("Content-Type: application/json").decrypt();
	std::string pathology_header = skCrypt("pathology: ").decrypt() + this->api_public_key;

	headers = curl_slist_append(headers, content_type.c_str());
	headers = curl_slist_append(headers, pathology_header.c_str());

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// 5. Тело запроса
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

	// 6. Вывод ответа (опционально)
	std::string response_str;

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
	std::string* response = static_cast<std::string*>(userdata);
	response->append(ptr, size * nmemb);
		return size * nmemb;
	});


	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);

	// 7. Выполняем запрос
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		std::cerr << skCrypt("curl_easy_perform() failed: ") << curl_easy_strerror(res) << std::endl;
	}

	try {
		auto response_json = json::parse(response_str);
		std::string exipre_date = skCrypt("expire_date").decrypt();
		std::string valid = skCrypt("valid").decrypt();
		std::string message = skCrypt("message").decrypt();

		if (response_json.contains(exipre_date.c_str()))
			result.unix_expire_time = response_json[exipre_date].get<std::string>();

		if (response_json.contains(valid.c_str()))
			result.valid = response_json[valid].get<bool>();

		if (response_json.contains(message.c_str()))
			result.message = response_json[message].get<std::string>();

	}
	catch (const std::exception& e) {
		std::cerr << ("Failed to parse server response: ") << e.what() << std::endl;
		return false;
	}

	// 8. Освобождаем ресурсы
	curl_slist_free_all(headers);

	return true;
}

std::vector<uint8_t> authlib::download_file(int file_id, const std::string& key)
{
	std::vector<uint8_t> file_data;
	json j;

	auto key_str = skCrypt("key");
	auto application_name = skCrypt("application_name");
	auto hardware_id_hash = skCrypt("hardware_id_hash");
	auto file_id_str = skCrypt("file_id");
	j[key_str.decrypt()] = key;
	j[application_name.decrypt()] = this->application_name;
	j[hardware_id_hash.decrypt()] = get_hwid_hash();
	j[file_id_str.decrypt()] = file_id;

	key_str.clear();
	application_name.clear();
	hardware_id_hash.clear();
	file_id_str.clear();


	std::string json_str = j.dump();

	CURL* curl = curl_easy_init();
	if (!curl) {
		std::cerr << skCrypt("Failed to initialize CURL\n");
		return file_data;
	}
	auto api_download_file = skCrypt("/api/download_file");
	std::string download_link = this->link + api_download_file.decrypt();

	curl_easy_setopt(curl, CURLOPT_URL, download_link.c_str()); // или this->link, если URL один
	curl_easy_setopt(curl, CURLOPT_CAINFO, this->ca_cert_path.c_str());
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, skCrypt("sha256//oGwi7ILV7mhHVD+xEhgSLR+D0UiBNsRsDdk9AVPh6XQ=").decrypt());


	// Заголовки
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, skCrypt("Content-Type: application/json").decrypt());
	headers = curl_slist_append(headers, (skCrypt("pathology: ").decrypt() + this->api_public_key).c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// POST-данные
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

	// Буфер для записи бинарных данных
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
		auto* vec = static_cast<std::vector<uint8_t>*>(userdata);
		vec->insert(vec->end(), ptr, ptr + size * nmemb);
		return size * nmemb;
		});
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file_data);

	// Выполнение запроса
	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		std::cerr << skCrypt("curl_easy_perform() failed: ") << curl_easy_strerror(res) << "\n";
		file_data.clear(); // сброс в случае ошибки
	}

	// Очистка
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return file_data;
}


bool authlib::ban_key(const std::string& key)
{
	json j;
	auto key_str = skCrypt("key");
	j[key_str.decrypt()] = key;

	std::string json_str = j.dump();
	std::string ban_link = this->link + skCrypt("/api/ban_key").decrypt();

	curl_easy_setopt(curl, CURLOPT_URL, ban_link.c_str());
	curl_easy_setopt(curl, CURLOPT_CAINFO, this->ca_cert_path.c_str());
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, skCrypt("sha256//oGwi7ILV7mhHVD+xEhgSLR+D0UiBNsRsDdk9AVPh6XQ=").decrypt());

	struct curl_slist* headers = nullptr;
	std::string content_type = skCrypt("Content-Type: application/json").decrypt();
	std::string validation_key = skCrypt("validation_key: ").decrypt() + this->api_public_key;

	headers = curl_slist_append(headers, content_type.c_str());
	headers = curl_slist_append(headers, validation_key.c_str());

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

	std::string response_str;

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
		std::string* response = static_cast<std::string*>(userdata);
		response->append(ptr, size * nmemb);
		return size * nmemb;
		});

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);

	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		std::cerr << skCrypt("curl_easy_perform() failed: ").decrypt() << curl_easy_strerror(res) << std::endl;
		curl_slist_free_all(headers);
		return false;
	}

	curl_slist_free_all(headers);

	return true;
}

bool authlib::create_ca_cert()
{
	char temp_path[MAX_PATH] = "";

	GetTempPathA(sizeof(temp_path), temp_path);

	auto file_name = skCrypt("cacert.pem").decrypt();

	this->ca_cert_path = std::string(temp_path) + file_name;

	std::ofstream file(this->ca_cert_path, std::ios::binary);
	
	file.write((char*)ca_cert, sizeof(ca_cert));

	return true;
}

bool authlib::delete_ca_cert()
{
	return std::remove(this->ca_cert_path.c_str()) == 0;
}
