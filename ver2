#ifndef TELEGRAM_BOT_HPP
#define TELEGRAM_BOT_HPP

#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <regex>
#include <thread>
#include <unordered_set>
#include <vector>
#include <random>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

// Константы
const int DEFAULT_MESSAGE_QUEUE_SIZE = 1000;
const int DEFAULT_WORKER_THREADS = 4;
const int DEFAULT_MAX_PROCESSED_MESSAGES = 10000;
const int DEFAULT_STATE_BACKUP_INTERVAL = 3600;
const int METRICS_PRINT_INTERVAL = 60;
const int AES_KEY_SIZE = 32; // 256 бит
const int AES_BLOCK_SIZE = 16; // 128 бит

// Перечисления
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

// Предварительные объявления
class ITelegramBot;

// Структура конфигурации
struct Config {
    std::string encryptedBotToken;
    std::string targetGroup;
    std::vector<std::pair<std::string, std::regex>> keywords;
    std::vector<int64_t> adminChatIds;
    std::string logFile;
    int messageQueueSize;
    int workerThreads;
    int maxProcessedMessages;
    int stateBackupInterval;
    LogLevel logLevel;

    // Загрузка конфигурации из файла
    void load(const std::string& filename) {
        std::ifstream configFile(filename);
        if (!configFile.is_open()) {
            throw std::runtime_error("Не удается открыть файл конфигурации");
        }

        json j;
        configFile >> j;
        encryptedBotToken = j["encryptedBotToken"];
        targetGroup = j["targetGroup"];
        adminChatIds = j["adminChatIds"].get<std::vector<int64_t>>();
        logFile = j["logFile"];
        messageQueueSize = j.value("messageQueueSize", DEFAULT_MESSAGE_QUEUE_SIZE);
        workerThreads = j.value("workerThreads", DEFAULT_WORKER_THREADS);
        maxProcessedMessages = j.value("maxProcessedMessages", DEFAULT_MAX_PROCESSED_MESSAGES);
        stateBackupInterval = j.value("stateBackupInterval", DEFAULT_STATE_BACKUP_INTERVAL);
        logLevel = static_cast<LogLevel>(j.value("logLevel", static_cast<int>(LogLevel::INFO)));

        keywords.clear();
        for (const auto& kw : j["keywords"]) {
            keywords.emplace_back(kw["word"].get<std::string>(), std::regex(kw["regex"].get<std::string>(), std::regex::icase));
        }
    }
};

// Структура сообщения
struct Message {
    int64_t chatId;
    std::string text;
    std::string username;
    int64_t messageId;
};

// Структура метрик
struct Metrics {
    std::atomic<uint64_t> messagesProcessed{ 0 };
    std::atomic<uint64_t> keywordsFound{ 0 };
    std::atomic<uint64_t> notificationsSent{ 0 };
    std::chrono::steady_clock::time_point startTime;
};

// Потокобезопасная очередь
template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue;
    mutable std::mutex mutex;
    std::condition_variable cond;
    std::atomic<bool> done{ false };

public:
    void push(const T& value) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            queue.push(value);
        }
        cond.notify_one();
    }

    bool pop(T& value) {
        std::unique_lock<std::mutex> lock(mutex);
        cond.wait(lock, [this] { return !queue.empty() || done; });
        if (queue.empty()) {
            return false;
        }
        value = std::move(queue.front());
        queue.pop();
        return true;
    }

    void stop() {
        done = true;
        cond.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.size();
    }
};

// Логгер
class Logger {
public:
    explicit Logger(const std::string& logFile, LogLevel level)
        : logFile_(logFile), logLevel_(level) {}

    void log(LogLevel severity, const std::string& message) {
        if (severity >= logLevel_) {
            std::lock_guard<std::mutex> lock(mutex_);

            std::ofstream logFile(logFile_, std::ios::app);
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            char timeBuffer[26];
            std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now_c));

            std::string severityStr;
            switch (severity) {
                case LogLevel::DEBUG: severityStr = "DEBUG"; break;
                case LogLevel::INFO: severityStr = "INFO"; break;
                case LogLevel::WARNING: severityStr = "WARNING"; break;
                case LogLevel::ERROR: severityStr = "ERROR"; break;
            }

            std::string logEntry = std::string(timeBuffer) + " [" + severityStr + "] " + message;
            logFile << logEntry << std::endl;
            std::cout << logEntry << std::endl;
        }
    }

    void setLogLevel(LogLevel level) {
        logLevel_ = level;
    }

private:
    std::string logFile_;
    LogLevel logLevel_;
    std::mutex mutex_;
};

// Интерфейс бота Telegram
class ITelegramBot {
public:
    virtual ~ITelegramBot() = default;
    virtual void sendMessage(int64_t chatId, const std::string& message) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void onAnyMessage(const std::function<void(const Message&)>& callback) = 0;
    virtual void onCommand(const std::string& command, const std::function<void(const Message&)>& callback) = 0;
};

// Шифратор
class Encryptor {
public:
    static std::string encrypt(const std::string& plaintext, const std::string& key) {
        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        RAND_bytes(iv.data(), AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv.data());

        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;

        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        std::string result(reinterpret_cast<char*>(iv.data()), AES_BLOCK_SIZE);
        result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        return result;
    }

    static std::string decrypt(const std::string& ciphertext, const std::string& key) {
        if (ciphertext.size() <= AES_BLOCK_SIZE) {
            throw std::runtime_error("Слишком короткий зашифрованный текст");
        }

        std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv.data());

        std::vector<unsigned char> plaintext(ciphertext.size() - AES_BLOCK_SIZE);
        int len = 0, plaintext_len = 0;

        EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str() + AES_BLOCK_SIZE), ciphertext.size() - AES_BLOCK_SIZE);
        plaintext_len = len;

        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }
};

// Реализация бота Telegram
class TelegramBot : public ITelegramBot {
public:
    TelegramBot(const std::string& encryptedToken, const std::string& encryptionKey) 
        : encryptedBotToken_(encryptedToken), encryptionKey_(encryptionKey) {
        try {
            botToken_ = Encryptor::decrypt(encryptedBotToken_, encryptionKey_);
        } catch (const std::exception& e) {
            throw std::runtime_error("Ошибка расшифровки токена бота: " + std::string(e.what()));
        }
    }

    void sendMessage(int64_t chatId, const std::string& message) override {
        std::string url = "https://api.telegram.org/bot" + botToken_ + "/sendMessage";
        std::string postData = "chat_id=" + std::to_string(chatId) + "&text=" + curl_easy_escape(curl, message.c_str(), message.size());

        CURLcode res;
        try {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                throw std::runtime_error("Не удалось отправить сообщение: " + std::string(curl_easy_strerror(res)));
            }
        } catch (const std::exception& e) {
            throw std::runtime_error("Ошибка отправки сообщения: " + std::string(e.what()));
        }
    }

    void start() override {
        running_ = true;
        pollingThread_ = std::thread(&TelegramBot::poll, this);
    }

    void stop() override {
        running_ = false;
        if (pollingThread_.joinable()) {
            pollingThread_.join();
        }
    }

    void onAnyMessage(const std::function<void(const Message&)>& callback) override {
        onAnyMessageCallback_ = callback;
    }

    void onCommand(const std::string& command, const std::function<void(const Message&)>& callback) override {
        commandCallbacks_[command] = callback;
    }

private:
    void poll() {
        while (running_) {
            std::string url = "https://api.telegram.org/bot" + botToken_ + "/getUpdates?timeout=10";
            CURLcode res;
            try {
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString_);

                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    throw std::runtime_error("Ошибка опроса: " + std::string(curl_easy_strerror(res)));
                }

                auto updates = json::parse(responseString_);
                handleUpdates(updates);
            } catch (const std::exception& e) {
                std::cerr << "Ошибка в процессе опроса: " << e.what() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }

    void handleUpdates(const json& updates) {
        try {
            for (const auto& update : updates["result"]) {
                if (update.contains("message")) {
                    const auto& message = update["message"];
                    Message msg{message["chat"]["id"].get<int64_t>(), message["text"].get<std::string>(), message["from"]["username"].get<std::string>(), message["message_id"].get<int64_t>()};

                    if (message.contains("text") && !message["text"].get<std::string>().empty()) {
                        std::string text = message["text"].get<std::string>();
                        if (text[0] == '/') {
                            auto spacePos = text.find(' ');
                            std::string command = text.substr(1, spacePos - 1);
                            if (commandCallbacks_.find(command) != commandCallbacks_.end()) {
                                commandCallbacks_[command](msg);
                            }
                        } else {
                            if (onAnyMessageCallback_) {
                                onAnyMessageCallback_(msg);
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Ошибка обработки обновлений: " << e.what() << std::endl;
        }
    }

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
        s->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    CURL* curl = curl_easy_init();
    std::string encryptedBotToken_;
    std::string encryptionKey_;
    std::string botToken_;
    std::thread pollingThread_;
    std::atomic<bool> running_{false};
    std::function<void(const Message&)> onAnyMessageCallback_;
    std::unordered_map<std::string, std::function<void(const Message&)>> commandCallbacks_;
    std::string responseString_;
};

// Управляющий ботом класс
class BotManager {
public:
    BotManager(std::unique_ptr<ITelegramBot> bot, const Config& config, std::shared_ptr<Logger> logger)
        : bot_(std::move(bot)), config_(config), logger_(std::move(logger)) {
        metrics_.startTime = std::chrono::steady_clock::now();
        initializeRateLimiter();
    }

    void run() {
        setupHandlers();
        startWorkers();
        startMetricsThread();
        startBackupThread();

        logger_->log(LogLevel::INFO, "Бот запущен");
        try {
            bot_->sendMessage(config_.adminChatIds[0], "Бот запущен");
        } catch (const std::exception& e) {
            logger_->log(LogLevel::ERROR, "Ошибка отправки сообщения о запуске бота: " + std::string(e.what()));
        }

        bot_->start();

        stopWorkers();
        saveState();

        logger_->log(LogLevel::INFO, "Бот остановлен");
        try {
            bot_->sendMessage(config_.adminChatIds[0], "Бот остановлен");
        } catch (const std::exception& e) {
            logger_->log(LogLevel::ERROR, "Ошибка отправки сообщения о остановке бота: " + std::string(e.what()));
        }
    }

    void stop() {
        running_ = false;
        bot_->stop();
        messageQueue_.stop();
    }

private:
    void setupHandlers() {
        bot_->onCommand("update_config", [this](const Message& message) {
            if (std::find(config_.adminChatIds.begin(), config_.adminChatIds.end(), message.chatId) != config_.adminChatIds.end()) {
                updateConfig();
                try {
                    bot_->sendMessage(message.chatId, "Конфигурация обновлена");
                } catch (const std::exception& e) {
                    logger_->log(LogLevel::ERROR, "Ошибка отправки сообщения об обновлении конфигурации: " + std::string(e.what()));
                }
            } else {
                try {
                    bot_->sendMessage(message.chatId, "У вас нет прав на выполнение этой команды");
                } catch (const std::exception& e) {
                    logger_->log(LogLevel::ERROR, "Ошибка отправки сообщения о недостатке прав: " + std::string(e.what()));
                }
            }
        });

        bot_->onAnyMessage([this](const Message& message) {
            if (message.username == config_.targetGroup) {
                if (messageQueue_.size() < config_.messageQueueSize) {
                    messageQueue_.push(message);
                } else {
                    logger_->log(LogLevel::WARNING, "Очередь сообщений переполнена, сообщение пропущено");
                }
            }
        });
    }

    void startWorkers() {
        for (int i = 0; i < config_.workerThreads; i++) {
            workers_.emplace_back([this] { processMessageQueue(); });
        }
    }

    void stopWorkers() {
        messageQueue_.stop();
        for (auto& worker : workers_) {
            worker.join();
        }
    }

    void startMetricsThread() {
        metricsThread_ = std::thread(&BotManager::printMetrics, this);
    }

    void startBackupThread() {
        backupThread_ = std::thread(&BotManager::backupState, this);
    }

    void processMessageQueue() {
        while (running_) {
            Message msg;
            if (messageQueue_.pop(msg)) {
                processMessage(msg);
            }
        }
    }

    void processMessage(const Message& msg) {
        if (isMessageProcessed(msg.messageId)) {
            return;
        }

        markMessageAsProcessed(msg.messageId);
        metrics_.messagesProcessed++;

        std::string lowerText = msg.text;
        std::transform(lowerText.begin(), lowerText.end(), lowerText.begin(), ::tolower);

        for (const auto& [word, regex] : config_.keywords) {
            if (std::regex_search(lowerText, regex)) {
                metrics_.keywordsFound++;
                std::string notification = "Ключевое слово \"" + word + "\" найдено в сообщении от @" + msg.username +
                    " в чате " + std::to_string(msg.chatId) + ":\n" + msg.text;
                sendNotificationToAdmins(notification);
                
                // Автоматический ответ
                std::string response = generateAutoResponse(word);
                enforceRateLimit();
                try {
                    bot_->sendMessage(msg.chatId, response);
                } catch (const std::exception& e) {
                    logger_->log(LogLevel::ERROR, "Ошибка отправки автоматического ответа: " + std::string(e.what()));
                }
                break;
            }
        }
    }

    void sendNotificationToAdmins(const std::string& message) {
        for (const auto& adminChatId : config_.adminChatIds) {
            try {
                enforceRateLimit();
                bot_->sendMessage(adminChatId, message);
                metrics_.notificationsSent++;
            } catch (const std::exception& e) {
                logger_->log(LogLevel::ERROR, "Не удалось отправить сообщение администратору " + std::to_string(adminChatId) + ": " + e.what());
            }
        }
    }

    bool isMessageProcessed(int64_t messageId) const {
        std::lock_guard<std::mutex> lock(processedMessagesMutex_);
        return processedMessages_.find(messageId) != processedMessages_.end();
    }

    void markMessageAsProcessed(int64_t messageId) {
        std::lock_guard<std::mutex> lock(processedMessagesMutex_);
        processedMessages_.insert(messageId);
        if (processedMessages_.size() > config_.maxProcessedMessages) {
            processedMessages_.erase(processedMessages_.begin());
        }
    }

    void printMetrics() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(METRICS_PRINT_INTERVAL));
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - metrics_.startTime);

            logger_->log(LogLevel::INFO, "Метрики за последние " + std::to_string(uptime.count()) + " секунд:");
            logger_->log(LogLevel::INFO, "Обработано сообщений: " + std::to_string(metrics_.messagesProcessed));
            logger_->log(LogLevel::INFO, "Найдено ключевых слов: " + std::to_string(metrics_.keywordsFound));
            logger_->log(LogLevel::INFO, "Отправлено уведомлений: " + std::to_string(metrics_.notificationsSent));
        }
    }

    void backupState() {
        while (running_) {
            saveState();
            std::this_thread::sleep_for(std::chrono::seconds(config_.stateBackupInterval));
        }
    }

    void saveState() {
        json state;
        {
            std::lock_guard<std::mutex> lock(processedMessagesMutex_);
            state["processedMessages"] = json(processedMessages_);
        }
        {
            std::lock_guard<std::mutex> lock(configMutex_);
            state["config"] = json::parse(std::ifstream("config.json"));
        }

        std::ofstream stateFile("bot_state.json");
        stateFile << state.dump(4);
    }

    void updateConfig() {
        try {
            std::lock_guard<std::mutex> lock(configMutex_);
            config_.load("config.json");
            logger_->setLogLevel(config_.logLevel);
            logger_->log(LogLevel::INFO, "Конфигурация успешно обновлена");
        } catch (const std::exception& e) {
            logger_->log(LogLevel::ERROR, "Ошибка при обновлении конфигурации: " + std::string(e.what()));
        }
    }

    std::string generateAutoResponse(const std::string& keyword) {
        std::vector<std::string> responses = {
            "Интересное упоминание о " + keyword + "! Можете рассказать подробнее?",
            "Я заметил, что вы говорите о " + keyword + ". Это очень важная тема!",
            keyword + " - отличная тема для обсуждения. Есть ли у вас какие-то конкретные мысли по этому поводу?",
            "О, " + keyword + "! Я всегда рад услышать мнения по этому вопросу.",
            "Спасибо, что подняли тему " + keyword + ". Давайте обсудим это подробнее!" 
        };
      //в целом хуйни сюда всякой от контекста

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, responses.size() - 1);
        return responses[dis(gen)];
    }

    void initializeRateLimiter() {
        lastRequestTime_ = std::chrono::steady_clock::now();
    }

    void enforceRateLimit() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastRequestTime_);
        if (elapsed < requestInterval_) {
            std::this_thread::sleep_for(requestInterval_ - elapsed);
        }
        lastRequestTime_ = std::chrono::steady_clock::now();
    }

    std::unique_ptr<ITelegramBot> bot_;
    Config config_;
    std::shared_ptr<Logger> logger_;
    ThreadSafeQueue<Message> messageQueue_;
    std::unordered_set<int64_t> processedMessages_;
    mutable std::mutex processedMessagesMutex_;
    std::mutex configMutex_;
    Metrics metrics_;
    std::vector<std::thread> workers_;
    std::thread metricsThread_;
    std::thread backupThread_;
    std::atomic<bool> running_{true};
    std::chrono::steady_clock::time_point lastRequestTime_;
    std::chrono::milliseconds requestInterval_{1000}; // 1 запрос в секунду
};

std::unique_ptr<BotManager> g_botManager;

// Обработчик сигналов
void signalHandler(int signum) {
    std::cout << "Получен сигнал прерывания (" << signum << ").\n";
    if (g_botManager) {
        g_botManager->stop();
    }
}

// Получение ключа шифрования из переменной окружения
std::string getEncryptionKeyFromEnv() {
    const char* env_key = std::getenv("BOT_ENCRYPTION_KEY");
    if (env_key == nullptr) {
        throw std::runtime_error("Переменная окружения BOT_ENCRYPTION_KEY не установлена");
    }
    return std::string(env_key);
}

int main() {
    try {
        Config config;
        config.load("config.json");

        std::string encryptionKey = getEncryptionKeyFromEnv();

        auto logger = std::make_shared<Logger>(config.logFile, config.logLevel);
        auto bot = std::make_unique<TelegramBot>(config.encryptedBotToken, encryptionKey);

        auto botManager = std::make_unique<BotManager>(std::move(bot), config, logger);
        g_botManager = std::move(botManager);

        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        if (fs::exists("bot_state.json")) {
            std::ifstream stateFile("bot_state.json");
            json state;
            stateFile >> state;

            std::unordered_set<int64_t> processedMessages = state["processedMessages"].get<std::unordered_set<int64_t>>();
        }

        logger->log(LogLevel::INFO, "Инициализация бота...");

        g_botManager->run();

        logger->log(LogLevel::INFO, "Завершение работы бота.");
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

#endif // TELEGRAM_BOT_HPP
