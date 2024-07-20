#include <string>
#include <vector>
#include <memory>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <unordered_set>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <regex>
#include <iomanip>
#include <ctime>
#include <csignal>
#include <iostream>
#include <sstream>
#include <future>
#include <optional>
#include <variant>
#include <tgbot/tgbot.h>
#include <tl/expected.hpp>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

namespace TelegramBot {

// Предварительные объявления
class SecureConfig;
class Logger;
class MessageProcessor;
class ITelegramBot;
class TelegramBotFacade;

/**
 * @enum ErrorCode
 * @brief Коды ошибок, используемые в приложении.
 */
enum class ErrorCode {
    ConfigurationError,
    NetworkError,
    AuthenticationError,
    MessageProcessingError
};

/**
 * @class Error
 * @brief Класс для представления ошибок в приложении.
 */
class Error {
public:
    Error(ErrorCode code, std::string_view message) : code_(code), message_(message) {}
    
    ErrorCode code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }

private:
    ErrorCode code_;
    std::string message_;
};

/**
 * @class Cache
 * @brief Простая реализация кэша с использованием LRU (Least Recently Used) стратегии.
 */
class Cache {
public:
    Cache(size_t max_size) : max_size_(max_size) {}

    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cache_.find(key) != cache_.end()) {
            // Перемещаем существующий элемент в начало
            auto it = std::find(order_.begin(), order_.end(), key);
            order_.erase(it);
            order_.push_front(key);
            cache_[key] = value;
        } else {
            if (cache_.size() >= max_size_) {
                // Удаляем последний (наименее недавно использованный) элемент
                auto last = order_.back();
                order_.pop_back();
                cache_.erase(last);
            }
            order_.push_front(key);
            cache_[key] = value;
        }
    }

    std::optional<std::string> get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            // Перемещаем элемент в начало
            auto order_it = std::find(order_.begin(), order_.end(), key);
            order_.erase(order_it);
            order_.push_front(key);
            return it->second;
        }
        return std::nullopt;
    }

private:
    std::unordered_map<std::string, std::string> cache_;
    std::list<std::string> order_;
    size_t max_size_;
    std::mutex mutex_;
};

/**
 * @class SecureConfig
 * @brief Класс для безопасного хранения и управления конфигурацией бота.
 */
class SecureConfig {
public:
    SecureConfig() : pImpl(std::make_unique<Impl>()) {}
    ~SecureConfig() = default;

    tl::expected<void, Error> loadFromFile(const std::filesystem::path& filename) {
        std::lock_guard<std::mutex> lock(configMutex);
        return loadConfigImpl(pImpl.get(), filename);
    }

    tl::expected<void, Error> reloadConfig(const std::filesystem::path& filename) {
        auto newConfig = std::make_unique<Impl>();
        auto result = loadConfigImpl(newConfig.get(), filename);
        if (result) {
            std::lock_guard<std::mutex> lock(configMutex);
            pImpl = std::move(newConfig);
        }
        return result;
    }

    [[nodiscard]] std::string getBotToken() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->botToken;
    }

    [[nodiscard]] std::string getTargetGroup() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->targetGroup;
    }

    [[nodiscard]] std::vector<int64_t> getAdminChatIds() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->adminChatIds;
    }

    [[nodiscard]] size_t getMessageQueueSize() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->messageQueueSize;
    }

    [[nodiscard]] int getWorkerThreads() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->workerThreads;
    }

    [[nodiscard]] std::chrono::seconds getStateBackupInterval() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->stateBackupInterval;
    }

    [[nodiscard]] std::string getSecretKey() const {
        std::lock_guard<std::mutex> lock(configMutex);
        return pImpl->secretKey;
    }

private:
    class Impl {
    public:
        std::string botToken;
        std::string targetGroup;
        std::vector<int64_t> adminChatIds;
        size_t messageQueueSize;
        int workerThreads;
        std::chrono::seconds stateBackupInterval;
        std::string secretKey;

        void decrypt(std::string_view ciphertext, std::string_view key) {
            // Простая XOR-шифрация для демонстрации
            std::string decrypted;
            for (size_t i = 0; i < ciphertext.length(); ++i) {
                decrypted += ciphertext[i] ^ key[i % key.length()];
            }
            botToken = decrypted;
        }
    };

    std::unique_ptr<Impl> pImpl;
    mutable std::mutex configMutex;

    tl::expected<void, Error> loadConfigImpl(Impl* config, const std::filesystem::path& filename) {
        std::ifstream file(filename);
        if (!file) {
            return tl::unexpected(Error(ErrorCode::ConfigurationError, 
                "Не удалось открыть файл конфигурации: " + filename.string()));
        }

        nlohmann::json j;
        file >> j;

        config->targetGroup = j["target_group"];
        config->adminChatIds = j["admin_chat_ids"].get<std::vector<int64_t>>();
        config->messageQueueSize = j["message_queue_size"];
        config->workerThreads = j["worker_threads"];
        config->stateBackupInterval = std::chrono::seconds(j["state_backup_interval"]);
        config->secretKey = j["secret_key"];

        const char* keyEnv = std::getenv("BOT_TOKEN_KEY");
        if (!keyEnv) {
            return tl::unexpected(Error(ErrorCode::ConfigurationError, 
                "Переменная окружения BOT_TOKEN_KEY не установлена"));
        }
        config->decrypt(j["encrypted_bot_token"], keyEnv);

        return {};
    }
};

/**
 * @class Logger
 * @brief Класс для логирования событий в приложении.
 */
class Logger {
public:
    enum class Severity {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    explicit Logger(const std::filesystem::path& logFile) : logFile(logFile.string(), std::ios::app) {
        if (!this->logFile) {
            throw std::runtime_error("Не удалось открыть файл журнала: " + logFile.string());
        }
    }

    void log(Severity severity, std::string_view message) {
        std::lock_guard<std::mutex> lock(logMutex);
        auto now = std::chrono::system_clock::now();
        auto inTimeT = std::chrono::system_clock::to_time_t(now);
        
        logFile << std::put_time(std::localtime(&inTimeT), "[%Y-%m-%d %H:%M:%S] ");
        switch (severity) {
        case Severity::DEBUG:
            logFile << "[DEBUG] ";
            break;
        case Severity::INFO:
            logFile << "[INFO] ";
            break;
        case Severity::WARNING:
            logFile << "[WARNING] ";
            break;
        case Severity::ERROR:
            logFile << "[ERROR] ";
            break;
        }
        logFile << message << std::endl;
    }

private:
    std::ofstream logFile;
    std::mutex logMutex;
};

/**
 * @struct Message
 * @brief Структура для представления сообщения в системе.
 */
struct Message {
    int64_t chatId;
    std::string text;
    std::string username;
    int64_t messageId;
};

/**
 * @class ThreadSafeQueue
 * @brief Потокобезопасная очередь для хранения сообщений.
 */
template <typename T>
class ThreadSafeQueue {
public:
    void push(T value) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            queue.push(std::move(value));
        }
        cv.notify_one();
    }

    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return !queue.empty() || !running; });
        if (!running && queue.empty())
            return std::nullopt;
        T value = std::move(queue.front());
        queue.pop();
        return value;
    }

    void stop() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex);
            running = false;
        }
        cv.notify_all();
    }

    [[nodiscard]] size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.size();
    }

private:
    std::queue<T> queue;
    mutable std::mutex mutex;
    std::condition_variable cv;
    bool running = true;
};

/**
 * @class ITelegramBot
 * @brief Интерфейс для Telegram бота.
 */
class ITelegramBot {
public:
    virtual ~ITelegramBot() = default;
    virtual tl::expected<void, Error> sendMessage(int64_t chatId, std::string_view message) = 0;
    virtual tl::expected<void, Error> start() = 0;
};

/**
 * @class AuthManager
 * @brief Класс для управления аутентификацией пользователей.
 */
class AuthManager {
public:
    AuthManager(const std::string& secret_key) : secret_key(secret_key) {}

    std::string createToken(int64_t user_id) {
        auto token = jwt::create()
            .set_issuer("telegram_bot")
            .set_type("JWS")
            .set_payload_claim("user_id", jwt::claim(std::to_string(user_id)))
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
            .sign(jwt::algorithm::hs256{secret_key});
        return token;
    }

    tl::expected<int64_t, Error> verifyToken(const std::string& token) {
        try {
            auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{secret_key})
                .with_issuer("telegram_bot");
            verifier.verify(decoded);
            return std::stoll(decoded.get_payload_claim("user_id").as_string());
        } catch (const std::exception& e) {
            return tl::unexpected(Error(ErrorCode::AuthenticationError, "Недействительный токен"));
        }
    }

private:
    std::string secret_key;
};

/**
 * @class MessageProcessor
 * @brief Класс для обработки сообщений.
 */
class MessageProcessor {
public:
    MessageProcessor(const SecureConfig& config, std::shared_ptr<Logger> logger)
        : config(config), logger(std::move(logger)) {
        metrics.startTime = std::chrono::steady_clock::now();
    }

    tl::expected<void, Error> processMessage(ITelegramBot& bot, const Message& message) {
        try {
            logger->log(Logger::Severity::INFO, "Обработка сообщения: " + message.text);
            
            if (message.text.front() == '/') {
                return handleBotCommand(message, bot);
            } else {
                if (message.text.find("важно") != std::string::npos) {
                    metrics.keywordsFound++;
                    return sendNotificationToAdmins(bot, "Обнаружено важное сообщение: " + message.text);
                }
            }
            
            markMessageAsProcessed(message.messageId);
            metrics.messagesProcessed++;
            return {};
        } catch (const std::exception& e) {
            return tl::unexpected(Error(ErrorCode::MessageProcessingError, 
                "Ошибка при обработке сообщения: " + std::string(e.what())));
        }
    }

    void enqueueMessage(const Message& message) {
        queue.push(message);
    }

    [[nodiscard]] size_t getQueueSize() const noexcept {
        return queue.size();
    }

    [[nodiscard]] bool isRunning() const noexcept {
        return running;
    }

    void stop() noexcept {
        running = false;
        queue.stop();
    }

private:
    const SecureConfig& config;
    std::shared_ptr<Logger> logger;
    ThreadSafeQueue<Message> queue;
    std::atomic<bool> running{true};
    std::unordered_set<int64_t> processedMessages;
    mutable std::shared_mutex processedMessagesMutex;

    struct Metrics {
        std::chrono::steady_clock::time_point startTime;
        std::atomic<size_t> messagesProcessed{0};
        std::atomic<size_t> keywordsFound{0};
        std::atomic<size_t> notificationsSent{0};
    } metrics;

    tl::expected<void, Error> handleBotCommand(const Message& message, ITelegramBot& bot) {
        if (message.text == "/start") {
            return bot.sendMessage(message.chatId, "Бот запущен. Добро пожаловать!");
        } else if (message.text == "/stats") {
            auto now = std::chrono::steady_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::hours>(now - metrics.startTime).count();
            
            std::stringstream ss;
            ss << "Статистика бота:\n"
               << "Время работы: " << uptime << " часов\n"
               << "Обработано сообщений: " << metrics.messagesProcessed << "\n"
               << "Найдено ключевых слов: " << metrics.keywordsFound << "\n"
               << "Отправлено уведомлений: " << metrics.notificationsSent;
            
            return bot.sendMessage(message.chatId, ss.str());
        }
        return tl::unexpected(Error(ErrorCode::MessageProcessingError, "Неизвестная команда"));
    }

    tl::expected<void, Error> sendNotificationToAdmins(ITelegramBot& bot, std::string_view message) {
        const auto& adminChatIds = config.getAdminChatIds();
        for (auto chatId : adminChatIds) {
            auto result = bot.sendMessage(chatId, message);
            if (!result) {
                return tl::unexpected(result.error());
            }
            metrics.notificationsSent++;
        }
        return {};
    }

    void markMessageAsProcessed(int64_t messageId) {
        std::unique_lock<std::shared_mutex> lock(processedMessagesMutex);
        processedMessages.insert(messageId);
    }

    [[nodiscard]] bool isMessageProcessed(int64_t messageId) const noexcept {
        std::shared_lock<std::shared_mutex> lock(processedMessagesMutex);
        return processedMessages.find(messageId) != processedMessages.end();
    }
};

/**
 * @class BotState
 * @brief Абстрактный класс для представления состояния бота.
 */
class BotState {
public:
    virtual ~BotState() = default;
    virtual void enter(TelegramBotFacade& bot) = 0;
    virtual void exit(TelegramBotFacade& bot) = 0;
    virtual tl::expected<void, Error> processMessage(TelegramBotFacade& bot, const Message& message) = 0;
};

/**
 * @class Plugin
 * @brief Абстрактный класс для плагинов бота.
 */
class Plugin {
public:
    virtual ~Plugin() = default;
    virtual std::string getName() const = 0;
    virtual tl::expected<void, Error> processMessage(const Message& message, TelegramBotFacade& bot) = 0;
};

/**
 * @class PluginManager
 * @brief Класс для управления плагинами бота.
 */
class PluginManager {
public:
    void registerPlugin(std::unique_ptr<Plugin> plugin) {
        plugins[plugin->getName()] = std::move(plugin);
    }

    tl::expected<void, Error> processMessageWithPlugins(const Message& message, TelegramBotFacade& bot) {
        for (const auto& [name, plugin] : plugins) {
            auto result = plugin->processMessage(message, bot);
            if (!result) {
                return result;
            }
        }
        return {};
    }

private:
    std::unordered_map<std::string, std::unique_ptr<Plugin>> plugins;
};

/**
 * @class TelegramBotFacade
 * @brief Основной класс, управляющий функциональностью бота.
 */
class TelegramBotFacade : public ITelegramBot {
public:
    TelegramBotFacade(std::shared_ptr<SecureConfig> config, 
                      std::shared_ptr<Logger> logger, 
                      std::shared_ptr<MessageProcessor> processor)
        : config(std::move(config)), 
          logger(std::move(logger)), 
          processor(std::move(processor)),
          currentState(std::make_unique<InitializationState>()),
          threadPool(std::make_unique<boost::asio::thread_pool>(this->config->getWorkerThreads())),
          registry(std::make_shared<prometheus::Registry>()),
          exposer(std::make_unique<prometheus::Exposer>("0.0.0.0:8080")),
          cache(1000),  // Кэш на 1000 элементов
          authManager(this->config->getSecretKey()) {
        
        exposer->RegisterCollectable(registry);
        
        messagesProcessed = &prometheus::BuildCounter()
            .Name("messages_processed_total")
            .Help("Total number of processed messages")
            .Register(*registry);
        
        activeConnections = &prometheus::BuildGauge()
            .Name("active_connections")
            .Help("Number of active connections")
            .Register(*registry);

        bot = std::make_unique<TgBot::Bot>(this->config->getBotToken());
    }

    tl::expected<void, Error> sendMessage(int64_t chatId, std::string_view message) override {
        try {
            bot->getApi().sendMessage(chatId, std::string(message));
            return {};
        } catch (const TgBot::TgException& e) {
            return tl::unexpected(Error(ErrorCode::NetworkError, 
                "Ошибка при отправке сообщения: " + std::string(e.what())));
        }
    }

    tl::expected<void, Error> start() override {
        try {
            changeState(std::make_unique<WorkingState>());
            
            bot->getEvents().onAnyMessage([this](TgBot::Message::Ptr message) {
                Message msg{
                    message->chat->id,
                    message->text,
                    message->from->username,
                    message->messageId
                };
                processMessage(msg);
            });

            logger->log(Logger::Severity::INFO, "Бот запущен. Ожидание сообщений...");
            
            TgBot::TgLongPoll longPoll(*bot);
            while (running) {
                try {
                    logger->log(Logger::Severity::DEBUG, "Начало цикла long polling");
                    longPoll.start();
                } catch (const std::exception& e) {
                    logger->log(Logger::Severity::ERROR, "Ошибка в long polling: " + std::string(e.what()));
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
            }
            return {};
        } catch (const TgBot::TgException& e) {
            return tl::unexpected(Error(ErrorCode::AuthenticationError, 
                "Ошибка при запуске бота: " + std::string(e.what())));
        }
    }

    void changeState(std::unique_ptr<BotState> newState) {
        if (currentState) {
            currentState->exit(*this);
        }
        currentState = std::move(newState);
        currentState->enter(*this);
    }

    tl::expected<void, Error> processMessage(const Message& message) {
        // Проверяем аутентификацию пользователя
        auto authResult = authenticateUser(message.chatId);
        if (!authResult) {
            return tl::unexpected(authResult.error());
        }

        // Проверяем кэш на наличие готового ответа
        auto cachedResponse = cache.get("response_" + std::to_string(message.chatId) + "_" + message.text);
        if (cachedResponse) {
            return sendMessage(message.chatId, *cachedResponse);
        }

        // Если ответа нет в кэше, обрабатываем сообщение
        boost::asio::post(*threadPool, [this, message]() {
            auto result = pluginManager.processMessageWithPlugins(message, *this);
            if (!result) {
                logger->log(Logger::Severity::ERROR, "Error processing message with plugins: " + result.error().message());
            }
            auto processingResult = processor->processMessage(*this, message);
            if (!processingResult) {
                logger->log(Logger::Severity::ERROR, "Error processing message: " + processingResult.error().message());
            } else {
                // Сохраняем результат в кэш
                cache.set("response_" + std::to_string(message.chatId) + "_" + message.text, "Processed successfully");
            }
            messagesProcessed->Increment();
        });
        return {};
    }

    tl::expected<void, Error> authenticateUser(int64_t userId) {
        auto token = cache.get("auth_token_" + std::to_string(userId));
        if (!token) {
            token = authManager.createToken(userId);
            cache.set("auth_token_" + std::to_string(userId), *token);
        }
        return authManager.verifyToken(*token);
    }

    void updateMetrics() {
        activeConnections->Set(threadPool->get_executor().running_in_this_thread());
    }

    void stop() {
        running = false;
        changeState(std::make_unique<ShutdownState>());
    }

    std::shared_ptr<Logger> getLogger() const { return logger; }
    std::shared_ptr<MessageProcessor> getProcessor() const { return processor; }

private:
    std::shared_ptr<SecureConfig> config;
    std::shared_ptr<Logger> logger;
    std::shared_ptr<MessageProcessor> processor;
    std::unique_ptr<BotState> currentState;
    std::unique_ptr<boost::asio::thread_pool> threadPool;
    PluginManager pluginManager;
    std::unique_ptr<TgBot::Bot> bot;
    Cache cache;
    AuthManager authManager;

    std::shared_ptr<prometheus::Registry> registry;
    std::unique_ptr<prometheus::Exposer> exposer;
    prometheus::Counter* messagesProcessed;
    prometheus::Gauge* activeConnections;

    std::atomic<bool> running{true};
};

/**
 * @class InitializationState
 * @brief Состояние инициализации бота.
 */
class InitializationState : public BotState {
public:
    void enter(TelegramBotFacade& bot) override {
        bot.getLogger()->log(Logger::Severity::INFO, "Entering Initialization State");
    }

    void exit(TelegramBotFacade& bot) override {
        bot.getLogger()->log(Logger::Severity::INFO, "Exiting Initialization State");
    }

    tl::expected<void, Error> processMessage(TelegramBotFacade& bot, const Message& message) override {
        return bot.sendMessage(message.chatId, "Бот инициализируется. Пожалуйста, подождите.");
    }
};

/**
 * @class WorkingState
 * @brief Рабочее состояние бота.
 */
class WorkingState : public BotState {
public:
    void enter(TelegramBotFacade& bot) override {
        bot.getLogger()->log(Logger::Severity::INFO, "Entering Working State");
    }

    void exit(TelegramBotFacade& bot) override {
        bot.getLogger()->log(Logger::Severity::INFO, "Exiting Working State");
    }

    tl::expected<void, Error> processMessage(TelegramBotFacade& bot, const Message& message) override {
        return bot.getProcessor()->processMessage(bot, message);
    }
};

/**
 * @class ShutdownState
 * @brief Состояние завершения работы бота.
 */
class ShutdownState : public BotState {
public:
    void enter(TelegramBotFacade& bot) override {
        bot.getLogger()->log(Logger::Severity::INFO, "Entering Shutdown State");
    }

    void exit(TelegramBotFacade& bot) override {
        bot.getLogger()->log(Logger::Severity::INFO, "Exiting Shutdown State");
    }

    tl::expected<void, Error> processMessage(TelegramBotFacade& bot, const Message& message) override {
        return bot.sendMessage(message.chatId, "Бот завершает работу. Спасибо за использование!");
    }
};

/**
 * @class RecoveryManager
 * @brief Класс для управления восстановлением бота после сбоев.
 */
class RecoveryManager {
public:
    RecoveryManager(TelegramBotFacade& bot) : bot(bot) {}

    void startMonitoring() {
        monitoringThread = std::thread([this]() {
            while (!shouldStop) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                checkBotHealth();
            }
        });
    }

    void stopMonitoring() {
        shouldStop = true;
        if (monitoringThread.joinable()) {
            monitoringThread.join();
        }
    }

private:
    void checkBotHealth() {
        if (bot.getProcessor()->getQueueSize() > 1000) {
            bot.getLogger()->log(Logger::Severity::WARNING, "Bot health check failed. Attempting recovery...");
            recoverBot();
        }
    }

    void recoverBot() {
        bot.changeState(std::make_unique<InitializationState>());
        bot.changeState(std::make_unique<WorkingState>());
    }

    TelegramBotFacade& bot;
    std::thread monitoringThread;
    std::atomic<bool> shouldStop{false};
};

std::atomic<bool> shouldExit(false);

void signalHandler(int signal) {
    std::cout << "Получен сигнал: " << signal << std::endl;
    shouldExit = true;
}

void setupSignalHandling() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
}

int main() {
    try {
        setupSignalHandling();

        auto config = std::make_shared<SecureConfig>();
        auto configResult = config->loadFromFile("config.json");
        if (!configResult) {
            std::cerr << "Ошибка загрузки конфигурации: " << configResult.error().message() << std::endl;
            return 1;
        }

        auto logger = std::make_shared<Logger>("bot_log.txt");
        auto processor = std::make_shared<MessageProcessor>(*config, logger);
        auto bot = std::make_unique<TelegramBotFacade>(config, logger, processor);
        
        RecoveryManager recoveryManager(*bot);
        recoveryManager.startMonitoring();

        auto botFuture = std::async(std::launch::async, [&bot]() {
            return bot->start();
        });

        // Основной цикл
        while (!shouldExit) {
            bot->updateMetrics();
            
            // Проверка необходимости перезагрузки конфигурации
            static auto lastConfigCheck = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::minutes>(now - lastConfigCheck) >= std::chrono::minutes(5)) {
                lastConfigCheck = now;
                auto reloadResult = config->reloadConfig("config.json");
                if (reloadResult) {
                    logger->log(Logger::Severity::INFO, "Конфигурация успешно перезагружена");
                } else {
                    logger->log(Logger::Severity::ERROR, "Ошибка перезагрузки конфигурации: " + reloadResult.error().message());
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        recoveryManager.stopMonitoring();
        bot->stop();

        auto startResult = botFuture.get();
        if (!startResult) {
            logger->log(Logger::Severity::ERROR, "Ошибка работы бота: " + startResult.error().message());
        }

        logger->log(Logger::Severity::INFO, "Бот успешно завершил работу.");
    }
    catch (const std::exception& e) {
        std::cerr << "Неожиданная ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

} // namespace TelegramBot

int main() {
    return TelegramBot::main();
}
