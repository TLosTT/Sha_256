#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <vector>

// Класс, реализующий алгоритм SHA-256
class SHA256 {
public:
    // Статическая функция для вычисления хэша SHA-256 от входной строки
    static std::string hash(const std::string& input) {
        // Инициализация переменных для хранения промежуточных результатов хэширования
        uint32_t h0 = 0x6a09e667;
        uint32_t h1 = 0xbb67ae85;
        uint32_t h2 = 0x3c6ef372;
        uint32_t h3 = 0xa54ff53a;
        uint32_t h4 = 0x510e527f;
        uint32_t h5 = 0x9b05688c;
        uint32_t h6 = 0x1f83d9ab;
        uint32_t h7 = 0x5be0cd19;

        // Подготовка сообщения: дополнение и конвертация в блоки
        std::string paddedMessage = padMessage(input);
        std::vector<uint32_t> blocks = createBlocks(paddedMessage);

        // Обработка блоков
        for (uint32_t block : blocks) {
            processBlock(block, h0, h1, h2, h3, h4, h5, h6, h7);
        }

        // Сбор результатов в строку
        std::stringstream result;
        result << std::hex << std::setw(8) << std::setfill('0') << h0
               << std::hex << std::setw(8) << std::setfill('0') << h1
               << std::hex << std::setw(8) << std::setfill('0') << h2
               << std::hex << std::setw(8) << std::setfill('0') << h3
               << std::hex << std::setw(8) << std::setfill('0') << h4
               << std::hex << std::setw(8) << std::setfill('0') << h5
               << std::hex << std::setw(8) << std::setfill('0') << h6
               << std::hex << std::setw(8) << std::setfill('0') << h7;

        return result.str();
    }

private:
    // Функция для дополнения входной строки до необходимой длины
    static std::string padMessage(const std::string& input) {
        // Добавление бита '1' в конец сообщения
        std::string result = input + static_cast<char>(0x80);

        // Добавление нулей до длины сообщения (в битах) с учетом добавленного '1'
        while ((result.length() * 8) % 512 != 448) {
            result += static_cast<char>(0x00);
        }

        // Добавление длины исходного сообщения (в битах) в конец сообщения
        uint64_t originalLength = input.length() * 8;
        result += std::string(8, '\0');
        result[result.length() - 8] = (originalLength >> 56) & 0xFF;
        result[result.length() - 7] = (originalLength >> 48) & 0xFF;
        result[result.length() - 6] = (originalLength >> 40) & 0xFF;
        result[result.length() - 5] = (originalLength >> 32) & 0xFF;
        result[result.length() - 4] = (originalLength >> 24) & 0xFF;
        result[result.length() - 3] = (originalLength >> 16) & 0xFF;
        result[result.length() - 2] = (originalLength >> 8) & 0xFF;
        result[result.length() - 1] = originalLength & 0xFF;

        return result;
    }

    // Функция для разделения входной строки на блоки по 64 байта
    static std::vector<uint32_t> createBlocks(const std::string& input) {
        std::vector<uint32_t> blocks;
        for (size_t i = 0; i < input.length(); i += 64) {
            uint32_t block = 0;
            for (size_t j = 0; j < 64; j++) {
                block = (block << 8) | static_cast<uint8_t>(input[i + j]);
            }
            blocks.push_back(block);
        }
        return blocks;
    }

    // Вспомогательная функция для циклического сдвига вправо
    static uint32_t rightRotate(uint32_t value, uint32_t count) {
        // Функция выполняет циклический сдвиг битов значения value вправо на count позиций.
        // Это достигается сдвигом вправо и логическим ИЛИ с результатом сдвига влево.
        return (value >> count) | (value << (32 - count));
    }

    // Вспомогательная функция для логической операции "choose" в основном цикле
    static uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
        // Функция возвращает результат логической операции "choose" над x, y и z.
        // Выражение (x & y) ^ (~x & z) означает, что для каждого бита результата,
        // если соответствующий бит в x и y установлен, или бит в z установлен, то бит в результате установлен.
        return (x & y) ^ (~x & z);
    }

    // Вспомогательная функция для логической операции "majority" в основном цикле
    static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
        // Функция возвращает результат логической операции "majority" над x, y и z.
        // Выражение (x & y) ^ (x & z) ^ (y & z) означает, что для каждого бита результата,
        // если бит в x и y установлен, или бит в x и z установлен, или бит в y и z установлен, то бит в результате установлен.
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t sigma0(uint32_t x) {
        return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
    }

    static uint32_t sigma1(uint32_t x) {
        return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
    }

    static uint32_t delta0(uint32_t x) {
        return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >> 3);
    }

    static uint32_t delta1(uint32_t x) {
        return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >> 10);
    }


    // Основная функция для обработки каждого блока
    static void processBlock(uint32_t block, uint32_t& h0, uint32_t& h1, uint32_t& h2, uint32_t& h3,
                             uint32_t& h4, uint32_t& h5, uint32_t& h6, uint32_t& h7) {
        // Инициализация констант
        const uint32_t k[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // Инициализация рабочих переменных
        uint32_t w[64];
        for (size_t i = 0; i < 16; i++) {
            w[i] = (block >> (24 - i * 8)) & 0xFF;
        }
        for (size_t i = 16; i < 64; i++) {
            w[i] = delta1(w[i - 2]) + w[i - 7] + delta0(w[i - 15]) + w[i - 16];
        }

        // Инициализация рабочих переменных для текущего блока
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        // Основной цикл
        for (size_t i = 0; i < 64; i++) {
            uint32_t t1 = h + sigma1(e) + choose(e, f, g) + k[i] + w[i];
            uint32_t t2 = sigma0(a) + majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Обновление значений хэша
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
};

// Функция main, в которой демонстрируется пример использования SHA-256
int main() {
    // Входная строка для хэширования
    std::string input = "Привет, мир!";
    
    // Получение хэша для входной строки
    std::string hashResult = SHA256::hash(input);

    // Вывод исходной строки и ее хэша на экран
    std::cout << "Input: " << input << std::endl;
    std::cout << "SHA-256 Hash: " << hashResult << std::endl;

    return 0;
}
