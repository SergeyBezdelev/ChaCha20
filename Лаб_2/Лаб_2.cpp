#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include <string>
using namespace std;
const array<int, 4> ROTATE = { 16, 12, 8, 7 };

/// Функция для квартер-кругового сдвига влево
inline uint32_t quarter_round(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    a += b; d ^= a; d <<= 16;
    c += d; b ^= c; b <<= 12;
    a += b; d ^= a; d <<= 8;
    c += d; b ^= c; b <<= 7;
    return a;
}

// Функция для генерации блока ChaCha20
array<uint8_t, 64> chacha20_block(const array<uint8_t, 32>& key, const array<uint8_t, 12>& nonce, uint32_t counter) {
    array<uint32_t, 16> state = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,         //Создается массив state из 16 элементов типа uint32_t, который инициализируется 
        *reinterpret_cast<const uint32_t*>(key.data()),         //фиксированными значениями (константами) и значениями из ключа, nonce и счетчика.
        *reinterpret_cast<const uint32_t*>(key.data() + 4),     
        *reinterpret_cast<const uint32_t*>(key.data() + 8),
        *reinterpret_cast<const uint32_t*>(key.data() + 12),
        *reinterpret_cast<const uint32_t*>(key.data() + 16),
        *reinterpret_cast<const uint32_t*>(key.data() + 20),
        *reinterpret_cast<const uint32_t*>(key.data() + 24),
        *reinterpret_cast<const uint32_t*>(key.data() + 28),
        *reinterpret_cast<const uint32_t*>(nonce.data()),        //Остальные элементы заполняются значениями из ключа и nonce
        *reinterpret_cast<const uint32_t*>(nonce.data() + 4),
        *reinterpret_cast<const uint32_t*>(nonce.data() + 8),
        counter                                                  //последний элемент — значением счетчика.
    };
    auto original_state = state;
    for (int i = 0; i < 10; ++i) {
        // Первый набор раундов
        state[0], state[4], state[8], state[12] = quarter_round(state[0], state[4], state[8], state[12]); //элемент массива state хранит 
        state[1], state[5], state[9], state[13] = quarter_round(state[1], state[5], state[9], state[13]); // 32-битное целое число  и инициализируется 
        state[2], state[6], state[10], state[14] = quarter_round(state[2], state[6], state[10], state[14]);//определенными значениями, включая:
        state[3], state[7], state[11], state[15] = quarter_round(state[3], state[7], state[11], state[15]);

        // Второй набор раундов
        state[0], state[5], state[10], state[15] = quarter_round(state[0], state[5], state[10], state[15]);
        state[1], state[6], state[11], state[12] = quarter_round(state[1], state[6], state[11], state[12]);
        state[2], state[7], state[8], state[13] = quarter_round(state[2], state[7], state[8], state[13]);
        state[3], state[4], state[9], state[14] = quarter_round(state[3], state[4], state[9], state[14]);
    }
    // Сложение с исходным состоянием
    for (size_t i = 0; i < 16; ++i)   state[i] = (state[i] + original_state[i]) & 0xffffffff; 
    // Преобразование в массив байт
    array<uint8_t, 64> output;
    for (size_t i = 0; i < 16; ++i)     memcpy(output.data() + i * 4, &state[i], 4);
    return output;
}

// Функция для шифрования данных
vector<uint8_t> chacha20_encrypt(const array<uint8_t, 32>& key, const array<uint8_t, 12>& nonce, const vector<uint8_t>& plaintext) {
    vector<uint8_t> ciphertext;
    uint32_t counter = 0;
    for (size_t i = 0; i < plaintext.size(); i += 64) {   // цикл проходит по открытым текстам, обрабатывая их блоками по 64 байта.
        auto block = chacha20_block(key, nonce, counter); //для каждого блока открытого текста вызывается функция chacha20_block, 
        counter++;                               //которая генерирует 64 байта ключевого потока на основе ключа, nonce и текущего значения счетчика.
        for (size_t j = 0; j < min(size_t(64), plaintext.size() - i); ++j)   ciphertext.push_back(plaintext[i + j] ^ block[j]);
    }
    return ciphertext;
}

// Функция для дешифрования данных
vector<uint8_t> chacha20_decrypt(const array<uint8_t, 32>& key, const array<uint8_t, 12>& nonce, const vector<uint8_t>& ciphertext) {
    vector<uint8_t> plaintext;
    uint32_t counter = 0;
    for (size_t i = 0; i < ciphertext.size(); i += 64) {
        auto block = chacha20_block(key, nonce, counter);
        counter++;
        for (size_t j = 0; j < min(size_t(64), ciphertext.size() - i); ++j)  plaintext.push_back(ciphertext[i + j] ^ block[j]);
    }
    return plaintext;
}
void main_menu() {
    array<uint8_t, 32> key = { 0 }; // 256-bit key (example all zeros)
    array<uint8_t, 12> nonce = { 0 }; // 96-bit nonce (example all zeros)
    while (true) {
        char Key = '0';
        cout << "<<Потоквый шифр Cha Cha>>   \n\n" << "1. Зашифровать слово\n" << "2. Выход\n" << "Выберите (1/2): ";
        Key = getchar();
        cin.ignore(1);
        if (Key < '1' || Key>'2')
            Key = '3';
        switch (Key) {
        case '1': {
            string plaintext;
            cout << "Введите слово, которое хотите зашифровать: ";
            getline(cin, plaintext);
            auto ciphertext = chacha20_encrypt(key, nonce, vector<uint8_t>(plaintext.begin(), plaintext.end()));
            cout << "Зашифрованное слово: ";
            for (auto byte : ciphertext) {
                cout << hex << setw(2) << setfill('0') << (int)byte;
            }
            cout << dec << endl;
            auto decrypted_message = chacha20_decrypt(key, nonce, ciphertext);
            cout << "Расшифрованное сообщение: " << string(decrypted_message.begin(), decrypted_message.end()) << endl << endl;
            break;
        }
        case '2':
            return;
        default:
            cout << "Неверный номер меню!" << endl;
            break;
        }
    }
}
int main(void) {
    setlocale(LC_ALL, "rus");
    main_menu();
}
