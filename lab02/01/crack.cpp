#include "_commit.h"
#include <thread>
#include <chrono>  
using namespace std;

string message_p1 = "flag"; 
vector<string> message_list(100); // flag0 ~ flag99
int nonce_min = 0x00000000;
int nonce_max = 0x00011177;

string target = "d62cc82e34b963db7ae121557d6fe4d3c0f7fc383ab309b352e750dffcd2c9d5";

int thread_num = 10;

chrono::high_resolution_clock::time_point start_time;

void __attribute__((constructor)) mian() {

}

void _create_commit(const std::string &message, const vector<unsigned char> &nonce)
{
    std::vector<unsigned char> C = commit(message, nonce); 
    if (to_hex(C) == target) {
        auto end_time = chrono::high_resolution_clock::now(); 
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count();
        cout << "Found! message: " << message << ", nonce: " << to_hex(nonce) << ", commit: " << to_hex(C) << endl;
        cout << "Cracking completed in " << duration << " ms" << endl; 
        exit(0);
    }
}

int main() {
    start_time = chrono::high_resolution_clock::now(); 

    for (int i = 0; i < 100; i++) {
        message_list[i] = message_p1 + to_string(i);
    }
    vector<thread> threads;
    for (int i = 0; i < thread_num; i++) {
        threads.emplace_back([i]() {
            for (int nonce_int = nonce_min + i; nonce_int <= nonce_max; nonce_int += thread_num) {
                auto nonce = hex_to_bytes((stringstream() << hex << setw(8) << setfill('0') << nonce_int).str());
                for (const auto &message : message_list) {
                    _create_commit(message, nonce);
                }
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    return 0;
}