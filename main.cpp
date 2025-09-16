#include <sodium.h>
#include <iostream>
#include <chrono>
#include <pqxx/pqxx> 
#include <string>
#include <cstdlib>

using namespace std;

static const size_t KEY_LEN  = crypto_secretbox_KEYBYTES;
static const size_t SALT_LEN = crypto_pwhash_SALTBYTES;

void push_db(const std::string &site,
                const std::string &username,
                const std::vector<unsigned char> &ciphertext,
                const std::vector<unsigned char> &nonce,
                const std::vector<unsigned char> &salt,
                const std::string &note) {
    try {
        const char* env = getenv("PASSWORD_DATABASE_URL");
        if (env == NULL) {
            cerr << "PASSWORD_DATABASE_URL is not set" << endl;
            exit(1);
        }
        pqxx::connection conn(env);
        cout << "Connected to: " << conn.dbname() << endl;

        pqxx::work txn(conn);
        txn.exec_params(
            "INSERT INTO vault_entries (site, username, ciphertext, nonce, salt, note) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            site,
            username,
            pqxx::binarystring(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()),
            pqxx::binarystring(reinterpret_cast<const char*>(nonce.data()), nonce.size()),
            pqxx::binarystring(reinterpret_cast<const char*>(salt.data()), salt.size()),
            note
        );
        txn.commit();   // 👈 Commit the transaction
    }
    catch (const exception& e) {
        cerr << e.what() << endl;
    }
}

#include <tuple>

std::tuple<std::string,
           std::vector<unsigned char>,
           std::vector<unsigned char>,
           std::vector<unsigned char>>
get_db(const std::string &site_name) {
    try {
        const char* env = getenv("PASSWORD_DATABASE_URL");
        if (env == NULL) {
            throw std::runtime_error("PASSWORD_DATABASE_URL is not set");
        }

        pqxx::connection conn(env);
        pqxx::work txn(conn);

        pqxx::result r = txn.exec_params(
            "SELECT username, ciphertext, nonce, salt "
            "FROM vault_entries WHERE site = $1 LIMIT 1",
            site_name
        );

        if (r.empty()) {
            throw std::runtime_error("No entry found for site: " + site_name);
        }

        const auto row = r[0];
        std::string username = row["username"].c_str();

        auto to_vec = [](const pqxx::field &f) {
            const pqxx::binarystring b(f);
            return std::vector<unsigned char>(b.begin(), b.end());
        };

        auto ciphertext = to_vec(row["ciphertext"]);
        auto nonce      = to_vec(row["nonce"]);
        auto salt       = to_vec(row["salt"]);

        txn.commit();
        return {username, ciphertext, nonce, salt};
    }
    catch (const std::exception &e) {
        std::cerr << "Error fetching login: " << e.what() << std::endl;
        return {"", {}, {}, {}};
    }
}


string generate_password(){
        string charset =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()_+";

        string random_str;
        int length = 20;

        for(int i = 0; i < length; i++){
            size_t idx = randombytes_uniform(charset.size());
            random_str += charset[idx];
            }
        return random_str;
}

std::vector<unsigned char> generate_nonce() {
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

string current_timestamp(){
    auto now = std::chrono::system_clock::now();
    time_t t = std::chrono::system_clock::to_time_t(now);

    tm tm = *localtime(&t);
    ostringstream oss;
    oss << put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

vector <unsigned char> generate_salt(){
    vector <unsigned char> salt(SALT_LEN);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

std::vector<unsigned char> derive_key(const std::string &pass, const std::vector<unsigned char> &salt) {
    std::vector<unsigned char> key(KEY_LEN);
    if (crypto_pwhash(
        key.data(), key.size(),
        pass.c_str(), pass.size(),
        salt.data(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("crypto_pwhash failed");
    }
    return key;
}

void encrypt_password(const std::string &plaintext,
                      const std::vector<unsigned char> &key,
                      const std::vector<unsigned char> &nonce,
                      std::vector<unsigned char> &ciphertext) {
    ciphertext.resize(plaintext.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(ciphertext.data(),
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          plaintext.size(),
                          nonce.data(),
                          key.data());
}

string decrypt_password(const std::vector<unsigned char> &ciphertext,
                             const std::vector<unsigned char> &nonce,
                             const std::vector<unsigned char> &key) {
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(decrypted.data(),
                                   ciphertext.data(),
                                   ciphertext.size(),
                                   nonce.data(),
                                   key.data()) != 0) {
        throw std::runtime_error("Decryption failed (wrong key/nonce or corrupted data)");
    }

    return std::string(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
}

int main() {
      if (sodium_init() < 0) {
        return 1;
    }
    auto sl = generate_salt();
    string pass;
    string account_name;
    string username;
    string timestamp = current_timestamp();
    string random_str;
    vector<unsigned char> ciphertext;
    auto nonce = generate_nonce();

    cout << "Welcome to the password generator. Do you want:" << endl;
    cout << "1. Generate a new password" << endl;
    cout << "2. Retrieve Password from the database" << endl;
    cout << "Enter your choice: ";
    int choice;
    cin >> choice;
    cin.ignore();
switch (choice)
{
case 1:{
    cout << "Enter site name: ";
    getline(cin, account_name);
    cout << "Enter username: ";
    getline(cin, username);  
    random_str = generate_password();
    std::cout << "Generated password: " << random_str << std::endl;
    std::cout << "Proceeding to save password in the database. " << std::endl;
    cout << "Enter Master pasphrase to encrypt password. This key will aslo be used to decrypt it: ";
    getline(cin, pass);
    auto key = derive_key(pass, sl); 
    encrypt_password(random_str, key, nonce, ciphertext);
    push_db(account_name, username, ciphertext, nonce, sl, timestamp);

    break;}
case 2:{
    cout << "Enter site name: ";
    getline(cin, account_name);
    auto [username, ciphertext, nonce, salt] = get_db(account_name);
    cout << "Enter Master pasphrase to decrypt password: ";
    getline(cin, pass);
    auto key = derive_key(pass, salt); 
    cout << "Username: " << username << endl;
    string recovered = decrypt_password(ciphertext, nonce, key);
    cout << "Recovered password: " << recovered << endl;
    break;}

default:
    cout << "Invalid choice" << endl;
    break;
}
    return 0;   
}
