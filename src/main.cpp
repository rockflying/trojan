/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio/signal_set.hpp>
#include <openssl/opensslv.h>
#ifdef ENABLE_MYSQL
#include <mysql.h>
#endif // ENABLE_MYSQL
#include "core/service.h"
#include "core/version.h"
using namespace std;
using namespace boost::asio;

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "config.json"
#endif // DEFAULT_CONFIG

void signal_async_wait(signal_set &sig, Service &service, bool &restart) {
    sig.async_wait([&](const boost::system::error_code error, int signum) {
        if (error) {
            return;
        }
        Log::log_with_date_time("got signal: " + to_string(signum), Log::WARN);
        switch (signum) {
            case SIGINT:
            case SIGTERM:
                service.stop();
                break;
#ifndef _WIN32
            case SIGHUP:
                restart = true;
                service.stop();
                break;
            case SIGUSR1:
                service.reload_cert();
                signal_async_wait(sig, service, restart);
                break;
#endif // _WIN32
        }
    });
}

int main(int argc, const char *argv[]) {
    try {
        Log::log("Welcome to trojan " + Version::get_version(), Log::FATAL);
        string config_file = DEFAULT_CONFIG;
        string log_file;
        string keylog_file;
        bool test = false;
        bool has_log = false;
        bool has_keylog = false;
        bool show_version = false;
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                Log::log(string("usage: ") + argv[0] + " [-htv] [-l LOG] [-k KEYLOG] [[-c] CONFIG]", Log::FATAL);
                cerr << "options:" << endl;
                cerr << "  -c [ --config ] CONFIG  specify config file" << endl;
                cerr << "  -h [ --help ]           print help message" << endl;
                cerr << "  -k [ --keylog ] KEYLOG  specify keylog file location (OpenSSL >= 1.1.1)" << endl;
                cerr << "  -l [ --log ] LOG        specify log file location" << endl;
                cerr << "  -t [ --test ]           test config file" << endl;
                cerr << "  -v [ --version ]        print version and build info" << endl;
                exit(EXIT_SUCCESS);
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
                show_version = true;
            } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
                test = true;
            } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
                if (++i < argc) config_file = argv[i];
            } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) {
                if (++i < argc) { log_file = argv[i]; has_log = true; }
            } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--keylog") == 0) {
                if (++i < argc) { keylog_file = argv[i]; has_keylog = true; }
            } else if (argv[i][0] != '-') {
                config_file = argv[i];
            }
        }
        if (show_version) {
            Log::log(string("Boost ") + BOOST_LIB_VERSION + ", " + OpenSSL_version(OPENSSL_VERSION), Log::FATAL);
#ifdef ENABLE_MYSQL
            Log::log(string(" [Enabled] MySQL Support (") + mysql_get_client_info() + ')', Log::FATAL);
#else // ENABLE_MYSQL
            Log::log("[Disabled] MySQL Support", Log::FATAL);
#endif // ENABLE_MYSQL
#ifdef TCP_FASTOPEN
            Log::log(" [Enabled] TCP_FASTOPEN Support", Log::FATAL);
#else // TCP_FASTOPEN
            Log::log("[Disabled] TCP_FASTOPEN Support", Log::FATAL);
#endif // TCP_FASTOPEN
#ifdef TCP_FASTOPEN_CONNECT
            Log::log(" [Enabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#else // TCP_FASTOPEN_CONNECT
            Log::log("[Disabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#endif // TCP_FASTOPEN_CONNECT
#if ENABLE_SSL_KEYLOG
            Log::log(" [Enabled] SSL KeyLog Support", Log::FATAL);
#else // ENABLE_SSL_KEYLOG
            Log::log("[Disabled] SSL KeyLog Support", Log::FATAL);
#endif // ENABLE_SSL_KEYLOG
#ifdef ENABLE_NAT
            Log::log(" [Enabled] NAT Support", Log::FATAL);
#else // ENABLE_NAT
            Log::log("[Disabled] NAT Support", Log::FATAL);
#endif // ENABLE_NAT
#ifdef ENABLE_TLS13_CIPHERSUITES
            Log::log(" [Enabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#else // ENABLE_TLS13_CIPHERSUITES
            Log::log("[Disabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#endif // ENABLE_TLS13_CIPHERSUITES
#ifdef ENABLE_REUSE_PORT
            Log::log(" [Enabled] TCP Port Reuse Support", Log::FATAL);
#else // ENABLE_REUSE_PORT
            Log::log("[Disabled] TCP Port Reuse Support", Log::FATAL);
#endif // ENABLE_REUSE_PORT
            Log::log("OpenSSL Information", Log::FATAL);
            if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
                Log::log(string("\tCompile-time Version: ") + OPENSSL_VERSION_TEXT, Log::FATAL);
            }
            Log::log(string("\tBuild Flags: ") + OpenSSL_version(OPENSSL_CFLAGS), Log::FATAL);
            exit(EXIT_SUCCESS);
        }
        if (has_log) {
            Log::redirect(log_file);
        }
        if (has_keylog) {
            Log::redirect_keylog(keylog_file);
        }
        bool restart;
        Config config;
        do {
            restart = false;
            if (config.sip003()) {
                Log::log_with_date_time("SIP003 is loaded", Log::WARN);
            } else {
                config.load(config_file);
            }
            Service service(config, test);
            if (test) {
                Log::log("The config file looks good.", Log::OFF);
                exit(EXIT_SUCCESS);
            }
            signal_set sig(service.service());
            sig.add(SIGINT);
            sig.add(SIGTERM);
#ifndef _WIN32
            sig.add(SIGHUP);
            sig.add(SIGUSR1);
#endif // _WIN32
            signal_async_wait(sig, service, restart);
            service.run();
            if (restart) {
                Log::log_with_date_time("trojan service restarting. . . ", Log::WARN);
            }
        } while (restart);
        Log::reset();
        exit(EXIT_SUCCESS);
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what(), Log::FATAL);
        Log::log_with_date_time("exiting. . . ", Log::FATAL);
        exit(EXIT_FAILURE);
    }
}
