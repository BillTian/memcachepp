
// Copyright 2015 (c) Bill <billtian945@gmail.com>
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef __MEMCACHE_POLICIES_KETAMA_HASH_HPP__
#define __MEMCACHE_POLICIES_KETAMA_HASH_HPP__

#ifdef _MEMCACHE_SUPPORT_KETAMA
#include <openssl/md5.h>
#include <fstream>
#include <memcachepp/memcache/detail/handle_access.hpp>

namespace memcache {
    namespace impl {
        typedef std::pair<size_t, boost::uint32_t> offset_value_pair;
        struct offset_value_less {
            bool operator()(const offset_value_pair &l, const offset_value_pair &r) {
                return l.second < r.second;
            }
        };
        typedef std::vector<offset_value_pair> continuum_items_vec;

        struct server_hash_cacl {
            explicit server_hash_cacl(continuum_items_vec &items)
            : items_(items) { }

            boost::uint32_t hash(const std::string &key) const {
                boost::uint32_t value = 0;

                for (size_t ki = 0; ki < key.size(); ++ki) {
                    boost::uint32_t val = key.at(ki);
                    value += val;
                    value += (value << 10);
                    value ^= (value >> 6);
                }
                value += (value << 3);
                value ^= (value >> 11);
                value += (value << 15);

                return value == 0 ? 1 : (uint32_t)value;
            }

            template <typename T>
            void operator() (T const & server) const {
                // TODO:
                for (int pidx = 0; pidx < 100; ++pidx) {
                    boost::uint32_t hashval = 0;
                    if (server.second.port == "11211") {
                        std::ostringstream ostr;
                        ostr << server.second.host << "-" << pidx;
                        hashval = hash(ostr.str());
                    }
                    else {
                        std::ostringstream ostr;
                        ostr << server.second.host << ":" << server.second.port << "-" << pidx;
                        hashval = hash(ostr.str());
                    }
                    items_.push_back(std::make_pair(server.second.index, hashval));
                }
            }
        private:
            continuum_items_vec &items_;
        };
    } // namespace impl

    namespace policies {
        template <class tag = tags::default_tag>
        struct ketama_hash {
            impl::continuum_items_vec items_;

            template <class handle_type>
            void init_hash(handle_type & handle) {
                typename traits::access<handle_type, 0>::server_type &server = traits::access<handle_type, 0>::get(handle);
                for_each(server.begin(), server.end(),
                    memcache::impl::server_hash_cacl(items_));
                std::sort(items_.begin(), items_.end(), memcache::impl::offset_value_less());
            }

            template <class handle_type>
            void update_hash(handle_type & handle) {}

            boost::uint32_t md5_hash(const std::string &key) const {
                unsigned char results[16] = {0};

                MD5((unsigned char*)key.c_str(), key.size(), results);

                using boost::uint32_t;
                return ((uint32_t)(results[3] & 0xFF) << 24)
                    | ((uint32_t)(results[2] & 0xFF) << 16)
                    | ((uint32_t)(results[1] & 0xFF) << 8)
                    | (results[0] & 0xFF);
            }

            size_t hash(std::string const & key, size_t server_count) const {
                assert(server_count != 0);
                if (items_.empty())
                    return 0;

                impl::continuum_items_vec::const_iterator left = items_.begin(), right = items_.end();

                boost::uint32_t hash = md5_hash(key);
                while (left < right) {
                    impl::continuum_items_vec::const_iterator middle = left + (right - left) / 2;
                    if (middle->second < hash)
                        left = middle + 1;
                    else
                        right = middle;
                }
                if (right == items_.end())
                    right = items_.begin();
                return right->first;
            };
        protected:
            ~ketama_hash() { }
        };
    } // namespace policies

} // namespace memcache

#endif // _MEMCACHE_SUPPORT_KETAMA

#endif // __MEMCACHE_POLICIES_KETAMA_HASH_HPP__

