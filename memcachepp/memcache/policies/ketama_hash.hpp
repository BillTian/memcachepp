
// Copyright 2015 (c) Bill Tian <billtian945@gmail.com>
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

/*
 * We implement KETAMA according to the libmemcached-0.35 which under BSD License
 *
 * Copyright (c) 2007, TangentOrg (Brian Aker)
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * 
 *     * Neither the name of TangentOrg nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
*/
/* We use md5 in openssl project also.
 *
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

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

