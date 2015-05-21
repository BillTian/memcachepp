// Copyright 2015 (c) Bill Tian <billtian945@gmail.com>
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef __MEMCACHE_DETAIL_HANDLE_ACCESS_HPP__
#define __MEMCACHE_DETAIL_HANDLE_ACCESS_HPP__

namespace memcache { namespace traits {

    template <class handle_type, int>
    struct access {
    };

    template <class handle_type>
    struct access<handle_type, 0>
    {
        typedef typename handle_type::server_container server_type;
        static server_type& get(handle_type &h)
        {
            return h.servers;
        }
    };

} // namespace traits

} // namespace memcache

#endif // __MEMCACHE_DETAIL_HANDLE_ACCESS_HPP__
