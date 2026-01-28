#pragma once

#include "session_manager.h"
#include <string>

class TCPReassembly {
public:
    static void reassemble(const SessionMap& sessions,
                           const std::string& outfile);
};
