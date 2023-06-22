#include "TTSCommon.h"

namespace WPEFramework {
namespace Plugin {
namespace TTS {

class SatToken {
public:
    static SatToken* getInstance();
    string getServiceAccessToken();

private:
    SatToken(){};
    SatToken(const  SatToken&) = delete;
    SatToken& operator=(const  SatToken&) = delete;

    string getSecurityToken();
    void serviceAccessTokenChangedEventHandler (const JsonObject& parameters);

    WPEFramework::JSONRPC::LinkType<WPEFramework::Core::JSON::IElement>* m_authService{nullptr};
    string m_SatToken;
    bool m_eventRegistered{false};
};

}
}
}
