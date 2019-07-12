#include "dkg/dkg_messages.hpp"
#include "core/logging.hpp"

namespace fetch {
namespace dkg {

    constexpr char const *LOGGING_NAME = "DKGMessage";

    std::shared_ptr<DKGMessage> DKGEnvelop::getMessage() const {
        DKGSerializer serialiser{serialisedMessage_};
        switch (type_) {
            case MessageType::COEFFICIENT:
                return std::make_shared<Coefficients>(serialiser);
            case MessageType::SHARE:
                return std::make_shared<Shares>(serialiser);
            case MessageType::COMPLAINT:
                return std::make_shared<Complaints>(serialiser);
            default:
                FETCH_LOG_ERROR(LOGGING_NAME, "Can not process payload");
        }
    }

}
}