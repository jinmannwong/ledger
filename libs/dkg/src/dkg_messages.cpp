#include "dkg/dkg_messages.hpp"
#include "core/logging.hpp"

namespace fetch {
namespace dkg {

    constexpr char const *LOGGING_NAME = "DKGMessage";

    std::shared_ptr<DKGMessage> DKGEnvelop::Message() const {
        DKGSerializer serialiser{serialisedMessage_};
        switch (type_) {
            case MessageType::COEFFICIENT:
                return std::make_shared<CoefficientsMessage>(serialiser);
            case MessageType::SHARE:
                return std::make_shared<SharesMessage>(serialiser);
            case MessageType::COMPLAINT:
                return std::make_shared<ComplaintsMessage>(serialiser);
            default:
                FETCH_LOG_ERROR(LOGGING_NAME, "Can not process payload");
        }
    }

}
}