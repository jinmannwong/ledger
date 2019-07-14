#pragma once

#include "core/byte_array/const_byte_array.hpp"
#include "core/serializers/byte_array.hpp"
#include "core/serializers/byte_array_buffer.hpp"
//#include "mcl/bn256.hpp"
#include "dkg/mcl_serializers.hpp"
#include "network/muddle/rpc/client.hpp"

namespace fetch {
namespace dkg {

    using DKGSerializer  = fetch::serializers::ByteArrayBuffer;

    class DKGMessage {
    public:
        using MsgSignature = byte_array::ConstByteArray;
        using MuddleAddress  = byte_array::ConstByteArray;
        using Coefficient = std::string;
        using Share = std::string;
        using CabinetId = MuddleAddress;

        enum class MessageType : uint8_t {
            COEFFICIENT,
            SHARE,
            COMPLAINT
        };

        MessageType Type() const {
            return type_;
        }
        MsgSignature Signature() const {
            return signature_;
        }
        virtual DKGSerializer Serialize() const = 0;
    protected:
        const MessageType type_;
        MsgSignature signature_;

        explicit DKGMessage(MessageType type): type_{type} {};
        explicit DKGMessage(MessageType type, MsgSignature sig): type_{type}, signature_{std::move(sig)} {};
    };

    class CoefficientsMessage : public DKGMessage {
        uint8_t phase_;
        std::vector<Coefficient> coefficients_;
    public:
        explicit CoefficientsMessage(DKGSerializer &serialiser): DKGMessage{MessageType::COEFFICIENT} {
            serialiser >> phase_ >> coefficients_ >> signature_;
        };
        explicit CoefficientsMessage(uint8_t phase, std::vector<Coefficient> coeff, MsgSignature sig):
            DKGMessage{MessageType::COEFFICIENT, std::move(sig)}, phase_{phase}, coefficients_{std::move(coeff)} {};
        DKGSerializer Serialize() const override {
            DKGSerializer serializer;
            serializer << phase_ << coefficients_ << signature_;
            return serializer;
        }
        uint8_t Phase() const {
            return phase_;
        }
        const std::vector<Coefficient>& Coefficients() const {
            return coefficients_;
        }
    };

    class SharesMessage : public DKGMessage {
        uint8_t phase_;
        std::unordered_map<CabinetId, int> null_;
        std::unordered_map<CabinetId, std::pair<Share, Share>> shares_; ///< Shares for a particular committee member
    public:
        explicit SharesMessage(DKGSerializer &serialiser): DKGMessage{MessageType::SHARE} {
            serialiser >> phase_ >> shares_ >> signature_;
        };
        explicit SharesMessage(uint8_t phase, std::unordered_map<CabinetId, std::pair<Share, Share>> shares,
                MsgSignature sig):
            DKGMessage{MessageType::SHARE, std::move(sig)}, phase_{phase}, shares_{std::move(shares)} {};
        DKGSerializer Serialize() const override {
            DKGSerializer serializer;
            serializer << phase_ << shares_ << signature_;
            return serializer;
        }
        uint8_t Phase() const {
            return phase_;
        }
        const std::unordered_map<CabinetId, std::pair<Share, Share>>& Shares() const {
            return shares_;
        }
    };

    class ComplaintsMessage : public DKGMessage {
        std::unordered_set<CabinetId> complaints_; ///< Committee members that you are complaining against
    public:
        explicit ComplaintsMessage(DKGSerializer &serialiser): DKGMessage{MessageType::COMPLAINT} {
            serialiser >> complaints_ >> signature_;
        };
        explicit ComplaintsMessage(std::unordered_set<CabinetId> complaints, MsgSignature sig):
            DKGMessage{MessageType::COMPLAINT, std::move(sig)}, complaints_{std::move(complaints)} {};
        DKGSerializer  Serialize() const override {
            DKGSerializer serializer;
            serializer << complaints_ << signature_;
            return serializer;
        }
        const std::unordered_set<CabinetId>& Complaints() const {
            return complaints_;
        }
    };

    class DKGEnvelop {
        using MessageType = DKGMessage::MessageType;
        using Payload = byte_array::ConstByteArray;

    public:
        DKGEnvelop() = default;
        explicit DKGEnvelop(const DKGMessage &msg): type_{msg.Type()}, serialisedMessage_{msg.Serialize().data()} {};

        template<typename T>
        void Serialize(T &serialiser) const {
            serialiser << (uint8_t) type_ << serialisedMessage_;
        }

        template<typename T>
        void Deserialize(T &serialiser) {
            uint8_t val;
            serialiser >> val;
            type_ = (MessageType) val;
            serialiser >> serialisedMessage_;
        }

        std::shared_ptr<DKGMessage> Message() const;

    private:
        MessageType type_;
        Payload serialisedMessage_;
    };

    template<typename T>
    inline void Serialize(T &serializer, DKGEnvelop const &env) {
        env.Serialize(serializer);
    }

    template<typename T>
    inline void Deserialize(T &serializer, DKGEnvelop &env) {
        env.Deserialize(serializer);
    }

}
}